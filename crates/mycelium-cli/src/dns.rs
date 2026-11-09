use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

use mycelium_core::topology::Topology;
pub(crate) use mycelium_dns_policy::{canonical_domain, plan, Delegation, DnsRecord};
use mycelium_dns_policy::{BlockAction, Blocklist, BlocklistSource};
use mycelium_peer_protocol::WireGuardBinding;
use std::path::PathBuf;

pub(crate) fn derive_records(
    topology: &Topology,
    bindings: &[WireGuardBinding],
    suffix: &str,
) -> Result<Vec<DnsRecord>, String> {
    let suffix = canonical_domain(suffix)?;
    let mut records = BTreeSet::new();
    let mut names = BTreeMap::<String, String>::new();
    let mut addresses = BTreeMap::<(String, bool), IpAddr>::new();
    for binding in bindings {
        let prefixes = binding
            .advertised_prefixes
            .iter()
            .map(|prefix| parse_prefix(prefix))
            .collect::<Result<Vec<_>, _>>()?;
        for node in topology.nodes.values() {
            if !node.sites.is_empty() && !node.sites.contains(&binding.site) {
                continue;
            }
            let Some(label) = node
                .annotation
                .name
                .as_ref()
                .or_else(|| node.hostnames.iter().next())
                .map(|value| dns_label(value))
                .filter(|value| !value.is_empty())
            else {
                continue;
            };
            let site = dns_label(&binding.site);
            for address in node
                .ips
                .keys()
                .copied()
                .filter(|address| prefixes.iter().any(|prefix| prefix.contains(*address)))
            {
                let name = format!("{label}.{site}.{suffix}");
                if let Some(owner) = names.insert(name.clone(), node.id.clone()) {
                    if owner != node.id {
                        return Err(format!("DNS name `{name}` has competing node owners"));
                    }
                }
                if let Some(previous) = addresses.insert((name.clone(), address.is_ipv4()), address)
                {
                    if previous != address {
                        return Err(format!(
                            "DNS name `{name}` maps to both {previous} and {address}"
                        ));
                    }
                }
                records.insert(DnsRecord {
                    name,
                    address,
                    site: binding.site.clone(),
                    node: node.id.clone(),
                });
            }
        }
    }
    Ok(records.into_iter().collect())
}

#[derive(Clone, Copy)]
struct Prefix {
    address: IpAddr,
    length: u8,
}

impl Prefix {
    fn contains(self, candidate: IpAddr) -> bool {
        match (self.address, candidate) {
            (IpAddr::V4(network), IpAddr::V4(candidate)) => {
                let mask = if self.length == 0 {
                    0
                } else {
                    u32::MAX << (32 - self.length)
                };
                u32::from(network) & mask == u32::from(candidate) & mask
            }
            (IpAddr::V6(network), IpAddr::V6(candidate)) => {
                let mask = if self.length == 0 {
                    0
                } else {
                    u128::MAX << (128 - self.length)
                };
                u128::from(network) & mask == u128::from(candidate) & mask
            }
            _ => false,
        }
    }
}

fn parse_prefix(value: &str) -> Result<Prefix, String> {
    let (address, length) = value
        .split_once('/')
        .ok_or_else(|| format!("invalid routed prefix `{value}`"))?;
    let address = address
        .parse::<IpAddr>()
        .map_err(|_| format!("invalid routed prefix `{value}`"))?;
    let length = length
        .parse::<u8>()
        .map_err(|_| format!("invalid routed prefix `{value}`"))?;
    if length > if address.is_ipv4() { 32 } else { 128 } {
        return Err(format!("invalid routed prefix `{value}`"));
    }
    Ok(Prefix { address, length })
}

fn dns_label(value: &str) -> String {
    value
        .trim_end_matches('.')
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || character == '-' {
                character.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect::<String>()
        .trim_matches('-')
        .to_owned()
}

/// `mycelium dns blocklist plan|check`: review local lists before the resolver
/// reads them. Fetching is a separate explicit step, so nothing here reaches
/// the network and the same files always produce the same lines.
pub(crate) fn blocklist(args: &[String]) -> Result<Vec<String>, String> {
    let action_name = args
        .first()
        .map(String::as_str)
        .ok_or("blocklist needs `plan` or `check`")?;
    if !matches!(action_name, "plan" | "check") {
        return Err("blocklist supports `plan` and `check`".into());
    }
    let mut sources = Vec::new();
    let mut allow = Vec::new();
    let mut suffix = String::from("myc");
    let mut action = BlockAction::default();
    let mut subject = None;
    let mut json = false;
    let mut dnsmasq = false;
    let mut seen = BTreeSet::new();
    let mut rest = args[1..].iter();
    while let Some(flag) = rest.next() {
        if !seen.insert(flag.as_str()) {
            return Err("duplicate blocklist option".into());
        }
        match flag.as_str() {
            "--json" => json = true,
            "--dnsmasq" if action_name == "plan" => dnsmasq = true,
            "--source" => sources.push(BlocklistSource {
                path: PathBuf::from(rest.next().ok_or("--source needs a file")?),
            }),
            "--allow" => allow.push(rest.next().ok_or("--allow needs a domain")?.to_string()),
            "--suffix" => suffix = rest.next().ok_or("--suffix needs a domain")?.to_string(),
            "--action" => {
                action = BlockAction::parse(rest.next().ok_or("--action needs an action")?)?
            }
            other if action_name == "check" && !other.starts_with("--") && subject.is_none() => {
                subject = Some(other.to_string())
            }
            _ => return Err("unknown blocklist option".into()),
        }
    }
    if sources.is_empty() {
        return Err("blocklist needs at least one --source".into());
    }
    if action_name == "check" && json && dnsmasq {
        return Err("choose --json or --dnsmasq".into());
    }
    let blocks = Blocklist::load(&sources, &suffix, &allow)?;
    if action_name == "check" {
        let name = canonical_domain(&subject.ok_or("blocklist check needs a name")?)?;
        let zone = blocks.matched(&name);
        if json {
            return Ok(vec![serde_json::json!({
                "name": name,
                "blocked": zone.is_some(),
                "zone": zone,
                "action": action.as_str(),
            })
            .to_string()]);
        }
        return Ok(vec![match zone {
            Some(zone) => format!("blocked by {zone} ({})", action.as_str()),
            None => format!("{name} is not on any configured list"),
        }]);
    }
    if dnsmasq {
        return Ok(vec![blocks.render(action)]);
    }
    if json {
        return Ok(vec![serde_json::json!({
            "suffix": canonical_domain(&suffix)?,
            "action": action.as_str(),
            "zones": blocks.len(),
            "skipped": blocks.skipped(),
            "allowlist": blocks.allowlist(),
            "sources": blocks.sources(),
        })
        .to_string()]);
    }
    let mut lines = vec![format!(
        "{} zones from {} source(s), {} line(s) skipped; action {}",
        blocks.len(),
        blocks.sources().len(),
        blocks.skipped(),
        action.as_str()
    )];
    lines.extend(blocks.zones().take(20).map(str::to_string));
    if blocks.len() > 20 {
        lines.push(format!("... {} more", blocks.len() - 20));
    }
    Ok(lines)
}

#[cfg(test)]
mod tests {
    use super::*;
    use mycelium_core::topology::{IpRecord, TopoNode};

    #[test]
    fn derives_only_addresses_reachable_through_signed_site_routes() {
        let mut topology = Topology::empty();
        let mut node = TopoNode::default();
        node.id = "camera".into();
        node.hostnames.insert("Front Camera".into());
        node.sites.insert("home".into());
        for address in ["192.168.10.30", "172.17.0.2"] {
            let address = address.parse().unwrap();
            node.ips.insert(
                address,
                IpRecord {
                    addr: address,
                    prefix: Some(24),
                    vlan: None,
                    origins: BTreeSet::new(),
                },
            );
        }
        topology.nodes.insert(node.id.clone(), node);
        let mut binding = WireGuardBinding {
            credential: mycelium_peer_protocol::TransportCredentialBinding {
                node_id: "identity".into(),
                kind: mycelium_peer_protocol::TransportKind::WireGuard,
                public_key: "public".into(),
                generation: 1,
                valid_until: None,
            },
            hostname: "gateway".into(),
            site: "home".into(),
            endpoint: None,
            advertised_prefixes: vec!["192.168.10.0/24".into()],
        };
        let records = derive_records(&topology, &[binding.clone()], "mycelium").unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].name, "front-camera.home.mycelium");
        assert_eq!(records[0].address.to_string(), "192.168.10.30");
        let v6 = "2001:db8::30".parse().unwrap();
        topology.nodes.get_mut("camera").unwrap().ips.insert(
            v6,
            IpRecord {
                addr: v6,
                prefix: Some(64),
                vlan: None,
                origins: BTreeSet::new(),
            },
        );
        binding.advertised_prefixes.push("2001:db8::/64".into());
        assert_eq!(
            derive_records(&topology, &[binding.clone()], "mycelium")
                .unwrap()
                .len(),
            2
        );
        let mut competing = topology.nodes["camera"].clone();
        competing.id = "other-camera".into();
        topology.nodes.insert(competing.id.clone(), competing);
        assert!(derive_records(&topology, &[binding], "mycelium").is_err());
    }

    #[test]
    fn blocklist_cli_reports_counts_and_refuses_namespace_entries() {
        let path = std::env::temp_dir().join(format!("cli-block-{}", std::process::id()));
        std::fs::write(&path, "0.0.0.0 ads.example.com\n").unwrap();
        let source = path.to_string_lossy().to_string();
        let args = |list: &[&str]| {
            list.iter()
                .map(|value| value.to_string())
                .collect::<Vec<_>>()
        };
        let plan = blocklist(&args(&["plan", "--source", &source, "--json"])).unwrap();
        assert!(plan[0].contains("\"zones\":1"), "{}", plan[0]);
        let hit = blocklist(&args(&["check", "x.ads.example.com", "--source", &source])).unwrap();
        assert!(hit[0].contains("blocked by ads.example.com"), "{}", hit[0]);
        std::fs::write(&path, "node.myc\n").unwrap();
        assert!(blocklist(&args(&["plan", "--source", &source])).is_err());
        let _ = std::fs::remove_file(&path);
    }
}
