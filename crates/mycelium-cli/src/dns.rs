use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

use mycelium_core::topology::{Topology, MYCELIUM_OVERLAY_NETWORK};
use mycelium_dns_policy::addresses::publishable_address;
pub(crate) use mycelium_dns_policy::{canonical_domain, plan, Delegation, DnsRecord};
use mycelium_dns_policy::{BlockAction, Blocklist, BlocklistSource};
use mycelium_peer_protocol::WireGuardBinding;
use myceliumd::protocol::Request;
use std::path::{Path, PathBuf};

/// The zone's host records: `node.site.<suffix>` for every publishable address
/// a signed site route reaches.
///
/// Service names are deliberately not derived here. They come from the one
/// naming rule (`mycelium_dns_policy::service_names`) applied to these records,
/// so a preview and the resolver cannot disagree about what a claim answers to.
///
/// `reachable_prefixes` is the installed resolver's declared scope. When it is
/// absent this host runs no resolver, and a binding's advertised prefixes are
/// the only reachability statement available.
pub(crate) fn derive_host_records(
    topology: &Topology,
    bindings: &[WireGuardBinding],
    suffix: &str,
    reachable_prefixes: Option<&[String]>,
) -> Result<Vec<DnsRecord>, String> {
    let suffix = canonical_domain(suffix)?;
    let mut records = BTreeSet::new();
    // One name may resolve to several addresses: a machine is multi-homed, and
    // one node record per overlay network describes the same machine more than
    // once. What must never happen is two *different* machines answering to one
    // name, so ownership is tracked per node id and compared at the end.
    let mut owners = BTreeMap::<String, BTreeMap<String, BTreeSet<IpAddr>>>::new();
    for binding in bindings {
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
                // Every machine has a `localhost` hostname, so it can never
                // name a node: it would collide across the whole fleet.
                .filter(|value| !value.eq_ignore_ascii_case("localhost"))
            else {
                continue;
            };
            let site = dns_label(&binding.site);
            let scope = reachable_prefixes.unwrap_or(&binding.advertised_prefixes);
            for address in node
                .ips
                .keys()
                .copied()
                // One rule decides which addresses are publishable, so the
                // resolver and this preview cannot disagree about a machine:
                // the overlay address always publishes, everything else needs
                // the scope the operator declared reachable.
                .filter(|address| publishable_address(*address, scope))
            {
                let name = format!("{label}.{site}.{suffix}");
                owners
                    .entry(name.clone())
                    .or_default()
                    .entry(node.id.clone())
                    .or_default()
                    .insert(address);
                records.insert(DnsRecord {
                    name,
                    address,
                    site: binding.site.clone(),
                    node: node.id.clone(),
                });
            }
        }
    }
    for (name, nodes) in &owners {
        let sets = nodes.values().collect::<Vec<_>>();
        for (index, left) in sets.iter().enumerate() {
            // Node ids multiply per overlay network, but their address sets
            // overlap when they describe one machine. Disjoint sets are two
            // machines and a name cannot belong to both.
            for right in &sets[index + 1..] {
                if left.is_disjoint(right) {
                    return Err(format!(
                        "DNS name `{name}` is claimed by different machines"
                    ));
                }
            }
        }
    }
    // One machine described by several node records yields the same name and
    // address more than once; the zone cares about the pair, not the id.
    let mut unique = BTreeMap::<(String, IpAddr), DnsRecord>::new();
    for record in records {
        unique
            .entry((record.name.clone(), record.address))
            .or_insert(record);
    }
    Ok(unique.into_values().collect())
}

/// Derive the overlay zone: `node.<suffix>` -> the node's overlay address.
///
/// Overlay addresses belong to one transport-agnostic space. A client that
/// resolves one of these names reaches the node either over a routed WireGuard
/// fast path or, when the address is unrouted, through the local proxy that
/// dials the peer over iroh. The DNS layer deliberately does not distinguish
/// the two: it publishes reachability, not transport.
///
/// These names are not site-scoped, so every record carries an empty `site`:
/// `plan` is a per-site dnsmasq fragment and drops them, which is why `--zone`
/// only applies to `dns zone`.
pub(crate) fn derive_overlay_records(
    topology: &Topology,
    suffix: &str,
) -> Result<Vec<DnsRecord>, String> {
    let suffix = canonical_domain(suffix)?;
    let mut records = BTreeSet::new();
    let mut names = BTreeMap::<String, IpAddr>::new();
    for node in topology.nodes.values() {
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
        for address in node.overlay_ips(MYCELIUM_OVERLAY_NETWORK) {
            let name = format!("{label}.{suffix}");
            if let Some(previous) = names.insert(name.clone(), address) {
                if previous != address {
                    return Err(format!(
                        "DNS name `{name}` maps to both {previous} and {address}"
                    ));
                }
            }
            records.insert(DnsRecord {
                name,
                address,
                site: String::new(),
                node: node.id.clone(),
            });
        }
    }
    Ok(records.into_iter().collect())
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

/// Address scopes this site occupies, so the resolver publishes peer
/// addresses it can actually reach and nothing else.
///
/// Signed bindings describe routed prefixes, which are per-host `/32`s on
/// most sites and would publish nothing. A site's nodes also report the
/// addresses they hold, and the covering `/24` (or `/64`) of those is the
/// subnet the peer is on — that is the scope a site-local resolver answers
/// from, and it never widens beyond names in the site's own namespace.
pub(crate) async fn live_prefixes(site: &str) -> Result<Vec<String>, String> {
    let mut client = crate::connect()
        .await
        .map_err(|error| format!("connect to the daemon: {error}"))?;
    let value = client
        .call(&Request::WireGuardBindingList)
        .await
        .map_err(|error| format!("read routed prefixes: {error}"))?;
    let bindings: Vec<WireGuardBinding> =
        serde_json::from_value(value).map_err(|error| format!("invalid bindings: {error}"))?;
    let topology: Topology = serde_json::from_value(
        client
            .call(&Request::Topology)
            .await
            .map_err(|error| format!("read topology: {error}"))?,
    )
    .map_err(|error| format!("invalid topology: {error}"))?;
    let mut prefixes = BTreeSet::new();
    for binding in bindings.iter().filter(|binding| binding.site == site) {
        for prefix in &binding.advertised_prefixes {
            if mycelium_core::parse_cidr(prefix).is_none() {
                return Err(format!(
                    "daemon advertised invalid routed prefix `{prefix}`"
                ));
            }
            prefixes.insert(prefix.clone());
        }
    }
    // Only nodes this site has a signed route to: an address nobody routed to
    // is not a scope a site-local resolver should answer from.
    let routed = bindings
        .iter()
        .filter(|binding| binding.site == site)
        .map(|binding| binding.credential.node_id.as_str())
        .collect::<BTreeSet<_>>();
    for node in topology.nodes.values() {
        if !node.sites.contains(site) || !routed.contains(node.id.as_str()) {
            continue;
        }
        for address in node.ips.keys() {
            if let Some(prefix) = covering_prefix(*address) {
                prefixes.insert(prefix);
            }
        }
    }
    if prefixes.is_empty() {
        return Err(format!(
            "no signed routes or site addresses for `{site}`; pass --reachable to `mycelium dns resolver init`"
        ));
    }
    if prefixes.len() > 64 {
        return Err(format!(
            "site `{site}` spans {} scopes; review them and pass --reachable",
            prefixes.len()
        ));
    }
    Ok(prefixes.into_iter().collect())
}

/// Container bridges and hypervisor NAT ranges are reported by every host that
/// runs a workload, and no fleet name is ever published from them. A site that
/// genuinely uses `172.16/12` passes `--reachable` explicitly instead.
fn is_container_scope(address: std::net::Ipv4Addr) -> bool {
    let octets = address.octets();
    matches!(
        octets,
        [172, 16..=31, _, _]
            | [10, 0, 2, _]
            | [192, 0, 2, _]
            | [198, 51, 100, _]
            | [203, 0, 113, _]
    )
}

/// The subnet a peer address sits on. Never wider than a `/24` or `/64`, so
/// one reported address cannot claim an entire private range.
fn covering_prefix(address: IpAddr) -> Option<String> {
    match address {
        IpAddr::V4(address)
            if !address.is_loopback()
                && !address.is_link_local()
                && !address.is_unspecified()
                && !is_container_scope(address) =>
        {
            let network = u32::from(address) & 0xffff_ff00;
            Some(format!("{}/24", std::net::Ipv4Addr::from(network)))
        }
        IpAddr::V6(address)
            if !address.is_loopback()
                && !address.is_unspecified()
                && !address.is_unicast_link_local() =>
        {
            let network = u128::from(address) & (u128::MAX << 64);
            Some(format!("{}/64", std::net::Ipv6Addr::from(network)))
        }
        _ => None,
    }
}

/// `mycelium dns resolver init` from a node's own point of view: fill in the
/// site, namespace and routed prefixes that can be derived here, so a rollout
/// never hand-copies site data. Anything given explicitly wins.
fn given(values: &[String], name: &str) -> bool {
    values.iter().any(|value| value == name)
}

pub(crate) async fn resolver_init(args: &[String]) -> Result<Vec<String>, String> {
    let mut forward = Vec::new();
    let mut rest = args.iter();
    while let Some(flag) = rest.next() {
        match flag.as_str() {
            "--site" | "--suffix" | "--reachable" | "--config" | "--doh" | "--doh-listen"
            | "--dnsmasq" | "--mycelium" => {
                let value = rest.next().ok_or_else(|| format!("{flag} needs a value"))?;
                forward.push(flag.clone());
                forward.push(value.clone());
            }
            "--write" | "--dry-run" | "--force" => forward.push(flag.clone()),
            _ => return Err(format!("unknown resolver init option `{flag}`")),
        }
    }
    if !given(&forward, "--config") {
        return Err("resolver init needs --config".into());
    }
    let home = myceliumd::home_dir();
    let (site, suffix) = crate::enroll::identity(&home)?;
    if !given(&forward, "--site") {
        forward.push("--site".to_string());
        forward.push(site.clone());
    }
    if !given(&forward, "--suffix") {
        forward.push("--suffix".to_string());
        forward.push(suffix);
    }
    if !given(&forward, "--reachable") {
        for prefix in live_prefixes(&site).await? {
            forward.push("--reachable".to_string());
            forward.push(prefix);
        }
    }
    let mut command = vec!["init".to_string()];
    command.extend(forward);
    Ok(vec![mycelium_driver_dnsmasq::command(&command).await?])
}

/// Make this node serve `.myc` locally: create the policy file from its own
/// identity and live routes when it is missing, then apply it. Records are
/// observed at apply time, so the configuration holds policy, not data.
pub(crate) async fn ensure(home: &Path) -> Result<Vec<String>, String> {
    let (site, suffix) = crate::enroll::identity(home)?;
    let config = home.join("dns/resolver.json");
    let mut lines = Vec::new();
    if !config.is_file() {
        let prefixes = live_prefixes(&site).await?;
        let managed = home.join("bin/mycelium");
        let mycelium = if managed.is_file() {
            managed
        } else {
            std::env::current_exe()
                .map_err(|error| format!("locate the Mycelium binary: {error}"))?
        };
        mycelium_driver_dnsmasq::init(
            &config,
            mycelium_driver_dnsmasq::InitOptions {
                site: site.clone(),
                suffix: suffix.clone(),
                reachable_prefixes: prefixes,
                service_address: None,
                listen: vec![],
                dnsmasq: None,
                mycelium: Some(mycelium),
                // Which encrypted endpoint to trust is a policy decision, so a
                // repair never invents one; `dns resolver init --doh` sets it.
                doh: None,
            },
            false,
        )?;
        lines.push(format!(
            "initialized DNS policy for {site} at {}",
            config.display()
        ));
    }
    let command = [
        "apply".to_string(),
        "--config".to_string(),
        config.display().to_string(),
        "--write".to_string(),
    ];
    // A repair restarts the daemon, so the first apply can land before gossip
    // has repopulated. Retry only that condition, and only for a minute.
    let mut last = String::new();
    for attempt in 0..12 {
        match mycelium_driver_dnsmasq::command(&command).await {
            Ok(applied) => {
                lines.push(format!("DNS resolver: {applied}"));
                return Ok(lines);
            }
            Err(error) if error.contains("no fresh reachable records") && attempt < 11 => {
                last = error;
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            }
            Err(error) => return Err(error),
        }
    }
    Err(last)
}

#[cfg(test)]
mod tests {
    use super::*;
    use mycelium_core::topology::{IpRecord, TopoNode};

    /// The resolver publishes what the operator declared reachable; a binding's
    /// advertised prefixes are only the fallback on a host with no resolver.
    #[test]
    fn the_installed_scope_replaces_the_bindings_advertised_prefixes() {
        let mut topology = Topology::empty();
        let mut node = TopoNode {
            id: "neo".into(),
            hostnames: BTreeSet::from(["neo".into()]),
            sites: BTreeSet::from(["home".into()]),
            ..TopoNode::default()
        };
        for address in ["192.168.10.30", "192.168.2.3"] {
            let address = address.parse().unwrap();
            node.ips.insert(
                address,
                IpRecord {
                    addr: address,
                    prefix: None,
                    vlan: None,
                    origins: BTreeSet::new(),
                },
            );
        }
        topology.nodes.insert(node.id.clone(), node);
        let mut binding = home_binding();
        binding.advertised_prefixes = vec!["192.168.10.0/24".into()];
        let addresses = |scope: Option<&[String]>| {
            derive_host_records(&topology, &[binding.clone()], "myc", scope)
                .unwrap()
                .into_iter()
                .map(|record| record.address.to_string())
                .collect::<BTreeSet<_>>()
        };
        assert_eq!(
            addresses(None),
            BTreeSet::from(["192.168.10.30".to_owned()])
        );
        assert_eq!(
            addresses(Some(&["192.168.2.0/24".to_owned()])),
            BTreeSet::from(["192.168.2.3".to_owned()])
        );
    }

    fn home_binding() -> WireGuardBinding {
        WireGuardBinding {
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
            advertised_prefixes: vec!["10.253.0.0/16".into()],
        }
    }

    /// The publishable-address rule is shared with the resolver: the overlay
    /// address always publishes, a LAN address only inside the site route's
    /// prefix, and neither adapter gets to decide on its own.
    #[test]
    fn the_overlay_address_publishes_without_a_declared_scope() {
        let mut topology = Topology::empty();
        let mut node = TopoNode {
            id: "neo".into(),
            hostnames: BTreeSet::from(["neo".into()]),
            sites: BTreeSet::from(["home".into()]),
            ..TopoNode::default()
        };
        for address in ["fd7a:115c:a1e0::6", "10.253.0.6", "192.168.44.9"] {
            let address = address.parse().unwrap();
            node.ips.insert(
                address,
                IpRecord {
                    addr: address,
                    prefix: None,
                    vlan: None,
                    origins: BTreeSet::new(),
                },
            );
        }
        topology.nodes.insert(node.id.clone(), node);
        let addresses = derive_host_records(&topology, &[home_binding()], "myc", None)
            .unwrap()
            .into_iter()
            .filter(|record| record.name == "neo.home.myc")
            .map(|record| record.address.to_string())
            .collect::<BTreeSet<_>>();
        assert_eq!(
            addresses,
            ["fd7a:115c:a1e0::6", "10.253.0.6"]
                .map(String::from)
                .into_iter()
                .collect(),
            "the overlay address publishes; the LAN address outside the site route does not"
        );
    }

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
        let records = derive_host_records(&topology, &[binding.clone()], "mycelium", None).unwrap();
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
            derive_host_records(&topology, &[binding.clone()], "mycelium", None)
                .unwrap()
                .len(),
            2,
            "one name, both families"
        );
        // Several node records can describe one machine -- one per overlay
        // network -- so the same name arriving from more than one id is normal
        // as long as it resolves to one address.
        let mut same_machine = topology.nodes["camera"].clone();
        same_machine.id = "camera-on-another-overlay".into();
        topology.nodes.insert(same_machine.id.clone(), same_machine);
        let shared = derive_host_records(&topology, &[binding.clone()], "mycelium", None).unwrap();
        let addresses = shared
            .iter()
            .filter(|record| record.name == "front-camera.home.mycelium")
            .map(|record| record.address)
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(
            addresses,
            [
                "192.168.10.30".parse().unwrap(),
                "2001:db8::30".parse().unwrap()
            ]
            .into_iter()
            .collect(),
            "another owner of the same machine must not add an address"
        );

        // The invariant that does matter: one name, two addresses, is refused
        // rather than silently resolved to whichever node was visited last.
        let mut competing = topology.nodes["camera"].clone();
        competing.id = "other-camera".into();
        competing.ips.clear();
        let other = "192.168.10.31".parse().unwrap();
        competing.ips.insert(
            other,
            IpRecord {
                addr: other,
                prefix: Some(24),
                vlan: None,
                origins: BTreeSet::new(),
            },
        );
        topology.nodes.insert(competing.id.clone(), competing);
        assert!(derive_host_records(&topology, &[binding], "mycelium", None).is_err());
    }

    /// The CLI composition end to end: host records from the shared address
    /// rule, then the shared naming rule. A lease endpoint on the overlay lands
    /// on the overlay host record, so the preview and the resolver answer with
    /// the same address for the same claim.
    #[test]
    fn a_lease_endpoint_on_the_overlay_lands_on_the_overlay_host_record() {
        let mut topology = Topology::empty();
        let mut node = TopoNode {
            id: "neo".into(),
            hostnames: BTreeSet::from(["neo".into()]),
            sites: BTreeSet::from(["home".into()]),
            ..TopoNode::default()
        };
        let overlay = "fd7a:115c:a1e0::6".parse().unwrap();
        node.ips.insert(
            overlay,
            IpRecord {
                addr: overlay,
                prefix: None,
                vlan: None,
                origins: BTreeSet::new(),
            },
        );
        topology.nodes.insert(node.id.clone(), node);
        let hosts = derive_host_records(&topology, &[home_binding()], "myc", None).unwrap();
        let catalog: fpl_resource_observation::ServiceCatalog =
            serde_json::from_value(serde_json::json!({
                "schema_version": 1,
                "observations": [{
                    "schema_version": 1,
                    "service_id": "service/neo/application/unibus",
                    "observed_at": 100,
                    "expires_at": 200,
                    "provenance": {
                        "provider": "mycelium-application-owner-lease",
                        "observer": "neo"
                    },
                    "confidence": "strong",
                    "value": {
                        "kind": "unibus",
                        "names": ["unibus.myc"],
                        "endpoints": ["https://[fd7a:115c:a1e0::6]:8444"],
                        "attributes": {"node_id": "neo"}
                    }
                }]
            }))
            .unwrap();
        let naming = mycelium_dns_policy::settings::Policy {
            service_aliases: BTreeMap::new(),
            service_index_peers: BTreeMap::new(),
            reachable_prefixes: Vec::new(),
            suffix: "myc".into(),
            site: "home".into(),
        };
        let (services, expiry) = mycelium_dns_policy::service_names::project_service_records(
            &naming, &hosts, &catalog, 100,
        )
        .unwrap();
        assert_eq!(expiry, Some(200));
        let projected = services
            .iter()
            .find(|record| record.name == "unibus.neo.home.myc")
            .expect("the service name lands on the overlay host record");
        assert_eq!(projected.address, overlay);
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

    #[test]
    fn derives_overlay_zone_from_the_shared_overlay_space() {
        let mut topology = Topology::empty();
        let mut node = TopoNode {
            id: "neo".into(),
            ..TopoNode::default()
        };
        node.hostnames.insert("neo".into());
        let overlay_ip = "100.64.0.7".parse().unwrap();
        let origin =
            mycelium_core::topology::Origin::new("neo", "wireguard-binding").at_site("home");
        node.ips.insert(
            overlay_ip,
            IpRecord {
                addr: overlay_ip,
                prefix: None,
                vlan: None,
                origins: BTreeSet::from(["home/neo:wireguard-binding".to_string()]),
            },
        );
        node.overlays.insert(
            "mycelium0/home/neo:wireguard-binding".to_string(),
            mycelium_core::topology::OverlayPeerRecord {
                network: "mycelium0".into(),
                protocol: mycelium_core::topology::MeshProtocol::WireGuard,
                control_plane: mycelium_core::topology::MeshControlPlane {
                    coordinator: mycelium_core::topology::MeshCoordinator::Custom,
                    url: None,
                },
                self_node: true,
                tailnet: None,
                dns_name: Some("neo.home.mycelium".into()),
                backend_state: None,
                observer: "neo".into(),
                online: false,
                active: false,
                relay: None,
                endpoint: None,
                routed_lans: BTreeSet::new(),
                observed_at: 1,
                origin,
            },
        );
        topology.nodes.insert(node.id.clone(), node);
        let records = derive_overlay_records(&topology, "mycelium").unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].name, "neo.mycelium");
        assert_eq!(records[0].address, overlay_ip);
    }
}
