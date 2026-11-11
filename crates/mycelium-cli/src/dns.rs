use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

use mycelium_core::topology::Topology;
pub(crate) use mycelium_dns_policy::{canonical_domain, plan, Delegation, DnsRecord};
use mycelium_dns_policy::{BlockAction, Blocklist, BlocklistSource};
use mycelium_peer_protocol::WireGuardBinding;
use myceliumd::protocol::Request;
use std::path::{Path, PathBuf};

/// IPv6 unique-local address (`fc00::/7`). Mycelium's overlay lives here, and
/// an address in this range belongs to the node by identity rather than by
/// whatever network it happens to be attached to.
fn is_unique_local(address: IpAddr) -> bool {
    matches!(address, IpAddr::V6(v6) if (v6.segments()[0] & 0xfe00) == 0xfc00)
}

pub(crate) fn derive_records(
    topology: &Topology,
    bindings: &[WireGuardBinding],
    suffix: &str,
) -> Result<Vec<DnsRecord>, String> {
    let suffix = canonical_domain(suffix)?;
    let mut records = BTreeSet::new();
    let mut names = BTreeMap::<String, String>::new();
    let mut addresses = BTreeMap::<(String, bool), IpAddr>::new();
    // Service names are not node names: many nodes may publish the same kind,
    // so a competing owner is normal here. Resolved by preference (this site
    // first, then the smallest owner id for determinism) rather than by the
    // error a node name would raise for two machines claiming one name.
    let mut service = BTreeMap::<(String, bool), (IpAddr, String, bool, String)>::new();
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
                // Every machine has a `localhost` hostname, so it can never
                // name a node: it would collide across the whole fleet.
                .filter(|value| !value.eq_ignore_ascii_case("localhost"))
            else {
                continue;
            };
            let site = dns_label(&binding.site);
            for address in node
                .ips
                .keys()
                .copied()
                // The overlay's own address space is always valid for a .myc
                // name. Those addresses are derived from the node identity, so
                // they are stable across networks and restarts, which is the
                // property a DNS record needs. Binding prefixes cover
                // everything else, and must not be allowed to hide the overlay
                // address the name is actually for.
                .filter(|address| {
                    is_unique_local(*address)
                        || prefixes.iter().any(|prefix| prefix.contains(*address))
                })
            {
                let name = format!("{label}.{site}.{suffix}");
                // Several node records can describe one machine — one per
                // overlay network — so the same name legitimately arrives from
                // more than one id. The invariant that matters is that a name
                // resolves to one address, which the check below enforces;
                // rejecting a shared owner would fail on healthy topologies.
                names.entry(name.clone()).or_insert_with(|| node.id.clone());
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

        // An application lease carries its kind and endpoints, so a published
        // service earns an apex name: `unibus.<suffix>` points at a hub, not at
        // a machine. A name resolves to an address, not a port, so an endpoint
        // is reduced to its host - and both families come free, because the
        // record already carries an IpAddr.
        for advertisement in topology.advertisements.values() {
            if advertisement.service_type != "_application-owner._tcp" {
                continue;
            }
            let Some(encoded) = advertisement
                .txt
                .iter()
                .find_map(|value| value.strip_prefix("observation="))
            else {
                continue;
            };
            let Ok(observation) = serde_json::from_str::<serde_json::Value>(encoded) else {
                continue;
            };
            let Some(kind) = observation["value"]["kind"].as_str() else {
                continue;
            };
            if !service_label(kind) {
                continue;
            }
            let Some(endpoint) = observation["value"]["endpoints"]
                .as_array()
                .and_then(|endpoints| endpoints.first())
                .and_then(|endpoint| endpoint.as_str())
            else {
                continue;
            };
            let Some(address) = endpoint_address(endpoint) else {
                continue;
            };
            // `plan` refuses a loopback, unspecified or multicast record and
            // fails the whole site when it sees one. A lease that names such an
            // endpoint is a service only this node can dial, so it earns no
            // name - and, crucially, cannot take the site's DNS down with it.
            if address.is_unspecified() || address.is_loopback() || address.is_multicast() {
                continue;
            }
            let Some(owner) = advertisement.target.clone() else {
                continue;
            };
            let in_site = topology
                .nodes
                .get(&owner)
                .is_none_or(|node| node.sites.is_empty() || node.sites.contains(&binding.site));
            let key = (format!("{kind}.{suffix}"), address.is_ipv4());
            let candidate = (address, owner, in_site, binding.site.clone());
            match service.get(&key) {
                // The incumbent already answers for this site; keep it.
                Some((_, _, true, _)) if !in_site => {}
                // Neither is local: pick deterministically instead of by order.
                Some((_, existing, false, _)) if !in_site && existing < &candidate.1 => {}
                _ => {
                    service.insert(key, candidate);
                }
            }
        }
    }

    for ((name, family), (address, owner, _, site)) in service {
        names.insert(name.clone(), owner.clone());
        addresses.insert((name.clone(), family), address);
        records.insert(DnsRecord {
            name,
            address,
            // A service name is still a site's name: `plan` keeps only records
            // for the site it is planning, so an empty site here silently
            // dropped every one of them.
            site,
            node: owner,
        });
    }
    Ok(records.into_iter().collect())
}

/// Whether a service kind is a name a fleet should resolve.
///
/// The rule is the shape of the kind, not a curated list: `confluence` and
/// `unibus` are names, while `redis/tcp/6379` is a fact about one node's port.
/// A list would have to be edited every time a Spore declares a new kind, and
/// it would be edited in Mycelium - by whoever remembers to - rather than in
/// the Spore that owns the name.
fn service_label(kind: &str) -> bool {
    !kind.is_empty()
        && kind.len() <= 63
        && kind.chars().all(|character| {
            character.is_ascii_lowercase() || character.is_ascii_digit() || character == '-'
        })
}

/// `tcp://10.0.0.1:18890` -> 10.0.0.1.
fn endpoint_address(endpoint: &str) -> Option<IpAddr> {
    let rest = endpoint.split_once("://")?.1;
    let host = rest.rsplit_once(':').map(|(host, _)| host).unwrap_or(rest);
    host.trim_matches(['[', ']']).parse().ok()
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

    /// A one-node fleet whose only interesting fact is the lease it publishes.
    fn hub_publishing(kind: &str, endpoint: &str) -> Topology {
        use mycelium_core::{Observation, Origin, ServiceAdvertisement};

        let mut topology = Topology::empty();
        let hub = TopoNode {
            id: "hub-cell".into(),
            hostnames: BTreeSet::from(["hub".into()]),
            sites: BTreeSet::from(["home".into()]),
            ..TopoNode::default()
        };
        topology.nodes.insert(hub.id.clone(), hub);

        // Exactly the document `myceliumd` projects into the advertisement.
        let lease = serde_json::json!({
            "schema_version": 1,
            "service_id": format!("service/hub-cell/application/{kind}"),
            "observed_at": 100,
            "expires_at": 160,
            "provenance": {"provider": "application", "observer": "hub-cell"},
            "confidence": "strong",
            "value": {
                "kind": kind,
                "endpoints": [endpoint],
                "attributes": {"node_id": "hub-cell"}
            }
        });
        topology.observe_all(vec![Observation::ServiceAdvertisement {
            advertisement: ServiceAdvertisement {
                instance: format!("service/hub-cell/application/{kind}"),
                service_type: "_application-owner._tcp".into(),
                domain: "hub-cell.mycelium".into(),
                target: Some("hub-cell".into()),
                addresses: BTreeSet::new(),
                port: None,
                txt: BTreeSet::from([format!("observation={lease}")]),
                interface: None,
                ttl: Some(60),
                first_seen: 100,
                last_seen: 100,
                origins: BTreeSet::from(["hub-cell".into()]),
            },
            origin: Origin::new("hub-cell", "application-owner-lease"),
        }]);
        topology
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

    #[test]
    fn a_service_observation_earns_an_apex_name() {
        let topology = hub_publishing("unibus", "tcp://10.253.0.6:18890");
        let records = derive_records(&topology, &[home_binding()], "myc").unwrap();

        // Through the planner, not just the derivation: `plan` keeps only the
        // records belonging to the site it is planning, and the planner is what
        // the resolver actually applies. Testing the derivation alone would
        // pass while every service name was silently dropped.
        let planned = plan("home", "myc", records, Vec::new()).expect("the site plan applies");
        let unibus = planned
            .records
            .iter()
            .find(|record| record.name == "unibus.myc")
            .expect("a published service earns an apex name");
        assert_eq!(unibus.address.to_string(), "10.253.0.6");

        // Both families, no special case: the endpoint decides.
        let v6 = endpoint_address("tcp://[fd7a:115c:a1e0::6]:18890").expect("v6 endpoint");
        assert!(v6.is_ipv6());
        assert_eq!(v6.to_string(), "fd7a:115c:a1e0::6");
        assert!(endpoint_address("not-an-endpoint").is_none());
    }

    #[test]
    fn a_lease_no_other_node_could_dial_earns_no_name() {
        let topology = hub_publishing("unibus", "tcp://127.0.0.1:18890");
        let records = derive_records(&topology, &[home_binding()], "myc").unwrap();

        // `plan` refuses a loopback record and fails the whole site when it
        // meets one, so this lease must earn nothing and break nothing.
        let planned = plan("home", "myc", records, Vec::new())
            .expect("a lease only its own node can dial must not take the site down");
        assert!(planned.records.is_empty(), "{:?}", planned.records);
    }

    #[test]
    fn a_port_derived_kind_is_not_a_name() {
        let topology = hub_publishing("redis/tcp/6379", "tcp://10.253.0.6:6379");
        let records = derive_records(&topology, &[home_binding()], "myc").unwrap();
        assert!(
            records.is_empty(),
            "a port is a fact about one node, not a fleet name: {records:?}"
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
            2,
            "one name, both families"
        );
        // Several node records can describe one machine -- one per overlay
        // network -- so the same name arriving from more than one id is normal
        // as long as it resolves to one address.
        let mut same_machine = topology.nodes["camera"].clone();
        same_machine.id = "camera-on-another-overlay".into();
        topology.nodes.insert(same_machine.id.clone(), same_machine);
        let shared = derive_records(&topology, &[binding.clone()], "mycelium").unwrap();
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
