//! Site DNS records and delegated namespace intent, independent of discovery providers.
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

/// Namespace ownership, not a second registry of the owner's members.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Delegation {
    pub zone: String,
    pub site: String,
    pub owner: String,
    pub server: IpAddr,
    pub port: u16,
}

#[derive(Debug, Serialize)]
pub struct DnsPlan {
    pub site: String,
    pub suffix: String,
    pub records: Vec<DnsRecord>,
    pub delegations: Vec<Delegation>,
    pub dnsmasq: String,
    pub apply_supported: bool,
    pub verification_required: Vec<&'static str>,
}

pub fn plan(
    site: &str,
    suffix: &str,
    mut records: Vec<DnsRecord>,
    mut delegations: Vec<Delegation>,
) -> Result<DnsPlan, String> {
    let suffix = canonical_domain(suffix)?;
    if site.is_empty() || site.len() > 128 || site.chars().any(char::is_control) {
        return Err("invalid DNS site".into());
    }
    if delegations.len() > 32 || records.len() > 4096 {
        return Err("DNS plan exceeds record or delegation bound".into());
    }
    let mut zones = BTreeSet::new();
    for delegation in &mut delegations {
        delegation.zone = canonical_domain(&delegation.zone)?;
        if delegation.site != site
            || delegation.owner.is_empty()
            || delegation.owner.len() > 128
            || delegation.owner.chars().any(char::is_control)
            || delegation.port == 0
            || delegation.server.is_unspecified()
            || delegation.server.is_multicast()
            || delegation.server.is_loopback()
            || matches!(delegation.server, IpAddr::V4(ip) if ip.is_link_local() || ip.is_broadcast())
            || matches!(delegation.server, IpAddr::V6(ip) if ip.is_unicast_link_local())
        {
            return Err(
                "delegation needs a site-local, non-loopback resolver and explicit owner/port"
                    .into(),
            );
        }
        if within(&suffix, &delegation.zone) {
            return Err("delegation cannot take ownership of the Mycelium namespace".into());
        }
        if !zones.insert(delegation.zone.clone()) {
            return Err("duplicate delegated namespace".into());
        }
    }
    for (index, a) in delegations.iter().enumerate() {
        for b in &delegations[index + 1..] {
            if within(&a.zone, &b.zone) || within(&b.zone, &a.zone) {
                return Err(
                    "overlapping delegated namespaces require an explicit owner boundary".into(),
                );
            }
        }
    }
    records.retain(|record| record.site == site);
    let mut owners = BTreeMap::new();
    for record in &mut records {
        record.name = canonical_domain(&record.name)?;
        if record.node.is_empty()
            || record.address.is_unspecified()
            || record.address.is_loopback()
            || record.address.is_multicast()
        {
            return Err("invalid DNS record identity or address".into());
        }
        if owners
            .insert(record.name.clone(), record.node.clone())
            .is_some_and(|node| node != record.node)
        {
            return Err("DNS name has competing node owners".into());
        }
        if !within(&record.name, &suffix)
            || delegations.iter().any(|d| within(&record.name, &d.zone))
        {
            return Err("Mycelium record crosses namespace ownership".into());
        }
    }
    records.sort();
    records.dedup();
    delegations.sort_by(|a, b| a.zone.cmp(&b.zone));
    let mut dnsmasq = format!(
        "# Generated Mycelium site DNS fragment; review before installation.\nlocal=/{suffix}/\n"
    );
    for record in &records {
        dnsmasq.push_str(&format!("host-record={},{}\n", record.name, record.address));
    }
    for delegation in &delegations {
        let server = delegation.server.to_string();
        dnsmasq.push_str(&format!(
            "server=/{}/{server}#{}\n",
            delegation.zone, delegation.port
        ));
    }
    Ok(DnsPlan {
        site: site.into(),
        suffix,
        records,
        delegations,
        dnsmasq,
        apply_supported: false,
        verification_required: vec![
            "check namespace ownership and resolver reachability from the DNS host",
            "verify authoritative negative answers do not recurse to uplink DNS",
            "verify Mycelium records, delegated records and unrelated uplink queries",
            "verify resolver reload and reboot persistence using its owning driver",
        ],
    })
}

fn within(name: &str, zone: &str) -> bool {
    name == zone || name.ends_with(&format!(".{zone}"))
}

pub fn canonical_domain(value: &str) -> Result<String, String> {
    let value = value.trim_end_matches('.').to_ascii_lowercase();
    if value.is_empty()
        || value.len() > 253
        || value == "local"
        || value.ends_with(".local")
        || !value.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
        })
    {
        return Err(
            "invalid DNS namespace (wildcards, .local and configuration syntax are forbidden)"
                .into(),
        );
    }
    Ok(value)
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DnsRecord {
    pub name: String,
    pub address: IpAddr,
    pub site: String,
    pub node: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    fn delegation() -> Delegation {
        Delegation {
            zone: "shroud.svc".into(),
            site: "lab".into(),
            owner: "shroud".into(),
            server: "192.0.2.53".parse().unwrap(),
            port: 53,
        }
    }
    fn record() -> DnsRecord {
        DnsRecord {
            name: "node.lab.mesh.example.net".into(),
            address: "192.0.2.12".parse().unwrap(),
            site: "lab".into(),
            node: "peer-identity".into(),
        }
    }
    #[test]
    fn delegates_namespace_without_importing_members_or_changing_default_dns() {
        let p = plan(
            "lab",
            "mesh.example.net",
            vec![record()],
            vec![delegation()],
        )
        .unwrap();
        assert!(!p.apply_supported);
        assert_eq!(p.records.len(), 1);
        assert!(p.dnsmasq.contains("local=/mesh.example.net/"));
        assert!(p.dnsmasq.contains("server=/shroud.svc/192.0.2.53#53"));
        assert!(!p.dnsmasq.contains("server=192.0.2.53"));
        assert!(!p.dnsmasq.contains("no-resolv"));
        assert!(!p.dnsmasq.contains("address=/shroud.svc/"));
    }
    #[test]
    fn no_serving_members_does_not_remove_namespace_delegation() {
        let p = plan("lab", "mesh.example.net", vec![], vec![delegation()]).unwrap();
        assert!(p.records.is_empty());
        assert_eq!(p.delegations.len(), 1);
    }
    #[test]
    fn rejects_takeover_overlap_and_duplicate_delegation() {
        for zone in ["mesh.example.net", "example.net", "net"] {
            let mut d = delegation();
            d.zone = zone.into();
            assert!(plan("lab", "mesh.example.net", vec![], vec![d]).is_err());
        }
        let d = delegation();
        assert!(plan(
            "lab",
            "mesh.example.net",
            vec![],
            vec![d.clone(), d.clone()]
        )
        .is_err());
        let mut child = d.clone();
        child.zone = "child.shroud.svc".into();
        assert!(plan("lab", "mesh.example.net", vec![], vec![d, child]).is_err());
    }
    #[test]
    fn refuses_records_in_delegated_namespace_and_cross_zone_records() {
        let mut d = delegation();
        d.zone = "services.mesh.example.net".into();
        let mut r = record();
        r.name = "api.services.mesh.example.net".into();
        assert!(plan("lab", "mesh.example.net", vec![r], vec![d]).is_err());
        let mut r = record();
        r.name = "peer.other.net".into();
        assert!(plan("lab", "mesh.example.net", vec![r], vec![]).is_err());
    }
    #[test]
    fn scopes_records_and_authorities_to_the_requested_site() {
        let mut r = record();
        r.site = "other".into();
        assert!(plan("lab", "mesh.example.net", vec![r], vec![])
            .unwrap()
            .records
            .is_empty());
        let mut d = delegation();
        d.site = "other".into();
        assert!(plan("lab", "mesh.example.net", vec![], vec![d]).is_err());
    }
    #[test]
    fn rejects_dnsmasq_injection_mdns_and_ambiguous_addresses() {
        for zone in [
            "shroud.svc\nserver=1.1.1.1",
            "*.shroud.svc",
            "home.local",
            "bad/zone",
            ".",
            "-bad.example",
        ] {
            assert!(canonical_domain(zone).is_err(), "{zone}");
        }
        for server in [
            "127.0.0.1",
            "::1",
            "0.0.0.0",
            "224.0.0.1",
            "fe80::1",
            "169.254.1.1",
        ] {
            let mut d = delegation();
            d.server = server.parse().unwrap();
            assert!(
                plan("lab", "mesh.example.net", vec![], vec![d]).is_err(),
                "{server}"
            );
        }
    }
    #[test]
    fn deterministic_dual_stack_names_but_competing_owners_fail() {
        let r = record();
        let mut v6 = r.clone();
        v6.address = "2001:db8::12".parse().unwrap();
        let a = plan(
            "lab",
            "MESH.EXAMPLE.NET.",
            vec![v6.clone(), r.clone()],
            vec![],
        )
        .unwrap();
        let b = plan("lab", "mesh.example.net", vec![r.clone(), v6], vec![]).unwrap();
        assert_eq!(a.dnsmasq, b.dnsmasq);
        let mut other = r.clone();
        other.node = "another-peer".into();
        assert!(plan("lab", "mesh.example.net", vec![r, other], vec![]).is_err());
    }
    #[test]
    fn ipv6_resolver_port_and_unknown_fields() {
        let mut d = delegation();
        d.server = "2001:db8::53".parse().unwrap();
        d.port = 5353;
        let p = plan("lab", "mesh.example.net", vec![], vec![d]).unwrap();
        assert!(p.dnsmasq.contains("server=/shroud.svc/2001:db8::53#5353"));
        assert!(serde_json::from_str::<Delegation>(r#"{"zone":"shroud.svc","site":"lab","owner":"shroud","server":"192.0.2.53","port":53,"members":[]}"#).is_err());
    }
}
pub mod resolver;
