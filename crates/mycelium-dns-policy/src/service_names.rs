//! Service names projected from application-owned leases.
//!
//! One rule, two consumers: the resolver turns these names into DNS records and
//! the gateway turns them into host routes. Neither owns the rule, so a service
//! that stops renewing its lease loses its name in both places at the same
//! moment. The claim stage decides *which names exist*; projection only attaches
//! them to addresses the caller already trusts.

use crate::settings::Policy;
use crate::{canonical_domain, DnsRecord};
use fpl_resource_observation::{ServiceCatalog, SCHEMA_VERSION};
use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, SocketAddr};

/// Only a lease the application wrote for itself may claim a name.
pub const APPLICATION_OWNER_LEASE: &str = "mycelium-application-owner-lease";

/// A host address a name can be projected onto. The caller supplies these from
/// whatever it already trusts as its zone.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServiceHost {
    pub name: String,
    pub address: IpAddr,
    pub node: String,
}

/// One label an owner may ask for: lowercase, 1-63 characters, no dot and no
/// leading or trailing hyphen. The zone composes the label into a name, so a
/// lease can never escape into another zone.
pub fn valid_label(label: &str) -> bool {
    !label.is_empty()
        && label.len() <= 63
        && !label.starts_with('-')
        && !label.ends_with('-')
        && label
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

/// A fresh, application-owned lease that publishes at least one name. This is
/// the whole of the naming rule: it needs no address, so a router can use it
/// without knowing the zone's host records.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServiceClaim {
    pub service_id: String,
    pub kind: String,
    /// Zone-composed names (`label.suffix`), deduplicated.
    pub names: Vec<String>,
    pub node: String,
    pub endpoints: BTreeSet<String>,
    pub expires_at: u64,
}

/// One name a service currently claims.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServiceName {
    pub name: String,
    pub kind: String,
    pub node: String,
    pub endpoint: String,
    pub address: IpAddr,
    pub expires_at: u64,
    /// Index into the host slice this name was projected onto.
    pub host: usize,
}

/// Restricted literal HTTPS entrance. Names, paths, credentials and queries are
/// not rewritten or resolved; service catalogs retain ports and transport hints.
pub fn entrance_address(endpoint: &str) -> Option<IpAddr> {
    let authority = endpoint.strip_prefix("https://")?.trim_end_matches('/');
    let socket: SocketAddr = authority.parse().ok()?;
    (socket.port() != 0 && socket.port() != 80).then_some(socket.ip())
}

/// Every service that may currently answer to a name.
pub fn claimed_services(catalog: &ServiceCatalog, now: u64) -> Result<Vec<ServiceClaim>, String> {
    if catalog.schema_version != SCHEMA_VERSION || catalog.observations.len() > 4096 {
        return Err("unsupported or oversized service DNS catalog".into());
    }
    let mut identities = BTreeSet::new();
    let mut owners = BTreeMap::new();
    let mut claims = Vec::new();
    for service in &catalog.observations {
        if service.schema_version != SCHEMA_VERSION
            || !service.is_fresh_at(now)
            || service.expires_at.saturating_sub(service.observed_at) > 300
            || service.provenance.provider != APPLICATION_OWNER_LEASE
            || service.value.attributes.get("node_id") != Some(&service.provenance.observer)
        {
            continue;
        }
        if !identities.insert(&service.service_id) {
            return Err("duplicate service DNS identity".into());
        }
        let node = service.provenance.observer.as_str();
        let mut names = BTreeSet::new();
        for name in &service.value.names {
            if canonical_domain(name)? != *name {
                return Err(format!(
                    "service {} publishes a non-canonical name",
                    service.service_id.0
                ));
            }
            names.insert(name.as_str());
        }
        if names.is_empty() {
            continue;
        }
        for name in names.iter().copied() {
            match owners.insert(name, node) {
                None => {}
                // Two services on one node answering to one name is ambiguous
                // and cannot be arbitrated locally.
                Some(existing) if existing == node => {
                    return Err(format!("two services on {node} claim `{name}`"));
                }
                // The same name on different nodes is the anycast case.
                Some(_) => {}
            }
        }
        claims.push(ServiceClaim {
            service_id: service.service_id.0.clone(),
            kind: service.value.kind.clone(),
            names: names.into_iter().map(str::to_owned).collect(),
            node: node.to_owned(),
            endpoints: service.value.endpoints.clone(),
            expires_at: service.expires_at,
        });
    }
    Ok(claims)
}

/// Project every name the catalog publishes onto the zone's host records.
///
/// A published name is `label.suffix`; this zone answers `label.suffix` from the
/// observer it names as apex (`apex: kind -> node`) and `label.host.suffix` from
/// every node that owns a matching address. Names in another zone are left to
/// that zone.
pub fn project_service_names(
    apex: &BTreeMap<String, String>,
    suffix: &str,
    hosts: &[ServiceHost],
    catalog: &ServiceCatalog,
    now: u64,
) -> Result<Vec<ServiceName>, String> {
    let zone = format!(".{suffix}");
    let mut names = Vec::new();
    for claim in claimed_services(catalog, now)? {
        for name in &claim.names {
            let Some(label) = name.strip_suffix(&zone) else {
                continue;
            };
            if label.is_empty() || label.contains('.') {
                continue;
            }
            for endpoint in &claim.endpoints {
                let Some(address) = entrance_address(endpoint) else {
                    continue;
                };
                for (index, host) in hosts.iter().enumerate() {
                    if host.node != claim.node || host.address != address {
                        continue;
                    }
                    let projected = ServiceName {
                        name: canonical_domain(&format!("{label}.{}", host.name))?,
                        kind: claim.kind.clone(),
                        node: claim.node.clone(),
                        endpoint: endpoint.clone(),
                        address,
                        expires_at: claim.expires_at,
                        host: index,
                    };
                    let bare = (apex.get(&claim.kind) == Some(&claim.node)).then(|| name.clone());
                    names.push(projected.clone());
                    if let Some(name) = bare {
                        names.push(ServiceName { name, ..projected });
                    }
                }
            }
        }
    }
    Ok(names)
}

/// Alias policy fills the names a published catalog left empty.
///
/// The daemon publishes names from the installed policy, and its aliases win
/// over a declared label. This stage is for aliases only the adapter can
/// evaluate (the resolver's Lua plugins): it must never overwrite a name the
/// daemon published or the owner declared, only name a lease that has none.
fn with_fallback_names(
    catalog: &ServiceCatalog,
    aliases: &BTreeMap<String, String>,
    suffix: &str,
) -> Result<ServiceCatalog, String> {
    let mut catalog = catalog.clone();
    for observation in &mut catalog.observations {
        if observation.provenance.provider != APPLICATION_OWNER_LEASE
            || !observation.value.names.is_empty()
        {
            continue;
        }
        let Some(label) = aliases.get(&observation.value.kind) else {
            continue;
        };
        if !valid_label(label) {
            return Err(format!("service alias `{label}` is not one DNS label"));
        }
        observation.value.names = vec![format!("{label}.{suffix}")];
    }
    Ok(catalog)
}

/// Project the claimed names onto the zone's host records — the one DNS half of
/// the naming rule.
///
/// Which names exist is [`claimed_services`]' decision; this attaches each to
/// the host record it names, so the resolver and the CLI preview cannot publish
/// different addresses for the same claim. Records are clones of the host they
/// were projected onto, which is why an overlay host record yields an overlay
/// answer for a service name without any adapter special-casing families.
///
/// Returns the projected records and the earliest lease expiry among them, so a
/// caller can shorten whatever freshness bound it already keeps.
pub fn project_service_records(
    policy: &Policy,
    hosts: &[DnsRecord],
    catalog: &ServiceCatalog,
    now: u64,
) -> Result<(Vec<DnsRecord>, Option<u64>), String> {
    let published = with_fallback_names(catalog, &policy.service_aliases, &policy.suffix)?;
    let service_hosts = hosts
        .iter()
        .map(|record| ServiceHost {
            name: record.name.clone(),
            address: record.address,
            node: record.node.clone(),
        })
        .collect::<Vec<_>>();
    let projected = project_service_names(
        &policy.service_index_peers,
        &policy.suffix,
        &service_hosts,
        &published,
        now,
    )?;
    let mut records = Vec::new();
    let mut entrances = BTreeMap::<(String, IpAddr), String>::new();
    let mut expiry: Option<u64> = None;
    for entry in projected {
        // One entrance per name/address: DNS cannot choose a port or URL.
        if entrances
            .insert((entry.name.clone(), entry.address), entry.endpoint.clone())
            .is_some_and(|old| old != entry.endpoint)
        {
            return Err("ambiguous service entrance; DNS cannot select ports".into());
        }
        let mut record = hosts[entry.host].clone();
        record.name = entry.name;
        records.push(record);
        expiry = Some(match expiry {
            Some(expiry) => expiry.min(entry.expires_at),
            None => entry.expires_at,
        });
    }
    Ok((records, expiry))
}

#[cfg(test)]
mod tests {
    use super::*;
    use fpl_resource_observation::ServiceCatalog;

    fn lease(names: &[&str], observer: &str, node: &str) -> ServiceCatalog {
        serde_json::from_value(serde_json::json!({
            "schema_version": 1,
            "observations": [{
                "schema_version": 1,
                "service_id": format!("service/{observer}/application/store"),
                "observed_at": 100,
                "expires_at": 200,
                "provenance": {"provider": APPLICATION_OWNER_LEASE, "observer": observer},
                "confidence": "strong",
                "value": {
                    "kind": "store",
                    "names": names,
                    "endpoints": ["https://100.108.9.93:8800"],
                    "attributes": {"node_id": node}
                }
            }]
        }))
        .unwrap()
    }

    fn hosts() -> Vec<ServiceHost> {
        vec![ServiceHost {
            name: "studio.wagar-house.myc".to_owned(),
            address: "100.108.9.93".parse().unwrap(),
            node: "n1".to_owned(),
        }]
    }

    #[test]
    fn a_fresh_lease_projects_onto_its_own_host_record() {
        let catalog = lease(&["store.myc"], "n1", "n1");
        let names =
            project_service_names(&BTreeMap::new(), "myc", &hosts(), &catalog, 100).unwrap();
        assert_eq!(names.len(), 1);
        assert_eq!(names[0].name, "store.studio.wagar-house.myc");
        assert_eq!(names[0].kind, "store");
        assert_eq!(names[0].address, "100.108.9.93".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn a_lease_that_is_not_the_application_owners_never_names_anything() {
        let stale = lease(&["store.myc"], "n1", "n1");
        assert!(
            project_service_names(&BTreeMap::new(), "myc", &hosts(), &stale, 201)
                .unwrap()
                .is_empty()
        );

        let mut scanned = lease(&["store.myc"], "n1", "n1");
        scanned.observations[0].provenance.provider = "mdns".into();
        assert!(
            project_service_names(&BTreeMap::new(), "myc", &hosts(), &scanned, 100)
                .unwrap()
                .is_empty()
        );

        let foreign = lease(&["store.myc"], "n1", "n2");
        assert!(
            project_service_names(&BTreeMap::new(), "myc", &hosts(), &foreign, 100)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn the_bare_name_belongs_to_the_observer_the_zone_names() {
        let catalog = lease(&["store.myc"], "n1", "n1");
        let apex = BTreeMap::from([("store".to_owned(), "n1".to_owned())]);
        let names = project_service_names(&apex, "myc", &hosts(), &catalog, 100).unwrap();
        assert_eq!(
            names
                .iter()
                .map(|name| name.name.as_str())
                .collect::<Vec<_>>(),
            vec!["store.studio.wagar-house.myc", "store.myc"]
        );

        let other = BTreeMap::from([("store".to_owned(), "n2".to_owned())]);
        let names = project_service_names(&other, "myc", &hosts(), &catalog, 100).unwrap();
        assert_eq!(names.len(), 1);
    }

    /// A router knows no host records and no addresses: the claim alone is what
    /// it needs, and it is the same rule the resolver applied.
    #[test]
    fn a_claim_exists_without_any_host_record() {
        let catalog = lease(&["store.myc"], "n1", "n1");
        let claims = claimed_services(&catalog, 100).unwrap();
        assert_eq!(claims.len(), 1);
        assert_eq!(claims[0].names, vec!["store.myc".to_owned()]);
        assert_eq!(claims[0].kind, "store");
        assert_eq!(claims[0].node, "n1");

        let nameless = lease(&[], "n1", "n1");
        assert!(claimed_services(&nameless, 100).unwrap().is_empty());
    }

    #[test]
    fn a_name_in_another_zone_is_not_projected_here() {
        let catalog = lease(&["store.example.com"], "n1", "n1");
        assert_eq!(claimed_services(&catalog, 100).unwrap().len(), 1);
        assert!(
            project_service_names(&BTreeMap::new(), "myc", &hosts(), &catalog, 100)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn two_services_on_one_node_cannot_claim_one_name() {
        let mut catalog = lease(&["store.myc"], "n1", "n1");
        let mut second = catalog.observations[0].clone();
        second.service_id.0 = "service/n1/application/other".into();
        second.value.kind = "other".into();
        catalog.observations.push(second);
        assert!(claimed_services(&catalog, 100).is_err());
    }

    #[test]
    fn the_same_name_on_two_nodes_is_the_anycast_case() {
        let mut catalog = lease(&["store.myc"], "n1", "n1");
        let mut second = catalog.observations[0].clone();
        second.service_id.0 = "service/n2/application/store".into();
        second.provenance.observer = "n2".into();
        second
            .value
            .attributes
            .insert("node_id".into(), "n2".into());
        catalog.observations.push(second);
        let claims = claimed_services(&catalog, 100).unwrap();
        assert_eq!(claims.len(), 2);
        assert_eq!(claims[0].names, claims[1].names);
    }

    #[test]
    fn loopback_and_port_80_endpoints_never_become_names() {
        assert!(entrance_address("https://127.0.0.1:80").is_none());
        assert!(entrance_address("http://100.108.9.93:8800").is_none());
        assert!(entrance_address("https://100.108.9.93:0").is_none());
        assert!(entrance_address("https://100.108.9.93:8800").is_some());
    }

    #[test]
    fn a_label_is_one_bounded_dns_label() {
        assert!(valid_label("store"));
        assert!(valid_label("files-2"));
        assert!(!valid_label(""));
        assert!(!valid_label("Store"));
        assert!(!valid_label("store.myc"));
        assert!(!valid_label("-store"));
        assert!(!valid_label("store-"));
        assert!(!valid_label(&"a".repeat(64)));
    }

    fn naming(aliases: &[(&str, &str)], apex: &[(&str, &str)]) -> Policy {
        Policy {
            service_aliases: aliases
                .iter()
                .map(|(kind, label)| ((*kind).to_owned(), (*label).to_owned()))
                .collect(),
            service_index_peers: apex
                .iter()
                .map(|(kind, node)| ((*kind).to_owned(), (*node).to_owned()))
                .collect(),
            suffix: "myc".to_owned(),
            site: "lab".to_owned(),
            ..Policy::default()
        }
    }

    fn host(name: &str, address: &str, node: &str) -> DnsRecord {
        DnsRecord {
            name: name.to_owned(),
            address: address.parse().unwrap(),
            site: "lab".to_owned(),
            node: node.to_owned(),
        }
    }

    /// The address a service name answers with is the host record's address, not
    /// a second derivation: an overlay host record therefore yields an overlay
    /// answer, which is the whole point of sharing this projection.
    #[test]
    fn an_overlay_host_record_carries_the_service_name() {
        let mut catalog = lease(&["unibus.myc"], "n1", "n1");
        catalog.observations[0].value.endpoints =
            BTreeSet::from(["https://[fd7a:115c:a1e0::6]:8444".into()]);
        let hosts = vec![host("neo.lab.myc", "fd7a:115c:a1e0::6", "n1")];
        let (records, expiry) =
            project_service_records(&naming(&[], &[]), &hosts, &catalog, 100).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].name, "unibus.neo.lab.myc");
        assert_eq!(
            records[0].address,
            "fd7a:115c:a1e0::6".parse::<IpAddr>().unwrap()
        );
        assert_eq!(records[0].site, "lab");
        assert_eq!(expiry, Some(200));
    }

    /// A Spore that names itself needs no operator alias; the alias table only
    /// covers leases that publish no names at all.
    #[test]
    fn a_published_name_needs_no_alias_and_an_alias_fills_a_nameless_lease() {
        let hosts = vec![host("studio.wagar-house.myc", "100.108.9.93", "n1")];
        let named = lease(&["store.myc"], "n1", "n1");
        let (records, _) = project_service_records(&naming(&[], &[]), &hosts, &named, 100).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].name, "store.studio.wagar-house.myc");

        let nameless = lease(&[], "n1", "n1");
        assert!(
            project_service_records(&naming(&[], &[]), &hosts, &nameless, 100)
                .unwrap()
                .0
                .is_empty()
        );
        let (records, _) =
            project_service_records(&naming(&[("store", "store")], &[]), &hosts, &nameless, 100)
                .unwrap();
        assert_eq!(records[0].name, "store.studio.wagar-house.myc");
    }

    /// DNS cannot choose a port, so two entrances behind one name and address
    /// must fail loudly rather than publish whichever was visited first.
    #[test]
    fn two_entrances_on_one_name_and_address_fail_closed() {
        let mut catalog = lease(&["store.myc"], "n1", "n1");
        catalog.observations[0]
            .value
            .endpoints
            .insert("https://100.108.9.93:8801".into());
        let hosts = vec![host("studio.wagar-house.myc", "100.108.9.93", "n1")];
        assert!(project_service_records(&naming(&[], &[]), &hosts, &catalog, 100).is_err());
    }
}
