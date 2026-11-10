//! Service names projected from application-owned leases.
//!
//! One rule, two consumers: the resolver turns these into DNS records and the
//! gateway turns them into host routes. Neither owns the rule, so a service that
//! stops renewing its lease loses its name in both places at the same moment.

use crate::canonical_domain;
use fpl_resource_observation::{ServiceCatalog, SCHEMA_VERSION};
use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, SocketAddr};

/// A host address a name can be projected onto. The caller supplies these from
/// whatever it already trusts as its zone.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServiceHost {
    pub name: String,
    pub address: IpAddr,
    pub node: String,
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

/// Project every name the catalog currently claims.
///
/// A name exists only for a fresh lease written by the application itself, on
/// the node that owns the endpoint, and only onto an address the zone already
/// knows. `apex` names the one observer allowed to answer the bare
/// `label.suffix` form for a kind.
pub fn project_service_names(
    aliases: &BTreeMap<String, String>,
    apex: &BTreeMap<String, String>,
    suffix: &str,
    hosts: &[ServiceHost],
    catalog: &ServiceCatalog,
    now: u64,
) -> Result<Vec<ServiceName>, String> {
    if catalog.schema_version != SCHEMA_VERSION || catalog.observations.len() > 4096 {
        return Err("unsupported or oversized service DNS catalog".into());
    }
    let mut identities = BTreeSet::new();
    let mut names = Vec::new();
    for service in &catalog.observations {
        let Some(label) = aliases.get(&service.value.kind) else {
            continue;
        };
        if service.schema_version != SCHEMA_VERSION
            || !service.is_fresh_at(now)
            || service.expires_at.saturating_sub(service.observed_at) > 300
            || service.provenance.provider != "mycelium-application-owner-lease"
            || service.value.attributes.get("node_id") != Some(&service.provenance.observer)
        {
            continue;
        }
        if !identities.insert(&service.service_id) {
            return Err("duplicate service DNS identity".into());
        }
        for endpoint in &service.value.endpoints {
            let Some(address) = entrance_address(endpoint) else {
                continue;
            };
            for (index, host) in hosts.iter().enumerate() {
                if host.node != service.provenance.observer || host.address != address {
                    continue;
                }
                let projected = ServiceName {
                    name: canonical_domain(&format!("{label}.{}", host.name))?,
                    kind: service.value.kind.clone(),
                    node: service.provenance.observer.clone(),
                    endpoint: endpoint.clone(),
                    address,
                    expires_at: service.expires_at,
                    host: index,
                };
                let bare = (apex.get(&service.value.kind) == Some(&service.provenance.observer))
                    .then(|| canonical_domain(&format!("{label}.{suffix}")))
                    .transpose()?;
                names.push(projected.clone());
                if let Some(name) = bare {
                    names.push(ServiceName {
                        name,
                        ..projected
                    });
                }
            }
        }
    }
    Ok(names)
}

#[cfg(test)]
mod tests {
    use super::*;
    use fpl_resource_observation::ServiceCatalog;

    fn catalog(hosts: &str, kind: &str, provider: &str, observer: &str, attributes: serde_json::Value) -> ServiceCatalog {
        serde_json::from_value(serde_json::json!({
            "schema_version": 1,
            "observations": [{
                "schema_version": 1,
                "service_id": "service/n1/application/store",
                "observed_at": 100,
                "expires_at": 200,
                "provenance": {"provider": provider, "observer": observer},
                "confidence": "strong",
                "value": {
                    "kind": kind,
                    "endpoints": ["https://100.108.9.93:8800"],
                    "attributes": attributes
                }
            }]
        }))
        .unwrap()
    }

    fn aliases() -> BTreeMap<String, String> {
        BTreeMap::from([("store".to_owned(), "store".to_owned())])
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
        let catalog = catalog("store", "store", "mycelium-application-owner-lease", "n1", serde_json::json!({"node_id": "n1"}));
        let names = project_service_names(&aliases(), &BTreeMap::new(), "myc", &hosts(), &catalog, 100).unwrap();
        assert_eq!(names.len(), 1);
        assert_eq!(names[0].name, "store.studio.wagar-house.myc");
        assert_eq!(names[0].kind, "store");
        assert_eq!(names[0].address, "100.108.9.93".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn a_lease_that_is_not_the_application_owners_never_names_anything() {
        let stale = catalog("store", "store", "mycelium-application-owner-lease", "n1", serde_json::json!({"node_id": "n1"}));
        assert!(project_service_names(&aliases(), &BTreeMap::new(), "myc", &hosts(), &stale, 201).unwrap().is_empty());

        let scanned = catalog("store", "store", "mdns", "n1", serde_json::json!({"node_id": "n1"}));
        assert!(project_service_names(&aliases(), &BTreeMap::new(), "myc", &hosts(), &scanned, 100).unwrap().is_empty());

        let foreign = catalog("store", "store", "mycelium-application-owner-lease", "n1", serde_json::json!({"node_id": "n2"}));
        assert!(project_service_names(&aliases(), &BTreeMap::new(), "myc", &hosts(), &foreign, 100).unwrap().is_empty());
    }

    #[test]
    fn the_bare_name_belongs_to_the_observer_the_zone_names() {
        let catalog = catalog("store", "store", "mycelium-application-owner-lease", "n1", serde_json::json!({"node_id": "n1"}));
        let apex = BTreeMap::from([("store".to_owned(), "n1".to_owned())]);
        let names = project_service_names(&aliases(), &apex, "myc", &hosts(), &catalog, 100).unwrap();
        assert_eq!(names.iter().map(|n| n.name.as_str()).collect::<Vec<_>>(), vec![
            "store.studio.wagar-house.myc",
            "store.myc"
        ]);

        let other = BTreeMap::from([("store".to_owned(), "n2".to_owned())]);
        let names = project_service_names(&aliases(), &other, "myc", &hosts(), &catalog, 100).unwrap();
        assert_eq!(names.len(), 1);
    }

    #[test]
    fn loopback_and_port_80_endpoints_never_become_names() {
        assert!(entrance_address("https://127.0.0.1:80").is_none());
        assert!(entrance_address("http://100.108.9.93:8800").is_none());
        assert!(entrance_address("https://100.108.9.93:0").is_none());
        assert!(entrance_address("https://100.108.9.93:8800").is_some());
    }
}
