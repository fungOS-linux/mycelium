//! Host records from the daemon's authenticated peer view.
//!
//! The resolver driver and `mycelium dns zone` must publish the same records for
//! the same fleet, so the adaptation from the daemon's `PeerList` view to DNS
//! records lives here, once. The caller supplies the policy inputs it applies
//! (suffix, admitted sites, reachable scopes, freshness bound); nothing about the
//! JSON shape of the peer view leaks past this module.
//!
//! Two record families come out of one peer observation:
//! - site records, `node.site.suffix`, for every publishable address: a path into
//!   a site, which is what the site zone is for;
//! - flat records, `node.suffix`, IPv6 only: the address a node is reachable at
//!   from anywhere. IPv4 is a path (LAN, WireGuard mesh), not an identity, so a
//!   flat IPv4 answer would name a route that only exists inside one site.

use crate::addresses::publishable_address;
use crate::{canonical_domain, Delegation, DnsRecord};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

/// The policy inputs a peer projection applies.
pub struct PeerScope<'a> {
    pub suffix: &'a str,
    pub site: &'a str,
    pub mesh_sites: bool,
    pub additional_sites: &'a [String],
    pub reachable_prefixes: &'a [String],
    pub expiry_seconds: u64,
    /// Subtrees another resolver owns; names under them are never published.
    pub delegations: &'a [Delegation],
}

impl PeerScope<'_> {
    fn admits_site(&self, site: &str) -> bool {
        self.mesh_sites
            || site == self.site
            || self.additional_sites.iter().any(|known| known == site)
    }
}

/// Records derived from one peer observation.
pub struct HostRecords {
    pub site: Vec<DnsRecord>,
    pub flat: Vec<DnsRecord>,
}

impl HostRecords {
    /// Both families, in one deterministic order. Callers that project service
    /// names use [`Self::site`] alone: a service name is a site's name, and a
    /// flat service name would collide across sites.
    pub fn merge(self) -> Vec<DnsRecord> {
        let mut records = self.site;
        records.extend(self.flat);
        records.sort();
        records.dedup_by(|left, right| left.name == right.name && left.address == right.address);
        records
    }
}

/// Adapt the daemon's JSON peer view, already subject to fleet authentication.
/// Expired identities cannot squat a name after re-enrollment, and competing
/// live owners fail closed instead of arbitrarily choosing an identity.
pub fn host_records(peers: &Value, scope: &PeerScope<'_>, now: u64) -> Result<HostRecords, String> {
    let peers = peers.as_array().ok_or("peers must be an array")?;
    let suffix = canonical_domain(scope.suffix)?;
    let mut site_records = BTreeSet::new();
    let mut flat_records = BTreeSet::new();
    let mut site_owners = BTreeMap::<String, String>::new();
    let mut flat_owners = BTreeMap::<String, String>::new();
    for peer in peers {
        let Some(hello) = peer.get("hello") else {
            continue;
        };
        let Some(peer_site) = hello["site"].as_str() else {
            continue;
        };
        if !scope.admits_site(peer_site) {
            continue;
        }
        let Some(seen) = peer["last_seen"].as_u64() else {
            continue;
        };
        if seen > now + 30 || now.saturating_sub(seen) > scope.expiry_seconds {
            continue;
        }
        let site = canonical_domain(peer_site)?;
        if site != peer_site || site.contains('.') {
            return Err("peer site must be one canonical DNS label".into());
        }
        let Some(node) = hello["node_id"].as_str() else {
            continue;
        };
        let Some(host) = hello["hostname"].as_str() else {
            continue;
        };
        let host = canonical_domain(host)?;
        if host.contains('.') {
            return Err("peer hostname must be one DNS label".into());
        }
        let site_name = format!("{host}.{site}.{suffix}");
        let flat_name = format!("{host}.{suffix}");
        // A configured delegation owns its subtree, even for authenticated peers.
        let delegated = |name: &str| {
            scope.delegations.iter().any(|delegation| {
                name == delegation.zone || name.ends_with(&format!(".{}", delegation.zone))
            })
        };
        let Some(interfaces) = hello["interfaces"].as_array() else {
            continue;
        };
        for address in interfaces
            .iter()
            .filter_map(|interface| interface["addresses"].as_array())
            .flatten()
            .filter_map(|address| {
                address
                    .as_str()
                    .and_then(|value| value.parse::<IpAddr>().ok())
            })
        {
            if !publishable_address(address, scope.reachable_prefixes) {
                continue;
            }
            if !delegated(&site_name) {
                if site_owners
                    .insert(site_name.clone(), node.to_owned())
                    .is_some_and(|owner| owner != node)
                {
                    return Err(format!("competing live owners for {site_name}"));
                }
                site_records.insert(DnsRecord {
                    name: site_name.clone(),
                    address,
                    site: peer_site.into(),
                    node: node.into(),
                });
            }
            if address.is_ipv6() && !delegated(&flat_name) {
                if flat_owners
                    .insert(flat_name.clone(), node.to_owned())
                    .is_some_and(|owner| owner != node)
                {
                    return Err(format!("competing live owners for {flat_name}"));
                }
                flat_records.insert(DnsRecord {
                    name: flat_name.clone(),
                    address,
                    site: peer_site.into(),
                    node: node.into(),
                });
            }
        }
    }
    Ok(HostRecords {
        site: site_records.into_iter().collect(),
        flat: flat_records.into_iter().collect(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn scopes() -> Vec<String> {
        vec!["192.168.10.0/24".into(), "fd7a:115c:a1e0::/64".into()]
    }

    struct Fixture {
        prefixes: Vec<String>,
        additional: Vec<String>,
        delegations: Vec<Delegation>,
        site: String,
        mesh_sites: bool,
        expiry: u64,
    }

    impl Default for Fixture {
        fn default() -> Self {
            Self {
                prefixes: scopes(),
                additional: Vec::new(),
                delegations: Vec::new(),
                site: "lab".into(),
                mesh_sites: true,
                expiry: 300,
            }
        }
    }

    impl Fixture {
        fn project(&self, peers: Value, now: u64) -> Result<HostRecords, String> {
            host_records(
                &peers,
                &PeerScope {
                    suffix: "myc",
                    site: &self.site,
                    mesh_sites: self.mesh_sites,
                    additional_sites: &self.additional,
                    reachable_prefixes: &self.prefixes,
                    expiry_seconds: self.expiry,
                    delegations: &self.delegations,
                },
                now,
            )
        }
    }

    fn peer(hostname: &str, node: &str, site: &str, seen: u64, addresses: &[&str]) -> Value {
        json!({
            "hello": {
                "node_id": node,
                "hostname": hostname,
                "site": site,
                "interfaces": [{"addresses": addresses}]
            },
            "last_seen": seen
        })
    }

    #[test]
    fn a_peer_yields_site_records_and_a_flat_ipv6_name() {
        let fixture = Fixture::default();
        let records = fixture
            .project(
                json!([peer(
                    "neo",
                    "n1",
                    "lab",
                    1000,
                    &["192.168.10.30", "fd7a:115c:a1e0::6"],
                )]),
                1000,
            )
            .unwrap();
        assert_eq!(records.site.len(), 2);
        assert_eq!(
            records.flat,
            vec![DnsRecord {
                name: "neo.myc".into(),
                address: "fd7a:115c:a1e0::6".parse().unwrap(),
                site: "lab".into(),
                node: "n1".into(),
            }],
            "a flat name is IPv6 only: IPv4 is a path into a site"
        );
    }

    #[test]
    fn expired_identities_and_unadmitted_sites_publish_nothing() {
        let fixture = Fixture::default();
        assert!(fixture
            .project(
                json!([peer("neo", "n1", "lab", 1, &["192.168.10.30"])]),
                1000
            )
            .unwrap()
            .site
            .is_empty());
        let mut closed = Fixture {
            mesh_sites: false,
            ..Fixture::default()
        };
        assert!(closed
            .project(
                json!([peer("neo", "n1", "titan", 1000, &["192.168.10.30"])]),
                1000
            )
            .unwrap()
            .site
            .is_empty());
        closed.additional.push("titan".into());
        assert_eq!(
            closed
                .project(
                    json!([peer("neo", "n1", "titan", 1000, &["192.168.10.30"])]),
                    1000
                )
                .unwrap()
                .site
                .len(),
            1
        );
    }

    #[test]
    fn addresses_outside_the_scope_never_publish() {
        let fixture = Fixture::default();
        let records = fixture
            .project(
                json!([peer("neo", "n1", "lab", 1000, &["172.16.0.9", "fe80::1"])]),
                1000,
            )
            .unwrap();
        assert!(records.site.is_empty());
        assert!(records.flat.is_empty());
    }

    #[test]
    fn two_machines_with_one_name_fail_closed_in_each_family() {
        let fixture = Fixture::default();
        assert!(fixture
            .project(
                json!([
                    peer("neo", "n1", "lab", 1000, &["192.168.10.30"]),
                    peer("neo", "n2", "lab", 1000, &["192.168.10.31"])
                ]),
                1000,
            )
            .is_err());
        assert!(fixture
            .project(
                json!([
                    peer("neo", "n1", "lab", 1000, &["fd7a:115c:a1e0::6"]),
                    peer("neo", "n2", "lab", 1000, &["fd7a:115c:a1e0::7"])
                ]),
                1000,
            )
            .is_err());
    }

    #[test]
    fn the_same_peer_in_two_sites_keeps_one_flat_name() {
        let fixture = Fixture::default();
        let records = fixture
            .project(
                json!([
                    peer("neo", "n1", "lab", 1000, &["fd7a:115c:a1e0::6"]),
                    peer("neo", "n1", "deck", 1000, &["fd7a:115c:a1e0::6"])
                ]),
                1000,
            )
            .unwrap();
        assert_eq!(records.site.len(), 2, "one record per site");
        assert_eq!(
            records.merge().len(),
            3,
            "two site records plus one flat name"
        );
    }

    #[test]
    fn a_delegated_subtree_is_never_published() {
        let mut fixture = Fixture::default();
        fixture.delegations.push(Delegation {
            zone: "lab.myc".into(),
            site: "lab".into(),
            owner: "dns-host".into(),
            server: "192.0.2.53".parse().unwrap(),
            port: 53,
        });
        let records = fixture
            .project(
                json!([peer(
                    "neo",
                    "n1",
                    "lab",
                    1000,
                    &["192.168.10.30", "fd7a:115c:a1e0::6"]
                )]),
                1000,
            )
            .unwrap();
        assert!(
            records.site.is_empty(),
            "the delegated zone owns every name under it"
        );
        assert_eq!(
            records.flat.len(),
            1,
            "the flat name is outside the delegated subtree"
        );
    }
}
