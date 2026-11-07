use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

use mycelium_core::topology::{Topology, MYCELIUM_OVERLAY_NETWORK};
use mycelium_peer_protocol::WireGuardBinding;
use serde::Serialize;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub(crate) struct DnsRecord {
    pub name: String,
    pub address: IpAddr,
    pub site: String,
    pub node: String,
}

pub(crate) fn derive_records(
    topology: &Topology,
    bindings: &[WireGuardBinding],
    suffix: &str,
) -> Result<Vec<DnsRecord>, String> {
    let suffix = suffix.trim_matches('.').to_ascii_lowercase();
    if suffix.is_empty() {
        return Err("DNS suffix cannot be empty".into());
    }
    let mut records = BTreeSet::new();
    let mut names = BTreeMap::<String, IpAddr>::new();
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
                    site: binding.site.clone(),
                    node: node.id.clone(),
                });
            }
        }
    }
    Ok(records.into_iter().collect())
}

/// Derive the overlay zone: `node.<suffix>` -> the node's overlay address.
///
/// Overlay addresses belong to one transport-agnostic space. A client that
/// resolves one of these names reaches the node either over a routed WireGuard
/// fast path or, when the address is unrouted, through the local proxy that
/// dials the peer over iroh. The DNS layer deliberately does not distinguish
/// the two: it publishes reachability, not transport.
pub(crate) fn derive_overlay_records(
    topology: &Topology,
    suffix: &str,
) -> Result<Vec<DnsRecord>, String> {
    let suffix = suffix.trim_matches('.').to_ascii_lowercase();
    if suffix.is_empty() {
        return Err("DNS suffix cannot be empty".into());
    }
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
        let binding = WireGuardBinding {
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
        let records = derive_records(&topology, &[binding], "mycelium").unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].name, "front-camera.home.mycelium");
        assert_eq!(records[0].address.to_string(), "192.168.10.30");
    }

    #[test]
    fn derives_overlay_zone_from_the_shared_overlay_space() {
        let mut topology = Topology::empty();
        let mut node = TopoNode::default();
        node.id = "neo".into();
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
            format!("mycelium0/home/neo:wireguard-binding"),
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
