use std::collections::{BTreeMap, BTreeSet};

use fpl_resource_observation::{
    Confidence, Provenance, Service, ServiceCatalog, ServiceId, ServiceObservation, SCHEMA_VERSION,
};
use mycelium_core::{ServiceAdvertisement, ServiceRecord, Topology};

const SERVICE_TTL_SECONDS: u64 = 15 * 60;

pub fn project(topology: &Topology) -> ServiceCatalog {
    let mut catalog = ServiceCatalog {
        schema_version: SCHEMA_VERSION,
        ..ServiceCatalog::default()
    };
    for advertisement in topology.advertisements.values() {
        match crate::local_services::project(advertisement) {
            Ok(Some(observation)) => catalog.observations.push(observation),
            Ok(None) => {}
            Err(error) => eprintln!("application owner lease rejected: {error}"),
        }
    }
    #[cfg(feature = "iroh-discovery")]
    for advertisement in topology.advertisements.values() {
        match mycelium_iroh_discovery::project(advertisement) {
            Ok(Some(observation)) => catalog.observations.push(observation),
            Ok(None) => {}
            Err(error) => eprintln!("Iroh discovery projection rejected: {error}"),
        }
    }
    for (node_id, node) in &topology.nodes {
        for service in node.services.values() {
            let Some((kind, confidence)) = recognize(service) else {
                continue;
            };
            let endpoint_scheme = application_scheme(service, &kind);
            // A listener observation identifies software, not its routability.
            // In particular Kubo RPC is administrative and loopback-only here.
            let endpoints = node
                .ips
                .keys()
                .filter(|_| kind != "ipfs")
                .map(|ip| endpoint(endpoint_scheme, ip.to_string(), service.port))
                .collect();
            let mut protocols = BTreeSet::from([service.transport.to_lowercase()]);
            protocols.insert(endpoint_scheme.into());
            if kind == "mcp" {
                protocols.insert("json-rpc".into());
            }
            let mut formats = BTreeSet::new();
            let evidence = evidence(service);
            if evidence.contains("h264") || evidence.contains("h.264") {
                formats.insert("h264".into());
            }
            let mut attributes = BTreeMap::new();
            attributes.insert("node_id".into(), node_id.clone());
            if let Some(label) = node
                .annotation
                .name
                .as_ref()
                .or_else(|| node.hostnames.iter().next())
            {
                attributes.insert("node_label".into(), label.clone());
            }
            attributes.insert("service_name".into(), service.name.clone());
            if let Some(product) = &service.product {
                attributes.insert("product".into(), product.clone());
            }
            if kind == "ipfs" {
                protocols.insert("ipfs".into());
                let local_rpc =
                    service.name == "ipfs-rpc" && service.origin.source == "kubo-loopback-version";
                attributes.insert(
                    "endpoint_scope".into(),
                    if local_rpc { "host-local" } else { "unknown" }.into(),
                );
                attributes.insert("role".into(), if local_rpc { "rpc" } else { "node" }.into());
                attributes.insert("authentication".into(), "unknown".into());
                if local_rpc {
                    protocols.insert("http".into());
                    attributes.insert("administrative".into(), "true".into());
                    if let Some(version) = service
                        .product
                        .as_deref()
                        .and_then(|p| p.strip_prefix("IPFS Kubo/"))
                    {
                        attributes.insert("implementation".into(), "kubo".into());
                        attributes.insert("version".into(), version.into());
                    }
                }
            }
            if let Some(site) = &service.origin.site {
                attributes.insert("site".into(), site.clone());
            }
            catalog.observations.push(ServiceObservation {
                schema_version: SCHEMA_VERSION,
                service_id: ServiceId(format!(
                    "service/{node_id}/{kind}/{}/{}",
                    service.transport.to_lowercase(),
                    service.port
                )),
                observed_at: service.observed_at,
                expires_at: service.observed_at.saturating_add(SERVICE_TTL_SECONDS),
                provenance: Provenance {
                    provider: "mycelium-topology".into(),
                    observer: service.origin.device.clone(),
                    source_id: Some(format!(
                        "{}:{}/{}",
                        service.transport, service.port, service.name
                    )),
                },
                confidence,
                value: Service {
                    kind,
                    endpoints,
                    protocols,
                    formats,
                    attributes,
                },
            });
        }
    }
    for advertisement in topology.advertisements.values() {
        let Some((kind, confidence)) = recognize_advertisement(advertisement) else {
            continue;
        };
        let Some(port) = advertisement.port else {
            continue;
        };
        let advertised_target = advertisement
            .target
            .as_deref()
            .map(|target| target.trim_end_matches('.').trim_end_matches(".local"));
        let matched_node = topology
            .nodes
            .iter()
            .filter_map(|(node_id, node)| {
                let address_match = advertisement
                    .addresses
                    .iter()
                    .any(|address| node.ips.contains_key(address));
                let listener_match = node.services.values().any(|service| {
                    service.port == port && service.state == mycelium_core::ServiceState::Up
                });
                let identity_match = advertised_target.is_some_and(|target| {
                    node_id.eq_ignore_ascii_case(target)
                        || node
                            .hostnames
                            .iter()
                            .any(|hostname| hostname.eq_ignore_ascii_case(target))
                        || node
                            .annotation
                            .name
                            .as_deref()
                            .is_some_and(|name| name.eq_ignore_ascii_case(target))
                });
                let site_match = advertised_target.is_some_and(|target| {
                    node.sites
                        .iter()
                        .any(|site| site.eq_ignore_ascii_case(target))
                });
                (address_match || listener_match || identity_match || site_match).then_some((
                    (address_match, listener_match, identity_match, site_match),
                    node_id,
                    node,
                ))
            })
            .max_by_key(|(rank, node_id, _)| (*rank, std::cmp::Reverse((*node_id).clone())))
            .map(|(_, node_id, node)| (node_id, node));
        let node_id = matched_node
            .map(|(node_id, _)| node_id.clone())
            .unwrap_or_else(|| {
                advertisement
                    .target
                    .as_deref()
                    .unwrap_or(&advertisement.instance)
                    .trim_end_matches(".local")
                    .trim_end_matches('.')
                    .to_lowercase()
            });
        let scheme = advertisement_scheme(advertisement, &kind);
        let addresses = if advertisement.addresses.is_empty() {
            matched_node
                .map(|(_, node)| node.ips.keys().copied().collect::<BTreeSet<_>>())
                .unwrap_or_default()
        } else {
            advertisement.addresses.clone()
        };
        let endpoints = addresses
            .iter()
            .map(|address| endpoint(scheme, address.to_string(), port))
            .collect();
        let mut protocols = BTreeSet::from(["tcp".into(), scheme.into()]);
        if kind == "mcp" {
            protocols.insert("json-rpc".into());
        }
        let mut attributes = BTreeMap::from([
            ("node_id".into(), node_id.clone()),
            ("service_name".into(), advertisement.instance.clone()),
            ("service_type".into(), advertisement.service_type.clone()),
        ]);
        if let Some(target) = &advertisement.target {
            attributes.insert("target".into(), target.clone());
        }
        catalog.observations.push(ServiceObservation {
            schema_version: SCHEMA_VERSION,
            service_id: ServiceId(format!("service/{node_id}/{kind}/tcp/{port}")),
            observed_at: advertisement.last_seen,
            expires_at: advertisement.last_seen.saturating_add(
                advertisement
                    .ttl
                    .map(u64::from)
                    .unwrap_or(SERVICE_TTL_SECONDS),
            ),
            provenance: Provenance {
                provider: "mycelium-topology".into(),
                observer: advertisement
                    .origins
                    .iter()
                    .next()
                    .cloned()
                    .unwrap_or_else(|| "unknown".into()),
                source_id: Some(advertisement.key()),
            },
            confidence,
            value: Service {
                kind,
                endpoints,
                protocols,
                formats: BTreeSet::new(),
                attributes,
            },
        });
    }
    catalog.normalize();
    catalog
}

fn recognize_advertisement(advertisement: &ServiceAdvertisement) -> Option<(String, Confidence)> {
    let evidence = format!(
        "{} {} {}",
        advertisement.service_type, advertisement.instance, advertisement.domain
    );
    let service = ServiceRecord {
        name: evidence,
        transport: if advertisement.service_type.contains("._udp") {
            "udp".into()
        } else {
            "tcp".into()
        },
        port: advertisement.port?,
        product: None,
        state: mycelium_core::ServiceState::Up,
        observed_at: advertisement.last_seen,
        origin: mycelium_core::Origin::new("advertisement", "dns-sd"),
    };
    recognize(&service)
}

fn advertisement_scheme<'a>(advertisement: &'a ServiceAdvertisement, kind: &str) -> &'a str {
    advertisement
        .txt
        .iter()
        .find_map(|entry| entry.strip_prefix("scheme="))
        .filter(|scheme| matches!(*scheme, "http" | "https"))
        .unwrap_or(if matches!(kind, "mcp" | "dcp") {
            "http"
        } else {
            "tcp"
        })
}

fn application_scheme<'a>(service: &'a ServiceRecord, kind: &str) -> &'a str {
    if matches!(kind, "mcp" | "dcp")
        && matches!(service.name.to_ascii_lowercase().as_str(), "http" | "https")
    {
        &service.name
    } else {
        &service.transport
    }
}

fn endpoint(transport: &str, host: String, port: u16) -> String {
    let host = if host.contains(':') {
        format!("[{host}]")
    } else {
        host
    };
    format!("{}://{host}:{port}", transport.to_lowercase())
}

fn evidence(service: &ServiceRecord) -> String {
    format!(
        "{} {}",
        service.name.to_lowercase(),
        service
            .product
            .as_deref()
            .unwrap_or_default()
            .to_lowercase()
    )
}

fn recognize(service: &ServiceRecord) -> Option<(String, Confidence)> {
    let evidence = evidence(service);
    let tokens = evidence
        .split(|character: char| !character.is_ascii_alphanumeric())
        .filter(|token| !token.is_empty())
        .collect::<BTreeSet<_>>();
    for (kind, aliases) in [
        ("isochrone", &["isochrone"][..]),
        ("unibus", &["unibus"][..]),
        ("mcp", &["mcp"][..]),
        ("dcp", &["dcp"][..]),
        ("postgresql", &["postgres", "postgresql"][..]),
        ("mysql", &["mysql", "mariadb"][..]),
        ("sql-server", &["mssql", "sqlserver"][..]),
        ("redis", &["redis"][..]),
        ("ipfs", &["ipfs", "kubo"][..]),
    ] {
        if aliases.iter().any(|alias| tokens.contains(alias)) {
            return Some((kind.into(), Confidence::Strong));
        }
    }
    if !service.transport.eq_ignore_ascii_case("tcp") {
        return None;
    }
    if tokens.contains("adb") {
        return Some(("adb".into(), Confidence::Strong));
    }
    // Standard ports are deliberately only derived confidence: another
    // service can use them, and explicit service evidence always wins above.
    match service.port {
        5555 => Some(("adb".into(), Confidence::Derived)),
        5432 => Some(("postgresql".into(), Confidence::Derived)),
        3306 => Some(("mysql".into(), Confidence::Derived)),
        1433 => Some(("sql-server".into(), Confidence::Derived)),
        6379 | 6380 => Some(("redis".into(), Confidence::Derived)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mycelium_core::{IpRecord, Origin, ServiceState, TopoNode};
    use std::net::IpAddr;

    fn service(name: &str, product: Option<&str>, port: u16) -> ServiceRecord {
        ServiceRecord {
            name: name.into(),
            transport: "tcp".into(),
            port,
            product: product.map(str::to_owned),
            state: ServiceState::Up,
            observed_at: 100,
            origin: Origin::new("neo", "fixture").at_site("home"),
        }
    }

    #[test]
    fn recognizes_named_protocols_without_network_io() {
        for (name, product, port, expected) in [
            ("https", Some("MCP server"), 8443, "mcp"),
            ("unibus", None, 4222, "unibus"),
            ("isochrone", Some("H.264"), 9443, "isochrone"),
            ("dcp", None, 9000, "dcp"),
            ("adb", None, 5555, "adb"),
            ("postgres", None, 5433, "postgresql"),
            ("unknown", Some("MariaDB server"), 3307, "mysql"),
            ("redis", None, 6381, "redis"),
            ("ipfs-rpc", Some("IPFS Kubo/0.43.1"), 5002, "ipfs"),
            ("ipfs", None, 4001, "ipfs"),
        ] {
            assert_eq!(
                recognize(&service(name, product, port)).unwrap().0,
                expected
            );
        }
    }

    #[test]
    fn adb_port_is_derived_and_unrelated_ports_are_ignored() {
        let (_, confidence) = recognize(&service("unknown", None, 5555)).unwrap();
        assert_eq!(confidence, Confidence::Derived);
        assert_eq!(
            recognize(&service("unknown", None, 6379)).unwrap(),
            ("redis".into(), Confidence::Derived)
        );
        assert!(recognize(&service("ssh", Some("OpenSSH"), 22)).is_none());
        let mut udp_adb = service("adb", Some("adb"), 5353);
        udp_adb.transport = "udp".into();
        assert!(recognize(&udp_adb).is_none());
    }

    #[test]
    fn ipfs_ports_alone_are_not_evidence() {
        for port in [4001, 4002, 5001, 5002, 8080, 8081] {
            assert!(recognize(&service("unknown", None, port)).is_none());
        }
        assert!(recognize(&service("myipfsbackup", None, 9000)).is_none());
    }

    #[test]
    fn loopback_rpc_is_visible_without_inventing_lan_access() {
        let mut node = TopoNode {
            id: "agora".into(),
            ..TopoNode::default()
        };
        let addr = "192.0.2.10".parse().unwrap();
        node.ips.insert(
            addr,
            IpRecord {
                addr,
                prefix: None,
                vlan: None,
                origins: BTreeSet::new(),
            },
        );
        let mut rpc = service("ipfs-rpc", Some("IPFS Kubo/0.43.1"), 5002);
        rpc.origin.source = "kubo-loopback-version".into();
        node.services.insert("tcp:5002/ipfs-rpc".into(), rpc);
        let mut topology = Topology::default();
        topology.nodes.insert(node.id.clone(), node);
        let catalog = project(&topology);
        let observed = &catalog.observations[0];
        assert_eq!(observed.value.kind, "ipfs");
        assert!(observed.value.endpoints.is_empty());
        assert_eq!(observed.value.attributes["endpoint_scope"], "host-local");
        assert_eq!(observed.value.attributes["version"], "0.43.1");
        assert_eq!(observed.value.attributes["administrative"], "true");
        assert_eq!(observed.expires_at, 100 + SERVICE_TTL_SECONDS);
        assert_eq!(observed.provenance.observer, "neo");
        assert!(observed.value.protocols.contains("http"));
    }

    #[test]
    fn process_hint_does_not_claim_rpc_or_gateway_access() {
        let mut node = TopoNode {
            id: "titan".into(),
            ..TopoNode::default()
        };
        node.services
            .insert("tcp:4001/ipfs".into(), service("ipfs", Some("ipfs"), 4001));
        let mut topology = Topology::default();
        topology.nodes.insert(node.id.clone(), node);
        let catalog = project(&topology);
        let value = &catalog.observations[0].value;
        assert!(value.endpoints.is_empty());
        assert_eq!(value.attributes["endpoint_scope"], "unknown");
        assert!(!value.attributes.contains_key("administrative"));
    }

    #[test]
    fn topology_services_project_to_stable_ipv4_and_ipv6_endpoints() {
        let mut topology = Topology::default();
        let mut node = TopoNode {
            id: "peer-a".into(),
            hostnames: BTreeSet::from(["agora-one".into()]),
            ..TopoNode::default()
        };
        for address in ["192.0.2.10", "2001:db8::10"] {
            let addr = address.parse::<IpAddr>().unwrap();
            node.ips.insert(
                addr,
                IpRecord {
                    addr,
                    prefix: None,
                    vlan: None,
                    origins: BTreeSet::new(),
                },
            );
        }
        node.services.insert(
            "tcp:9443/isochrone".into(),
            service("isochrone", Some("H.264"), 9443),
        );
        topology.nodes.insert(node.id.clone(), node);

        let catalog = project(&topology);
        assert_eq!(catalog.observations.len(), 1);
        let observation = &catalog.observations[0];
        assert_eq!(observation.value.kind, "isochrone");
        assert_eq!(observation.value.attributes["node_label"], "agora-one");
        assert!(observation.value.formats.contains("h264"));
        assert!(observation
            .value
            .endpoints
            .contains("tcp://192.0.2.10:9443"));
        assert!(observation
            .value
            .endpoints
            .contains("tcp://[2001:db8::10]:9443"));
    }

    #[test]
    fn application_protocol_endpoints_do_not_leak_tcp_as_the_url_scheme() {
        let mut topology = Topology::default();
        let mut node = TopoNode {
            id: "peer-a".into(),
            ..TopoNode::default()
        };
        let address = "127.0.0.1".parse::<IpAddr>().unwrap();
        node.ips.insert(
            address,
            IpRecord {
                addr: address,
                prefix: None,
                vlan: None,
                origins: BTreeSet::new(),
            },
        );
        node.services.insert(
            "tcp:8792/http".into(),
            service("http", Some("DCP server"), 8792),
        );
        topology.nodes.insert(node.id.clone(), node);

        let catalog = project(&topology);
        assert_eq!(catalog.observations[0].value.kind, "dcp");
        assert_eq!(
            catalog.observations[0].value.endpoints,
            BTreeSet::from(["http://127.0.0.1:8792".into()])
        );
        assert!(catalog.observations[0].value.protocols.contains("http"));
    }

    #[test]
    fn explicit_dcp_advertisement_promotes_an_existing_listener() {
        let mut topology = Topology::default();
        let address = "192.168.10.74".parse::<IpAddr>().unwrap();
        let mut node = TopoNode {
            id: "linux-home-pi".into(),
            ..TopoNode::default()
        };
        node.ips.insert(
            address,
            IpRecord {
                addr: address,
                prefix: None,
                vlan: None,
                origins: BTreeSet::new(),
            },
        );
        node.services
            .insert("tcp:7893/unknown".into(), service("unknown", None, 7893));
        topology.nodes.insert(node.id.clone(), node);
        topology.advertisements.insert(
            "synesthesia._dcp._tcp.local".into(),
            ServiceAdvertisement {
                instance: "Synesthesia Studio".into(),
                service_type: "_dcp._tcp".into(),
                domain: "local".into(),
                target: Some("home-pi.local".into()),
                addresses: BTreeSet::from([address]),
                port: Some(7893),
                txt: BTreeSet::from(["scheme=http".into(), "path=/.well-known/dcp".into()]),
                interface: Some("eth0".into()),
                ttl: Some(120),
                first_seen: 90,
                last_seen: 100,
                origins: BTreeSet::from(["home-pi:avahi-browse".into()]),
            },
        );

        let catalog = project(&topology);
        assert_eq!(catalog.observations.len(), 1);
        let observation = &catalog.observations[0];
        assert_eq!(observation.value.kind, "dcp");
        assert_eq!(
            observation.service_id.0,
            "service/linux-home-pi/dcp/tcp/7893"
        );
        assert!(observation
            .value
            .endpoints
            .contains("http://192.168.10.74:7893"));
        assert_eq!(observation.expires_at, 220);
    }

    #[test]
    fn advertisement_target_resolves_missing_addresses_from_topology() {
        let mut topology = Topology::default();
        let address = "192.168.10.74".parse::<IpAddr>().unwrap();
        let mut node = TopoNode {
            id: "linux-home-pi".into(),
            hostnames: BTreeSet::from(["home-pi".into()]),
            ..TopoNode::default()
        };
        node.ips.insert(
            address,
            IpRecord {
                addr: address,
                prefix: None,
                vlan: None,
                origins: BTreeSet::new(),
            },
        );
        node.services
            .insert("tcp:7893/unknown".into(), service("unknown", None, 7893));
        topology.nodes.insert(node.id.clone(), node);
        topology.nodes.insert(
            "ip:100.76.214.103".into(),
            TopoNode {
                id: "ip:100.76.214.103".into(),
                hostnames: BTreeSet::from(["home-pi".into()]),
                ips: BTreeMap::from([(
                    "100.76.214.103".parse::<IpAddr>().unwrap(),
                    IpRecord {
                        addr: "100.76.214.103".parse().unwrap(),
                        prefix: None,
                        vlan: None,
                        origins: BTreeSet::new(),
                    },
                )]),
                ..TopoNode::default()
            },
        );
        topology.advertisements.insert(
            "synesthesia-dcp._http._tcp.local".into(),
            ServiceAdvertisement {
                instance: "Synesthesia DCP".into(),
                service_type: "_http._tcp".into(),
                domain: "local".into(),
                target: Some("home-pi.local".into()),
                addresses: BTreeSet::new(),
                port: Some(7893),
                txt: BTreeSet::from(["scheme=http".into()]),
                interface: None,
                ttl: None,
                first_seen: 90,
                last_seen: 100,
                origins: BTreeSet::new(),
            },
        );

        let catalog = project(&topology);
        assert_eq!(
            catalog.observations[0].service_id.0,
            "service/linux-home-pi/dcp/tcp/7893"
        );
        assert!(catalog.observations[0]
            .value
            .endpoints
            .contains("http://192.168.10.74:7893"));
    }
}
