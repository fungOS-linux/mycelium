use std::collections::{BTreeMap, BTreeSet};

use fpl_resource_observation::{
    Confidence, Provenance, Service, ServiceCatalog, ServiceId, ServiceObservation, SCHEMA_VERSION,
};
use mycelium_core::{ServiceRecord, Topology};

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
            let Some(recognized) = recognize(service) else {
                continue;
            };
            let kind = recognized.kind;
            // A listener observation identifies software, not its routability.
            // A loopback bind says the service is reachable from this host only,
            // so publishing a node address would advertise a route peers cannot
            // use. The loopback URL is truthful: this host's gateway accepts it,
            // and every other gateway drops a remote loopback hint.
            let endpoints = if kind == "ipfs" {
                BTreeSet::new()
            } else if service.host_local {
                BTreeSet::from([endpoint("http", "127.0.0.1".into(), service.port)])
            } else {
                node.ips
                    .keys()
                    .map(|ip| {
                        endpoint(
                            if recognized.http {
                                "http"
                            } else {
                                &service.transport
                            },
                            ip.to_string(),
                            service.port,
                        )
                    })
                    .collect()
            };
            let mut protocols = BTreeSet::from([service.transport.to_lowercase()]);
            if kind == "mcp" {
                protocols.insert("json-rpc".into());
            }
            if recognized.http {
                protocols.insert("http".into());
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
            if service.host_local {
                attributes.insert("endpoint_scope".into(), "host-local".into());
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
                confidence: recognized.confidence,
                value: Service {
                    kind: kind.to_owned(),
                    endpoints,
                    protocols,
                    formats,
                    attributes,
                },
            });
        }
    }
    catalog.normalize();
    catalog
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

/// What a listener's evidence supports claiming about it.
struct Recognized {
    kind: &'static str,
    confidence: Confidence,
    /// The kind's contract is an OpenAI-compatible HTTP surface, so the
    /// projected endpoint is an HTTP origin rather than a bare `tcp` port. Only
    /// a kind may make that claim; a scan alone proves nothing about protocol.
    http: bool,
}

impl Recognized {
    fn strong(kind: &'static str, http: bool) -> Self {
        Self {
            kind,
            confidence: Confidence::Strong,
            http,
        }
    }
}

fn recognize(service: &ServiceRecord) -> Option<Recognized> {
    let evidence = evidence(service);
    let tokens = evidence
        .split(|character: char| !character.is_ascii_alphanumeric())
        .filter(|token| !token.is_empty())
        .collect::<BTreeSet<_>>();
    // Inference servers name themselves in the process or product string. The
    // gateway routes `ai.myc` to whatever advertises this kind, so recognizing
    // them here is what makes a UMIE or llama.cpp node reachable without an
    // application-owner lease.
    for (kind, http, aliases) in [(
        "ai",
        true,
        &[
            "umie", "llama", "llamacpp", "ollama", "vllm", "sglang", "tgi", "bifrost",
        ][..],
    )] {
        if aliases.iter().any(|alias| tokens.contains(alias))
            // "LM Studio" splits into two ordinary words, so the pair is the
            // evidence rather than either word alone.
            || (tokens.contains("lm") && tokens.contains("studio"))
        {
            return Some(Recognized::strong(kind, http));
        }
    }
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
            return Some(Recognized::strong(kind, false));
        }
    }
    if !service.transport.eq_ignore_ascii_case("tcp") {
        return None;
    }
    if tokens.contains("adb") {
        return Some(Recognized::strong("adb", false));
    }
    // Standard ports are deliberately only derived confidence: another
    // service can use them, and explicit service evidence always wins above.
    let (kind, http) = match service.port {
        5555 => ("adb", false),
        5432 => ("postgresql", false),
        3306 => ("mysql", false),
        1433 => ("sql-server", false),
        6379 | 6380 => ("redis", false),
        // Ollama's default port is specific enough to be useful evidence.
        11434 => ("ai", true),
        _ => return None,
    };
    Some(Recognized {
        kind,
        confidence: Confidence::Derived,
        http,
    })
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
            host_local: false,
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
                recognize(&service(name, product, port)).unwrap().kind,
                expected
            );
        }
    }

    #[test]
    fn adb_port_is_derived_and_unrelated_ports_are_ignored() {
        let recognized = recognize(&service("unknown", None, 5555)).unwrap();
        assert_eq!(recognized.confidence, Confidence::Derived);
        assert_eq!(
            recognize(&service("unknown", None, 6379)).unwrap().kind,
            "redis"
        );
        assert!(recognize(&service("ssh", Some("OpenSSH"), 22)).is_none());
        let mut udp_adb = service("adb", Some("adb"), 5353);
        udp_adb.transport = "udp".into();
        assert!(recognize(&udp_adb).is_none());
    }

    #[test]
    fn inference_servers_are_recognized_as_ai_endpoints() {
        for (name, product, port) in [
            ("umie-serve", None, 8122),
            ("llama-server", Some("llama.cpp"), 8094),
            ("python", Some("vLLM engine"), 8000),
            ("unknown", Some("LM Studio"), 1234),
            ("bifrost", None, 4000),
            ("unknown", Some("ollama"), 11500),
        ] {
            let recognized = recognize(&service(name, product, port)).unwrap();
            assert_eq!(recognized.kind, "ai", "{name} {product:?}");
            assert!(
                recognized.http,
                "{name} {product:?} must project an HTTP origin"
            );
            assert_eq!(recognized.confidence, Confidence::Strong);
        }
        // The default Ollama port is useful but weaker evidence.
        let derived = recognize(&service("unknown", None, 11434)).unwrap();
        assert_eq!(derived.kind, "ai");
        assert_eq!(derived.confidence, Confidence::Derived);
    }

    #[test]
    fn a_loopback_inference_server_is_published_for_this_host_only() {
        let mut node = TopoNode {
            id: "agora".into(),
            ..TopoNode::default()
        };
        let addr = "192.0.2.10".parse::<IpAddr>().unwrap();
        node.ips.insert(
            addr,
            IpRecord {
                addr,
                prefix: None,
                vlan: None,
                origins: BTreeSet::new(),
            },
        );
        let mut umie = service("umie-serve", None, 8122);
        umie.host_local = true;
        node.services.insert("tcp:8122/umie-serve".into(), umie);
        let mut topology = Topology::default();
        topology.nodes.insert(node.id.clone(), node);

        let catalog = project(&topology);
        let value = &catalog.observations[0].value;
        assert_eq!(value.kind, "ai");
        assert_eq!(
            value.endpoints,
            BTreeSet::from(["http://127.0.0.1:8122".into()])
        );
        assert_eq!(value.attributes["endpoint_scope"], "host-local");
        assert!(value.protocols.contains("http"));
    }

    #[test]
    fn a_mesh_bound_inference_server_is_reachable_by_peers() {
        let mut node = TopoNode {
            id: "titan".into(),
            ..TopoNode::default()
        };
        let addr = "192.0.2.20".parse::<IpAddr>().unwrap();
        node.ips.insert(
            addr,
            IpRecord {
                addr,
                prefix: None,
                vlan: None,
                origins: BTreeSet::new(),
            },
        );
        node.services.insert(
            "tcp:8122/umie-serve".into(),
            service("umie-serve", None, 8122),
        );
        let mut topology = Topology::default();
        topology.nodes.insert(node.id.clone(), node);

        let catalog = project(&topology);
        let value = &catalog.observations[0].value;
        assert_eq!(
            value.endpoints,
            BTreeSet::from(["http://192.0.2.20:8122".into()])
        );
        assert!(!value.attributes.contains_key("endpoint_scope"));
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
}
