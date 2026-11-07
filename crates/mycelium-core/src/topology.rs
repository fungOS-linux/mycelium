//! Network topology: derived, typed, and mergeable across LANs/WANs.
//!
//! Nothing here is configured by hand (tenet #3). A topology is assembled
//! from `Observation`s reported by drivers — ARP/mroute tables, interface
//! inventories, DHCP pools and leases, VLAN membership config — keyed by
//! the physical LAN segment so devices on different subnets/LANs describe
//! the same hosts into the same node.
//!
//! Identity rules (v0):
//! - a node is keyed by MAC when known (the stable L2 id), else by IP
//!   prefixed `ip:` (anycast/gateway addresses without MAC report).
//! - conflicting metadata never resolves silently; it is recorded as a
//!   `Conflict` and surfaced in the report (fail loud, tenet #12).

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::net::IpAddr;

pub use mycelium_network_types::{LinkDuplex, LinkMedium, MacAddress};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct VlanId(pub u16);

/// How an address was observed, for trust ranking and provenance.
#[derive(Clone, Debug, PartialEq, Eq, Ord, PartialOrd, Serialize, Deserialize)]
pub struct Origin {
    pub device: String,
    pub source: String,
    /// Routing/identity domain. Identical RFC1918 addresses in different
    /// sites are distinct facts, not conflicts.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub site: Option<String>,
}

impl Origin {
    pub fn new(device: impl Into<String>, source: impl Into<String>) -> Self {
        Self {
            device: device.into(),
            source: source.into(),
            site: None,
        }
    }

    pub fn at_site(mut self, site: impl Into<String>) -> Self {
        self.site = Some(site.into());
        self
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct IpRecord {
    pub addr: IpAddr,
    pub prefix: Option<u8>,
    /// VLAN the address was seen on, if known.
    pub vlan: Option<VlanId>,
    pub origins: BTreeSet<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LinkState {
    Up,
    Down,
    Unknown,
}

/// One port on one device — a link endpoint.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PortRef {
    pub device: String,
    pub port: String,
    /// e.g. "eth0" carrying VLAN 35 as `eth0.35`
    pub vif: Option<VlanId>,
}

impl fmt::Display for PortRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.vif {
            Some(v) => write!(f, "{}/{}.{}", self.device, self.port, v.0),
            None => write!(f, "{}/{}", self.device, self.port),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Link {
    pub a: PortRef,
    pub b: Option<PortRef>,
    pub state: LinkState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub medium: Option<LinkMedium>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub speed_mbps: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub duplex: Option<LinkDuplex>,
    pub origins: BTreeSet<String>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SegmentKind {
    #[default]
    Lan,
    Vlan,
    Wan,
    PointToPoint,
}

/// An L2/L3 domain as seen by one or more devices. Segment ids are stable
/// across reports: `<net>` for IPv4 LANs, `vlan:<id>` when reported.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct Segment {
    pub id: String,
    pub kind: SegmentKind,
    pub vlan: Option<VlanId>,
    pub subnet: Option<(IpAddr, u8)>,
    pub gw: Option<IpAddr>,
    pub domain_name: Option<String>,
    pub origins: BTreeSet<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct LeaseRecord {
    pub ip: IpAddr,
    pub mac: MacAddress,
    pub hostname: Option<String>,
    pub pool: Option<String>,
    pub origin: Origin,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServiceState {
    Up,
    Down,
    Unknown,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceRecord {
    pub name: String,
    pub transport: String,
    pub port: u16,
    pub product: Option<String>,
    pub state: ServiceState,
    pub observed_at: u64,
    pub origin: Origin,
}

/// A service advertised through DNS-SD/mDNS. Unlike [`ServiceRecord`], this
/// is a network announcement and may not yet resolve to a known topology node.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceAdvertisement {
    pub instance: String,
    pub service_type: String,
    pub domain: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    #[serde(default)]
    pub addresses: BTreeSet<IpAddr>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    #[serde(default)]
    pub txt: BTreeSet<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interface: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttl: Option<u32>,
    pub first_seen: u64,
    pub last_seen: u64,
    #[serde(default)]
    pub origins: BTreeSet<String>,
}

/// Provider-neutral device facts recognized from an advertisement. This is
/// identity evidence, not an authorization grant or a managed-device handle.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiscoveredDevice {
    pub stable_id: String,
    pub name: String,
    pub kind: String,
    /// Set by the host from the source advertisement, not by recognizer code.
    #[serde(default)]
    pub observed_at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vendor: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub firmware: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub serial: Option<String>,
    #[serde(default)]
    pub addresses: BTreeSet<IpAddr>,
    #[serde(default)]
    pub attributes: BTreeMap<String, String>,
    #[serde(default)]
    pub services: Vec<DiscoveredService>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiscoveredService {
    pub name: String,
    pub transport: String,
    pub port: u16,
}

impl ServiceAdvertisement {
    /// Newer TXT records supersede previous values rather than retaining stale
    /// leases or endpoint hints. Equal-time observations can add evidence;
    /// replayed older snapshots cannot roll current metadata backwards.
    pub fn merge(&mut self, incoming: Self) {
        let newer = incoming.last_seen > self.last_seen;
        let same_time = incoming.last_seen == self.last_seen;
        if newer {
            self.txt = incoming.txt;
        } else if same_time {
            self.txt.extend(incoming.txt);
        }
        if newer || same_time {
            if incoming.target.is_some() {
                self.target = incoming.target;
            }
            if incoming.port.is_some() {
                self.port = incoming.port;
            }
            if incoming.interface.is_some() {
                self.interface = incoming.interface;
            }
            if incoming.ttl.is_some() {
                self.ttl = incoming.ttl;
            }
        }
        self.first_seen = self.first_seen.min(incoming.first_seen);
        self.last_seen = self.last_seen.max(incoming.last_seen);
        self.addresses.extend(incoming.addresses);
        self.origins.extend(incoming.origins);
    }

    pub fn key(&self) -> String {
        format!(
            "{}.{}.{}",
            self.instance.to_lowercase(),
            self.service_type.to_lowercase(),
            self.domain.trim_end_matches('.').to_lowercase()
        )
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeAnnotation {
    pub name: Option<String>,
    pub kind: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MeshProtocol {
    Tailscale,
    WireGuard,
    #[default]
    Unknown,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MeshCoordinator {
    TailscaleCloud,
    Headscale,
    Custom,
    #[default]
    Unknown,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MeshControlPlane {
    pub coordinator: MeshCoordinator,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OverlayPeerRecord {
    pub network: String,
    #[serde(default)]
    pub protocol: MeshProtocol,
    #[serde(default)]
    pub control_plane: MeshControlPlane,
    #[serde(default)]
    pub self_node: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tailnet: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backend_state: Option<String>,
    pub observer: String,
    pub online: bool,
    pub active: bool,
    pub relay: Option<String>,
    pub endpoint: Option<String>,
    pub routed_lans: BTreeSet<String>,
    pub observed_at: u64,
    pub origin: Origin,
}

/// One atomic piece of topology truth from one device.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum Observation {
    /// A signed device identity projected from a peer's self-claimed public
    /// interface facts. Existing discovery nodes are merged only when MAC/IP
    /// evidence is non-conflicting.
    DeviceIdentity {
        device: String,
        hostname: String,
        port: String,
        mac: Option<MacAddress>,
        ips: Vec<IpAddr>,
        origin: Origin,
    },
    /// Reachable host seen in a forwarding table (arp/neighbors).
    Neighbor {
        mac: Option<MacAddress>,
        ip: IpAddr,
        hostname: Option<String>,
        port: Option<PortRef>,
        origin: Origin,
    },
    /// A layer-2 attachment learned without an IP address (for example from
    /// a switch forwarding table or a wireless controller association).
    Attachment {
        mac: MacAddress,
        hostname: Option<String>,
        port: PortRef,
        origin: Origin,
    },
    /// A listening or remotely identified service. MAC is preferred for
    /// identity, then an existing node with `ip`, then `device`.
    Service {
        device: String,
        mac: Option<MacAddress>,
        ip: Option<IpAddr>,
        service: ServiceRecord,
    },
    /// A DNS-SD/mDNS announcement visible from an observer.
    ServiceAdvertisement {
        advertisement: ServiceAdvertisement,
        origin: Origin,
    },
    /// Stable identity and descriptive facts projected by a bounded
    /// recognizer from a raw network advertisement.
    DiscoveredDevice {
        device: DiscoveredDevice,
        origin: Origin,
    },
    OverlayPeer {
        ip: IpAddr,
        hostname: String,
        record: OverlayPeerRecord,
    },
    /// This observer's own attachment to an overlay. Unlike a peer report,
    /// identity is anchored to the known device rather than inferred from an
    /// address or hostname.
    OverlaySelf {
        device: String,
        ips: Vec<IpAddr>,
        hostname: String,
        record: OverlayPeerRecord,
    },
    /// A port of a device, with link state.
    DevicePort {
        device: String,
        port: String,
        mac: Option<MacAddress>,
        ips: Vec<IpAddr>,
        state: LinkState,
        medium: Option<LinkMedium>,
        speed_mbps: Option<u32>,
        duplex: Option<LinkDuplex>,
        origin: Origin,
    },
    /// VLAN membership: device trunk/access port carrying a VLAN.
    VlanMember {
        device: String,
        vlan: VlanId,
        members: Vec<String>,
        origin: Origin,
    },
    /// A DHCP pool / network segment as configured on a device.
    Segment { segment: Segment, origin: Origin },
    /// A configured or active DHCP lease.
    Lease { lease: LeaseRecord, origin: Origin },
}

/// The single overlay network name the mycelium mesh publishes. One address
/// space is shared by the WireGuard fast path and the proxy+iroh fallback.
pub const MYCELIUM_OVERLAY_NETWORK: &str = "mycelium0";

/// A node in the merged graph: one host, or one appliance device.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct TopoNode {
    pub id: String,
    pub mac: Option<MacAddress>,
    pub ips: BTreeMap<IpAddr, IpRecord>,
    pub hostnames: BTreeSet<String>,
    pub device: bool,
    pub ports: BTreeMap<String, Link>,
    pub origins: BTreeSet<String>,
    #[serde(default)]
    pub sites: BTreeSet<String>,
    #[serde(default)]
    pub services: BTreeMap<String, ServiceRecord>,
    #[serde(default)]
    pub annotation: NodeAnnotation,
    /// Descriptive discovery facts. Keys are namespaced by convention and
    /// never confer management or access authority.
    #[serde(default)]
    pub facts: BTreeMap<String, String>,
    #[serde(default)]
    pub overlays: BTreeMap<String, OverlayPeerRecord>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Conflict {
    SameIpDiffMac {
        ip: IpAddr,
        macs: Vec<MacAddress>,
        sources: Vec<String>,
    },
    SameMacDiffSubnet {
        mac: MacAddress,
        subnets: Vec<String>,
        sources: Vec<String>,
    },
    SegmentParamsDiff {
        segment: String,
        field: String,
        values: Vec<String>,
        sources: Vec<String>,
    },
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct TopologyReport {
    pub conflicts: Vec<Conflict>,
    pub new_nodes: usize,
    pub updated_nodes: usize,
    pub merged_segments: usize,
}

/// The merged topology. Build once with `empty()`, then `observe()` over
/// time; serialization is the on-disk cache format.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Topology {
    pub nodes: BTreeMap<String, TopoNode>,
    pub segments: BTreeMap<String, Segment>,
    pub leases: Vec<LeaseRecord>,
    #[serde(default)]
    pub advertisements: BTreeMap<String, ServiceAdvertisement>,
    /// Placement edges projected from resource observations. Typed resource
    /// profiles remain in the resource catalog and are not duplicated here.
    #[serde(default)]
    pub resource_attachments:
        BTreeMap<fpl_resource_observation::ResourceId, fpl_resource_observation::Attachment>,
    pub conflicts: Vec<Conflict>,
    pub updated_from: Vec<Origin>,
}

fn origin_key(o: &Origin) -> String {
    match &o.site {
        Some(site) => format!("{site}/{}:{}", o.device, o.source),
        None => format!("{}:{}", o.device, o.source),
    }
}

fn node_key(mac: Option<MacAddress>, ip: IpAddr, site: Option<&str>) -> String {
    match mac {
        Some(m) => m.to_string(),
        None => match site {
            Some(site) => format!("site:{site}:ip:{ip}"),
            None => format!("ip:{ip}"),
        },
    }
}

impl TopoNode {
    /// Addresses this node holds within a named overlay network, matched by
    /// the origin that recorded them. Overlay addresses are transport-agnostic:
    /// the same address space is served by a WireGuard fast path or a local
    /// proxy over iroh depending on reachability, so callers must not infer a
    /// transport from an address belonging to this set.
    pub fn overlay_ips(&self, network: &str) -> BTreeSet<IpAddr> {
        let keys = self
            .overlays
            .values()
            .filter(|record| record.network == network)
            .map(|record| origin_key(&record.origin))
            .collect::<BTreeSet<_>>();
        if keys.is_empty() {
            return BTreeSet::new();
        }
        self.ips
            .iter()
            .filter(|(_, record)| record.origins.iter().any(|origin| keys.contains(origin)))
            .map(|(ip, _)| *ip)
            .collect()
    }
}

impl Topology {
    pub fn empty() -> Self {
        Self::default()
    }

    /// Merge a separately signed observer snapshot into a read model. Local
    /// state is not mutated by peer snapshots, preventing gossip feedback.
    pub fn merge_snapshot(&mut self, other: Self) {
        for (id, node) in other.nodes {
            match self.nodes.entry(id) {
                std::collections::btree_map::Entry::Vacant(entry) => {
                    entry.insert(node);
                }
                std::collections::btree_map::Entry::Occupied(mut entry) => {
                    merge_node(entry.get_mut(), node);
                }
            }
        }
        for (id, segment) in other.segments {
            match self.segments.entry(id) {
                std::collections::btree_map::Entry::Vacant(entry) => {
                    entry.insert(segment);
                }
                std::collections::btree_map::Entry::Occupied(mut entry) => {
                    let current = entry.get_mut();
                    current.origins.extend(segment.origins);
                    if current.gw.is_none() {
                        current.gw = segment.gw;
                    }
                    if current.subnet.is_none() {
                        current.subnet = segment.subnet;
                    }
                    if current.domain_name.is_none() {
                        current.domain_name = segment.domain_name;
                    }
                    if current.vlan.is_none() {
                        current.vlan = segment.vlan;
                    }
                }
            }
        }
        for lease in other.leases {
            if !self.leases.contains(&lease) {
                self.leases.push(lease);
            }
        }
        for (key, advertisement) in other.advertisements {
            match self.advertisements.entry(key) {
                std::collections::btree_map::Entry::Vacant(entry) => {
                    entry.insert(advertisement);
                }
                std::collections::btree_map::Entry::Occupied(mut entry) => {
                    entry.get_mut().merge(advertisement);
                }
            }
        }
        for (resource_id, attachment) in other.resource_attachments {
            self.resource_attachments.insert(resource_id, attachment);
        }
        for conflict in other.conflicts {
            if !self.conflicts.contains(&conflict) {
                self.conflicts.push(conflict);
            }
        }
        for origin in other.updated_from {
            if !self.updated_from.contains(&origin) {
                self.updated_from.push(origin);
            }
        }
    }

    pub fn observe_all(&mut self, obs: impl IntoIterator<Item = Observation>) -> TopologyReport {
        let mut report = TopologyReport::default();
        for o in obs {
            self.observe_one(o, &mut report);
        }
        for c in std::mem::take(&mut report.conflicts) {
            if !self.conflicts.contains(&c) {
                self.conflicts.push(c.clone());
                report.conflicts.push(c);
            }
        }
        report
    }

    fn observe_one(&mut self, obs: Observation, report: &mut TopologyReport) {
        let obs_origin = observation_origin(&obs);
        match obs {
            Observation::DeviceIdentity {
                device,
                hostname,
                port,
                mac,
                ips,
                origin,
            } => {
                let aliases = self
                    .nodes
                    .iter()
                    .filter(|(id, node)| {
                        id.as_str() != device
                            && !node.device
                            && (mac.is_some_and(|claimed| node.mac == Some(claimed))
                                || node.mac.is_none()
                                    && ips.iter().any(|ip| node.ips.contains_key(ip)))
                    })
                    .map(|(id, _)| id.clone())
                    .collect::<Vec<_>>();
                for alias in aliases {
                    if let Some(source) = self.nodes.remove(&alias) {
                        let target = self.device_node(&device, mac, &origin);
                        merge_node(target, source);
                    }
                }
                let node = self.device_node(&device, mac, &origin);
                let source = origin_key(&origin);
                node.hostnames.insert(hostname.to_lowercase());
                node.origins.insert(source.clone());
                for ip in &ips {
                    node.ips
                        .entry(*ip)
                        .or_insert_with(|| IpRecord {
                            addr: *ip,
                            prefix: None,
                            vlan: None,
                            origins: BTreeSet::new(),
                        })
                        .origins
                        .insert(source.clone());
                }
                node.ports
                    .entry(port.clone())
                    .or_insert_with(|| Link {
                        a: PortRef {
                            device: device.clone(),
                            port,
                            vif: None,
                        },
                        b: None,
                        state: LinkState::Up,
                        medium: None,
                        speed_mbps: None,
                        duplex: None,
                        origins: BTreeSet::new(),
                    })
                    .origins
                    .insert(source);
                let snapshot = node.clone();
                for ip in ips {
                    self.check_ip_mac(&snapshot, ip, mac, &origin, report);
                }
                report.updated_nodes += 1;
            }
            Observation::Neighbor {
                mac,
                ip,
                hostname,
                port,
                origin,
            } => {
                let key = node_key(mac, ip, origin.site.as_deref());
                let node = self.nodes.entry(key.clone()).or_insert_with(|| {
                    report.new_nodes += 1;
                    TopoNode {
                        id: key,
                        mac,
                        ips: BTreeMap::new(),
                        hostnames: BTreeSet::new(),
                        device: false,
                        ports: BTreeMap::new(),
                        origins: BTreeSet::new(),
                        sites: BTreeSet::new(),
                        services: BTreeMap::new(),
                        annotation: NodeAnnotation::default(),
                        facts: BTreeMap::new(),
                        overlays: BTreeMap::new(),
                    }
                });
                if let Some(site) = &origin.site {
                    node.sites.insert(site.clone());
                }
                let k = origin_key(&origin);
                node.origins.insert(k);
                if let Some(h) = hostname.filter(|h| !h.is_empty() && h != "Unknown") {
                    node.hostnames.insert(h.to_lowercase());
                }
                match node.ips.get_mut(&ip) {
                    None => {
                        node.ips.insert(
                            ip,
                            IpRecord {
                                addr: ip,
                                prefix: None,
                                vlan: None,
                                origins: BTreeSet::from_iter([origin_key(&origin)]),
                            },
                        );
                    }
                    Some(rec) => {
                        rec.origins.insert(origin_key(&origin));
                    }
                }
                if let Some(port) = port {
                    let entry = node.ports.entry(port.port.clone()).or_insert_with(|| Link {
                        a: PortRef {
                            device: node.id.clone(),
                            port: port.port.clone(),
                            vif: None,
                        },
                        b: None,
                        state: LinkState::Unknown,
                        medium: None,
                        speed_mbps: None,
                        duplex: None,
                        origins: BTreeSet::new(),
                    });
                    entry.origins.insert(origin_key(&origin));
                    if let Some(v) = port.vif {
                        entry.a.vif = Some(v);
                    }
                }
                report.updated_nodes += 1;
                let snapshot = node.clone();
                self.check_ip_mac(&snapshot, ip, mac, &origin, report);
            }
            Observation::Attachment {
                mac,
                hostname,
                port,
                origin,
            } => {
                let key = mac.to_string();
                let node = self.nodes.entry(key.clone()).or_insert_with(|| {
                    report.new_nodes += 1;
                    TopoNode {
                        id: key,
                        mac: Some(mac),
                        ..TopoNode::default()
                    }
                });
                if let Some(site) = &origin.site {
                    node.sites.insert(site.clone());
                }
                if let Some(hostname) = hostname.filter(|name| !name.is_empty()) {
                    node.hostnames.insert(hostname.to_lowercase());
                }
                let origin = origin_key(&origin);
                node.origins.insert(origin.clone());
                node.ports.insert(
                    format!("{}/{}", port.device, port.port),
                    Link {
                        a: PortRef {
                            device: node.id.clone(),
                            port: "attachment".into(),
                            vif: None,
                        },
                        b: Some(port),
                        state: LinkState::Up,
                        medium: None,
                        speed_mbps: None,
                        duplex: None,
                        origins: BTreeSet::from_iter([origin]),
                    },
                );
                report.updated_nodes += 1;
            }
            Observation::Service {
                device,
                mac,
                ip,
                service,
            } => {
                let key = mac.map(|value| value.to_string()).or_else(|| {
                    ip.and_then(|address| {
                        self.nodes
                            .iter()
                            .find(|(_, node)| node.ips.contains_key(&address))
                            .map(|(id, _)| id.clone())
                    })
                });
                let key = key.unwrap_or_else(|| device.clone());
                let node = self.nodes.entry(key.clone()).or_insert_with(|| TopoNode {
                    id: key,
                    mac,
                    device: mac.is_none() && ip.is_none(),
                    ..TopoNode::default()
                });
                if let Some(address) = ip {
                    node.ips.entry(address).or_insert_with(|| IpRecord {
                        addr: address,
                        prefix: None,
                        vlan: None,
                        origins: BTreeSet::from_iter([origin_key(&service.origin)]),
                    });
                }
                let service_key =
                    format!("{}:{}/{}", service.transport, service.port, service.name);
                node.origins.insert(origin_key(&service.origin));
                node.services.insert(service_key, service);
                report.updated_nodes += 1;
            }
            Observation::ServiceAdvertisement {
                mut advertisement,
                origin,
            } => {
                advertisement.origins.insert(origin_key(&origin));
                let key = advertisement.key();
                match self.advertisements.get_mut(&key) {
                    Some(existing) => {
                        existing.merge(advertisement);
                    }
                    None => {
                        self.advertisements.insert(key, advertisement);
                    }
                }
            }
            Observation::DiscoveredDevice { device, origin } => {
                let aliases = self
                    .nodes
                    .iter()
                    .filter(|(id, node)| {
                        id.as_str() != device.stable_id
                            && !node.device
                            && device
                                .addresses
                                .iter()
                                .any(|address| node.ips.contains_key(address))
                    })
                    .map(|(id, _)| id.clone())
                    .collect::<Vec<_>>();
                for alias in aliases {
                    if let Some(source) = self.nodes.remove(&alias) {
                        let target = self.nodes.entry(device.stable_id.clone()).or_default();
                        target.id = device.stable_id.clone();
                        merge_node(target, source);
                    }
                }
                let node = self
                    .nodes
                    .entry(device.stable_id.clone())
                    .or_insert_with(|| {
                        report.new_nodes += 1;
                        TopoNode {
                            id: device.stable_id.clone(),
                            ..TopoNode::default()
                        }
                    });
                let source = origin_key(&origin);
                node.origins.insert(source.clone());
                if let Some(site) = &origin.site {
                    node.sites.insert(site.clone());
                }
                if !device.name.trim().is_empty() {
                    node.hostnames.insert(device.name.to_lowercase());
                    node.annotation.name = Some(device.name.clone());
                }
                node.annotation.kind = Some(device.kind.clone());
                for (key, value) in device.attributes {
                    node.facts.insert(key, value);
                }
                for (key, value) in [
                    ("vendor", device.vendor),
                    ("model", device.model),
                    ("firmware", device.firmware),
                    ("serial", device.serial),
                ] {
                    if let Some(value) = value {
                        node.facts.insert(key.into(), value);
                    }
                }
                for address in device.addresses {
                    node.ips
                        .entry(address)
                        .or_insert_with(|| IpRecord {
                            addr: address,
                            prefix: None,
                            vlan: None,
                            origins: BTreeSet::new(),
                        })
                        .origins
                        .insert(source.clone());
                }
                for discovered in device.services {
                    let service = ServiceRecord {
                        name: discovered.name,
                        transport: discovered.transport,
                        port: discovered.port,
                        product: None,
                        state: ServiceState::Up,
                        observed_at: device.observed_at,
                        origin: origin.clone(),
                    };
                    node.services.insert(
                        format!("{}:{}/{}", service.transport, service.port, service.name),
                        service,
                    );
                }
                report.updated_nodes += 1;
            }
            Observation::OverlayPeer {
                ip,
                hostname,
                record,
            } => {
                let normalized_hostname = hostname.to_lowercase();
                let key = self
                    .nodes
                    .iter()
                    .find(|(_, node)| node.ips.contains_key(&ip))
                    .or_else(|| {
                        self.nodes
                            .iter()
                            .find(|(_, node)| node.hostnames.contains(&normalized_hostname))
                    })
                    .map(|(id, _)| id.clone())
                    .unwrap_or_else(|| node_key(None, ip, None));
                let node = self.nodes.entry(key.clone()).or_insert_with(|| TopoNode {
                    id: key,
                    ..TopoNode::default()
                });
                node.hostnames.insert(normalized_hostname);
                node.ips.entry(ip).or_insert_with(|| IpRecord {
                    addr: ip,
                    prefix: None,
                    vlan: None,
                    origins: BTreeSet::from_iter([origin_key(&record.origin)]),
                });
                node.origins.insert(origin_key(&record.origin));
                node.overlays
                    .insert(format!("{}/{}", record.network, record.observer), record);
                report.updated_nodes += 1;
            }
            Observation::OverlaySelf {
                device,
                ips,
                hostname,
                record,
            } => {
                let origin = record.origin.clone();
                let aliases = self
                    .nodes
                    .iter()
                    .filter(|(id, node)| {
                        id.as_str() != device
                            && !node.device
                            && node.mac.is_none()
                            && ips.iter().any(|ip| node.ips.contains_key(ip))
                    })
                    .map(|(id, _)| id.clone())
                    .collect::<Vec<_>>();
                for alias in aliases {
                    if let Some(source) = self.nodes.remove(&alias) {
                        let target = self.device_node(&device, None, &origin);
                        merge_node(target, source);
                    }
                }
                let node = self.device_node(&device, None, &origin);
                let origin_key = origin_key(&origin);
                node.hostnames.insert(hostname.to_lowercase());
                node.origins.insert(origin_key.clone());
                for ip in ips {
                    node.ips.entry(ip).or_insert_with(|| IpRecord {
                        addr: ip,
                        prefix: None,
                        vlan: None,
                        origins: BTreeSet::from_iter([origin_key.clone()]),
                    });
                }
                node.overlays
                    .insert(format!("{}/{}", record.network, record.observer), record);
                report.updated_nodes += 1;
            }
            Observation::DevicePort {
                device,
                port,
                mac,
                ips,
                state,
                medium,
                speed_mbps,
                duplex,
                origin,
            } => {
                let node = self.device_node(&device, mac, &origin);
                let k = origin_key(&origin);
                node.origins.insert(k.clone());
                for ip in ips {
                    node.ips
                        .entry(ip)
                        .or_insert_with(|| IpRecord {
                            addr: ip,
                            prefix: None,
                            vlan: None,
                            origins: BTreeSet::new(),
                        })
                        .origins
                        .insert(k.clone());
                }
                let entry = node.ports.entry(port.clone()).or_insert_with(|| Link {
                    a: PortRef {
                        device: device.clone(),
                        port: port.clone(),
                        vif: None,
                    },
                    b: None,
                    state: LinkState::Unknown,
                    medium: None,
                    speed_mbps: None,
                    duplex: None,
                    origins: BTreeSet::new(),
                });
                entry.state = merge_state(entry.state, state);
                if medium.is_some() {
                    entry.medium = medium;
                }
                if speed_mbps.is_some() {
                    entry.speed_mbps = speed_mbps;
                }
                if duplex.is_some() {
                    entry.duplex = duplex;
                }
                entry.origins.insert(k);
                report.updated_nodes += 1;
            }
            Observation::VlanMember {
                device,
                vlan,
                members,
                origin,
            } => {
                let k = origin_key(&origin);
                let id = scoped_id(origin.site.as_deref(), &format!("vlan:{}", vlan.0));
                let seg = self.segments.entry(id.clone()).or_insert_with(|| {
                    report.merged_segments += 1;
                    Segment {
                        id,
                        kind: SegmentKind::Vlan,
                        vlan: Some(vlan),
                        subnet: None,
                        gw: None,
                        domain_name: None,
                        origins: BTreeSet::new(),
                    }
                });
                seg.origins.insert(k.clone());
                // attach membership onto each member device's ports
                for m in members {
                    let dev = self.device_node(&device, None, &origin);
                    dev.origins.insert(k.clone());
                    let _ = m; // v0: membership recorded on the segment only;
                               // port-level member edges are a v1 refinement.
                }
            }
            Observation::Segment { segment, origin } => {
                let k = origin_key(&origin);
                let mut segment = segment;
                segment.id = scoped_id(origin.site.as_deref(), &segment.id);
                if let Some(existing) = self.segments.get(&segment.id) {
                    let existing = existing.clone();
                    if let (Some(old), Some(new)) = (existing.gw, segment.gw) {
                        if old != new {
                            report.conflicts_push(Conflict::SegmentParamsDiff {
                                segment: segment.id.clone(),
                                field: "gateway".into(),
                                values: vec![old.to_string(), new.to_string()],
                                sources: existing
                                    .origins
                                    .iter()
                                    .chain(std::iter::once(&k))
                                    .cloned()
                                    .collect(),
                            });
                        }
                    }
                    if let (Some((a_ip, a_pfx)), Some((b_ip, b_pfx))) =
                        (existing.subnet, segment.subnet)
                    {
                        if a_ip != b_ip || a_pfx != b_pfx {
                            report.conflicts_push(Conflict::SegmentParamsDiff {
                                segment: segment.id.clone(),
                                field: "subnet".into(),
                                values: vec![format!("{a_ip}/{a_pfx}"), format!("{b_ip}/{b_pfx}")],
                                sources: existing
                                    .origins
                                    .iter()
                                    .chain(std::iter::once(&k))
                                    .cloned()
                                    .collect(),
                            });
                        }
                    }
                    if let (Some(a), Some(b)) = (&existing.domain_name, &segment.domain_name) {
                        if a != b {
                            report.conflicts_push(Conflict::SegmentParamsDiff {
                                segment: segment.id.clone(),
                                field: "domain".into(),
                                values: vec![a.clone(), b.clone()],
                                sources: existing
                                    .origins
                                    .iter()
                                    .chain(std::iter::once(&k))
                                    .cloned()
                                    .collect(),
                            });
                        }
                    }
                    let seg = self.segments.get_mut(&segment.id).expect("present");
                    seg.origins.insert(k);
                } else {
                    report.merged_segments += 1;
                    let mut segment = segment;
                    segment.origins.insert(k);
                    self.segments.insert(segment.id.clone(), segment);
                }
            }
            Observation::Lease { lease, origin } => {
                if !self.leases.iter().any(|l| {
                    l.ip == lease.ip
                        && l.mac == lease.mac
                        && l.pool == lease.pool
                        && l.origin.device == lease.origin.device
                }) {
                    let mut lease = lease;
                    lease.origin = origin;
                    self.leases.push(lease);
                }
            }
        }
        self.updated_from.push(obs_origin);
    }

    fn device_node(
        &mut self,
        device: &str,
        mac: Option<MacAddress>,
        _origin: &Origin,
    ) -> &mut TopoNode {
        let node = self
            .nodes
            .entry(device.to_owned())
            .or_insert_with(|| TopoNode {
                id: device.to_owned(),
                mac,
                ips: BTreeMap::new(),
                hostnames: BTreeSet::new(),
                device: true,
                ports: BTreeMap::new(),
                origins: BTreeSet::new(),
                sites: BTreeSet::new(),
                services: BTreeMap::new(),
                annotation: NodeAnnotation::default(),
                facts: BTreeMap::new(),
                overlays: BTreeMap::new(),
            });
        node.device = true;
        if let Some(mac) = mac {
            node.mac = Some(mac);
        }
        if let Some(site) = &_origin.site {
            node.sites.insert(site.clone());
        }
        node
    }

    fn check_ip_mac(
        &self,
        node: &TopoNode,
        ip: IpAddr,
        mac: Option<MacAddress>,
        origin: &Origin,
        report: &mut TopologyReport,
    ) {
        if let Some(new_mac) = mac {
            // same ip claimed by a different mac elsewhere?
            for (other_id, other) in &self.nodes {
                if other_id == &node.id {
                    continue;
                }
                // A device node may contain addresses from several interfaces while
                // `mac` is only its representative identity. It is therefore not an
                // authoritative IP-to-MAC binding. Neighbor observations and signed
                // device identities are checked independently when they arrive.
                if other.device {
                    continue;
                }
                if let Some(site) = &origin.site {
                    if !other.sites.contains(site) {
                        continue;
                    }
                }
                if other.mac.is_some_and(|m| m != new_mac) && other.ips.contains_key(&ip) {
                    report.conflicts_push(Conflict::SameIpDiffMac {
                        ip,
                        macs: vec![other.mac.unwrap(), new_mac],
                        sources: other
                            .origins
                            .iter()
                            .cloned()
                            .chain(std::iter::once(origin_key(origin)))
                            .collect(),
                    });
                }
            }
        }
    }
}

fn observation_origin(o: &Observation) -> Origin {
    match o {
        Observation::DeviceIdentity { origin, .. }
        | Observation::Neighbor { origin, .. }
        | Observation::Attachment { origin, .. }
        | Observation::DevicePort { origin, .. }
        | Observation::VlanMember { origin, .. }
        | Observation::Segment { origin, .. }
        | Observation::Lease { origin, .. } => origin.clone(),
        Observation::Service { service, .. } => service.origin.clone(),
        Observation::ServiceAdvertisement { origin, .. } => origin.clone(),
        Observation::DiscoveredDevice { origin, .. } => origin.clone(),
        Observation::OverlayPeer { record, .. } | Observation::OverlaySelf { record, .. } => {
            record.origin.clone()
        }
    }
}

fn merge_state(cur: LinkState, new: LinkState) -> LinkState {
    match (cur, new) {
        (LinkState::Unknown, s) | (s, LinkState::Unknown) => s,
        (LinkState::Down, LinkState::Up) | (LinkState::Up, LinkState::Down) => {
            // both are trusted reports; keep Up (freshest evidence wins once
            // timestamps are wired; v0 conservative = up)
            LinkState::Up
        }
        (s, _) => s,
    }
}

fn merge_node(target: &mut TopoNode, source: TopoNode) {
    if target.mac.is_none() {
        target.mac = source.mac;
    }
    target.hostnames.extend(source.hostnames);
    target.origins.extend(source.origins);
    target.sites.extend(source.sites);
    for (ip, record) in source.ips {
        match target.ips.entry(ip) {
            std::collections::btree_map::Entry::Vacant(entry) => {
                entry.insert(record);
            }
            std::collections::btree_map::Entry::Occupied(mut entry) => {
                entry.get_mut().origins.extend(record.origins);
            }
        }
    }
    for (key, link) in source.ports {
        target.ports.entry(key).or_insert(link);
    }
    for (key, service) in source.services {
        target.services.entry(key).or_insert(service);
    }
    for (key, overlay) in source.overlays {
        target.overlays.entry(key).or_insert(overlay);
    }
    if target.annotation.name.is_none() {
        target.annotation.name = source.annotation.name;
    }
    if target.annotation.kind.is_none() {
        target.annotation.kind = source.annotation.kind;
    }
    target.facts.extend(source.facts);
}

fn scoped_id(site: Option<&str>, id: &str) -> String {
    match site {
        Some(site) => format!("{site}/{id}"),
        None => id.to_owned(),
    }
}

impl TopologyReport {
    fn conflicts_push(&mut self, c: Conflict) {
        if !self.conflicts.contains(&c) {
            self.conflicts.push(c);
        }
    }
}

/// IPv4 CIDR utilities (v0 keeps IPv6 /n semantics to the segment record).
pub fn ipv4_in_cidr(ip: IpAddr, network: IpAddr, prefix: u8) -> bool {
    let (IpAddr::V4(ip), IpAddr::V4(net)) = (ip, network) else {
        return false;
    };
    if prefix > 32 {
        return false;
    }
    let mask: u32 = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    u32::from(ip) & mask == u32::from(net) & mask
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn mac_parse_and_display() {
        let m = MacAddress::parse("aa:bb:cc:dd:ee:ff").unwrap();
        assert_eq!(m.to_string(), "aa:bb:cc:dd:ee:ff");
        assert!(MacAddress::parse("aa:bb:cc").is_none());
    }

    #[test]
    fn cidr_membership() {
        assert!(ipv4_in_cidr(ip("10.0.5.7"), ip("10.0.5.0"), 24));
        assert!(!ipv4_in_cidr(ip("10.0.6.7"), ip("10.0.5.0"), 24));
        assert!(ipv4_in_cidr(ip("10.0.5.7"), ip("10.0.0.0"), 8));
    }

    #[test]
    fn same_mac_from_two_devices_merges_into_one_node() {
        let mut topo = Topology::empty();
        topo.observe_all([
            Observation::Neighbor {
                mac: MacAddress::parse("aa:bb:cc:dd:ee:01"),
                ip: ip("10.0.7.20"),
                hostname: Some("nas".into()),
                port: None,
                origin: Origin::new("er-1", "arp"),
            },
            Observation::Neighbor {
                mac: MacAddress::parse("aa:bb:cc:dd:ee:01"),
                ip: ip("10.0.7.20"),
                hostname: None,
                port: Some(PortRef {
                    device: "sw-1".into(),
                    port: "eth2".into(),
                    vif: None,
                }),
                origin: Origin::new("sw-1", "arp"),
            },
        ]);
        assert_eq!(topo.nodes.len(), 1);
        let nas = &topo.nodes["aa:bb:cc:dd:ee:01"];
        assert_eq!(nas.origins.len(), 2);
        assert!(nas.hostnames.contains("nas"));
    }

    #[test]
    fn peer_snapshots_merge_distinct_vantage_points() {
        let mut laptop = Topology::empty();
        laptop.observe_all([Observation::Neighbor {
            mac: MacAddress::parse("02:00:00:00:00:10"),
            ip: "192.168.10.10".parse().unwrap(),
            hostname: Some("laptop-visible".into()),
            port: None,
            origin: Origin::new("laptop", "arp").at_site("wagar-house"),
        }]);
        let mut pi = Topology::empty();
        pi.observe_all([Observation::Neighbor {
            mac: MacAddress::parse("02:00:00:00:00:20"),
            ip: "192.168.10.20".parse().unwrap(),
            hostname: Some("pi-visible".into()),
            port: None,
            origin: Origin::new("home-pi", "arp").at_site("wagar-house"),
        }]);

        pi.merge_snapshot(laptop);

        assert_eq!(pi.nodes.len(), 2);
        assert!(pi
            .nodes
            .values()
            .any(|node| node.hostnames.contains("laptop-visible")));
        assert!(pi
            .nodes
            .values()
            .any(|node| node.hostnames.contains("pi-visible")));
    }

    #[test]
    fn ip_without_mac_keys_by_ip() {
        let mut topo = Topology::empty();
        topo.observe_all([Observation::Neighbor {
            mac: None,
            ip: ip("8.8.8.8"),
            hostname: None,
            port: None,
            origin: Origin::new("er-1", "arp"),
        }]);
        assert!(topo.nodes.contains_key("ip:8.8.8.8"));
    }

    #[test]
    fn segment_conflict_is_recorded_not_swallowed() {
        let mut topo = Topology::empty();
        let seg = |id: &str, gw: &str, dev: &str| Observation::Segment {
            segment: Segment {
                id: id.into(),
                kind: SegmentKind::Lan,
                vlan: None,
                subnet: Some((ip("10.0.7.0"), 24)),
                gw: Some(ip(gw)),
                domain_name: None,
                origins: BTreeSet::new(),
            },
            origin: Origin::new(dev, "dhcp-config"),
        };
        topo.observe_all([
            seg("10.0.7.0/24", "10.0.7.1", "er-1"),
            seg("10.0.7.0/24", "10.0.7.9", "er-2"),
        ]);
        assert!(matches!(
            topo.conflicts.as_slice(),
            [Conflict::SegmentParamsDiff { field, .. }] if field == "gateway"
        ));
    }

    #[test]
    fn overlapping_sites_do_not_collide() {
        let mut topo = Topology::empty();
        let neighbor = |site: &str, mac: &str| Observation::Neighbor {
            mac: MacAddress::parse(mac),
            ip: ip("192.168.1.1"),
            hostname: None,
            port: None,
            origin: Origin::new(site, "ip-neigh").at_site(site),
        };
        topo.observe_all([
            neighbor("pris", "02:00:00:00:00:01"),
            neighbor("titan", "02:00:00:00:00:02"),
        ]);
        assert!(topo.conflicts.is_empty());

        topo.observe_all([Observation::Neighbor {
            mac: MacAddress::parse("02:00:00:00:00:03"),
            ip: ip("192.168.1.1"),
            hostname: None,
            port: None,
            origin: Origin::new("pris-second", "ip-neigh").at_site("pris"),
        }]);
        assert!(matches!(
            topo.conflicts.as_slice(),
            [Conflict::SameIpDiffMac { .. }]
        ));
    }

    #[test]
    fn neighbor_does_not_conflict_with_multi_interface_device_summary() {
        let mut topology = Topology::empty();
        topology.observe_all([Observation::DevicePort {
            device: "darwin-studio".into(),
            port: "en0".into(),
            mac: MacAddress::parse("9c:76:0e:42:a8:6b"),
            ips: vec![ip("192.168.10.84"), ip("192.168.2.3")],
            state: LinkState::Up,
            medium: Some(LinkMedium::Ethernet),
            speed_mbps: Some(1000),
            duplex: Some(LinkDuplex::Full),
            origin: Origin::new("darwin-studio", "ifconfig").at_site("wagar-house"),
        }]);
        topology.observe_all([Observation::Neighbor {
            mac: MacAddress::parse("32:10:ce:6c:1c:c8"),
            ip: ip("192.168.10.84"),
            hostname: Some("studio".into()),
            port: None,
            origin: Origin::new("darwin-studio", "arp").at_site("wagar-house"),
        }]);

        assert!(topology.conflicts.is_empty());
    }

    #[test]
    fn duplicate_leases_deduped() {
        let mut topo = Topology::empty();
        let lease = Observation::Lease {
            lease: LeaseRecord {
                ip: ip("10.0.7.50"),
                mac: MacAddress::parse("02:00:00:00:00:05").unwrap(),
                hostname: Some("lamp".into()),
                pool: Some("LAN".into()),
                origin: Origin::new("er-1", "dhcp-config"),
            },
            origin: Origin::new("er-1", "dhcp-config"),
        };
        topo.observe_all([lease.clone(), lease]);
        assert_eq!(topo.leases.len(), 1);
    }

    #[test]
    fn mac_only_attachment_preserves_parent_port() {
        let mut topo = Topology::empty();
        topo.observe_all([Observation::Attachment {
            mac: MacAddress::parse("02:00:00:00:00:05").unwrap(),
            hostname: Some("camera".into()),
            port: PortRef {
                device: "switch-1".into(),
                port: "g25".into(),
                vif: None,
            },
            origin: Origin::new("switch-1", "bridge-fdb"),
        }]);
        let node = &topo.nodes["02:00:00:00:00:05"];
        assert!(node.hostnames.contains("camera"));
        assert_eq!(node.ports["switch-1/g25"].b.as_ref().unwrap().port, "g25");
    }

    #[test]
    fn service_merges_into_node_by_ip() {
        let mut topo = Topology::empty();
        topo.observe_all([Observation::Neighbor {
            mac: MacAddress::parse("02:00:00:00:00:05"),
            ip: ip("10.0.7.20"),
            hostname: Some("nvr".into()),
            port: None,
            origin: Origin::new("router", "arp"),
        }]);
        topo.observe_all([Observation::Service {
            device: "observer".into(),
            mac: None,
            ip: Some(ip("10.0.7.20")),
            service: ServiceRecord {
                name: "frigate".into(),
                transport: "tcp".into(),
                port: 8971,
                product: Some("Frigate".into()),
                state: ServiceState::Up,
                observed_at: 1,
                origin: Origin::new("observer", "probe"),
            },
        }]);
        assert_eq!(topo.nodes.len(), 1);
        assert_eq!(topo.nodes["02:00:00:00:00:05"].services.len(), 1);
    }

    #[test]
    fn service_advertisements_merge_resolution_and_provenance() {
        let advertisement = |time, address: Option<&str>| ServiceAdvertisement {
            instance: "Office Printer".into(),
            service_type: "_ipp._tcp".into(),
            domain: "local".into(),
            target: address.map(|_| "printer.local".into()),
            addresses: address.into_iter().map(ip).collect(),
            port: address.map(|_| 631),
            txt: BTreeSet::new(),
            interface: None,
            ttl: None,
            first_seen: time,
            last_seen: time,
            origins: BTreeSet::new(),
        };
        let mut topology = Topology::empty();
        topology.observe_all([
            Observation::ServiceAdvertisement {
                advertisement: advertisement(10, None),
                origin: Origin::new("darwin-deckard", "dns-sd"),
            },
            Observation::ServiceAdvertisement {
                advertisement: advertisement(20, Some("192.168.1.20")),
                origin: Origin::new("linux-pris", "avahi-browse"),
            },
        ]);

        assert_eq!(topology.advertisements.len(), 1);
        let merged = topology.advertisements.values().next().unwrap();
        assert_eq!(merged.first_seen, 10);
        assert_eq!(merged.last_seen, 20);
        assert_eq!(merged.port, Some(631));
        assert_eq!(merged.origins.len(), 2);
    }

    #[test]
    fn overlay_ipv4_and_ipv6_merge_by_hostname() {
        let mut topology = Topology::empty();
        let peer = |address: &str| Observation::OverlayPeer {
            ip: ip(address),
            hostname: "agora-one".into(),
            record: OverlayPeerRecord {
                network: "tailscale".into(),
                protocol: MeshProtocol::Tailscale,
                control_plane: MeshControlPlane {
                    coordinator: MeshCoordinator::TailscaleCloud,
                    url: Some("https://controlplane.tailscale.com".into()),
                },
                self_node: false,
                tailnet: None,
                dns_name: None,
                backend_state: None,
                observer: "linux-titan".into(),
                online: true,
                active: false,
                relay: Some("sea".into()),
                endpoint: None,
                routed_lans: BTreeSet::new(),
                observed_at: 1,
                origin: Origin::new("linux-titan", "tailscale-status"),
            },
        };
        topology.observe_all([peer("100.80.85.86"), peer("fd7a:115c:a1e0::901:55d1")]);
        assert_eq!(topology.nodes.len(), 1);
        assert_eq!(topology.nodes.values().next().unwrap().ips.len(), 2);
    }

    #[test]
    fn overlay_self_attaches_addresses_to_the_observing_device() {
        let mut topology = Topology::empty();
        topology.observe_all([Observation::DevicePort {
            device: "linux-pris".into(),
            port: "enp1s0".into(),
            mac: None,
            ips: vec![ip("192.168.1.9")],
            state: LinkState::Up,
            medium: Some(LinkMedium::Ethernet),
            speed_mbps: Some(1_000),
            duplex: Some(LinkDuplex::Full),
            origin: Origin::new("linux-pris", "interfaces"),
        }]);
        topology.observe_all([Observation::OverlayPeer {
            ip: ip("100.74.130.83"),
            hostname: "pris".into(),
            record: OverlayPeerRecord {
                network: "tailscale".into(),
                protocol: MeshProtocol::Tailscale,
                control_plane: MeshControlPlane {
                    coordinator: MeshCoordinator::TailscaleCloud,
                    url: Some("https://controlplane.tailscale.com".into()),
                },
                self_node: false,
                tailnet: Some("fpl".into()),
                dns_name: Some("pris.example.ts.net.".into()),
                backend_state: Some("Running".into()),
                observer: "linux-titan".into(),
                online: true,
                active: false,
                relay: Some("sea".into()),
                endpoint: None,
                routed_lans: BTreeSet::new(),
                observed_at: 1,
                origin: Origin::new("linux-titan", "tailscale-status"),
            },
        }]);
        assert_eq!(topology.nodes.len(), 2);
        topology.observe_all([Observation::OverlaySelf {
            device: "linux-pris".into(),
            ips: vec![ip("100.74.130.83"), ip("fd7a:115c:a1e0::f034:8254")],
            hostname: "pris".into(),
            record: OverlayPeerRecord {
                network: "tailscale".into(),
                protocol: MeshProtocol::Tailscale,
                control_plane: MeshControlPlane {
                    coordinator: MeshCoordinator::TailscaleCloud,
                    url: Some("https://controlplane.tailscale.com".into()),
                },
                self_node: true,
                tailnet: Some("fpl".into()),
                dns_name: Some("pris.example.ts.net.".into()),
                backend_state: Some("Running".into()),
                observer: "linux-pris".into(),
                online: true,
                active: false,
                relay: None,
                endpoint: None,
                routed_lans: BTreeSet::new(),
                observed_at: 1,
                origin: Origin::new("linux-pris", "tailscale-status"),
            },
        }]);

        let node = &topology.nodes["linux-pris"];
        assert_eq!(topology.nodes.len(), 1);
        assert_eq!(node.ips.len(), 3);
        assert!(node.hostnames.contains("pris"));
        assert!(node.overlays["tailscale/linux-pris"].self_node);
        assert!(node.overlays.contains_key("tailscale/linux-titan"));
    }

    #[test]
    fn serde_round_trips() {
        let mut topo = Topology::empty();
        topo.observe_all([Observation::DevicePort {
            device: "er-1".into(),
            port: "eth0".into(),
            mac: MacAddress::parse("00:11:22:33:44:55"),
            ips: vec![Ipv4Addr::new(10, 0, 7, 1).into()],
            state: LinkState::Up,
            medium: Some(LinkMedium::Ethernet),
            speed_mbps: Some(1000),
            duplex: Some(LinkDuplex::Full),
            origin: Origin::new("er-1", "interfaces"),
        }]);
        let json = serde_json::to_string(&topo).unwrap();
        let back: Topology = serde_json::from_str(&json).unwrap();
        assert_eq!(topo, back);
    }

    #[test]
    fn signed_device_identity_merges_matching_discovery_node() {
        let mut topology = Topology::empty();
        topology.observe_all([Observation::Neighbor {
            mac: MacAddress::parse("02:00:00:00:00:42"),
            ip: ip("192.168.10.42"),
            hostname: None,
            port: None,
            origin: Origin::new("gateway", "arp").at_site("home"),
        }]);
        topology.observe_all([Observation::DeviceIdentity {
            device: "peer-key-42".into(),
            hostname: "radioman-pi".into(),
            port: "eth0".into(),
            mac: MacAddress::parse("02:00:00:00:00:42"),
            ips: vec![ip("192.168.10.42")],
            origin: Origin::new("radioman-pi", "peer-identity").at_site("home"),
        }]);
        assert_eq!(topology.nodes.len(), 1);
        let node = &topology.nodes["peer-key-42"];
        assert!(node.hostnames.contains("radioman-pi"));
        assert!(node.ips.contains_key(&ip("192.168.10.42")));
    }

    #[test]
    fn conflicting_device_identity_does_not_consume_other_mac() {
        let mut topology = Topology::empty();
        topology.observe_all([Observation::Neighbor {
            mac: MacAddress::parse("02:00:00:00:00:41"),
            ip: ip("192.168.10.42"),
            hostname: None,
            port: None,
            origin: Origin::new("gateway", "arp").at_site("home"),
        }]);
        topology.observe_all([Observation::DeviceIdentity {
            device: "peer-key-42".into(),
            hostname: "radioman-pi".into(),
            port: "eth0".into(),
            mac: MacAddress::parse("02:00:00:00:00:42"),
            ips: vec![ip("192.168.10.42")],
            origin: Origin::new("radioman-pi", "peer-identity").at_site("home"),
        }]);
        assert_eq!(topology.nodes.len(), 2);
        assert!(topology
            .conflicts
            .iter()
            .any(|conflict| matches!(conflict, Conflict::SameIpDiffMac { .. })));
    }

    #[test]
    fn discovered_serial_identity_survives_address_movement() {
        let observed = |address: &str| Observation::DiscoveredDevice {
            device: DiscoveredDevice {
                stable_id: "bambu:SERIAL1".into(),
                name: "Printer".into(),
                kind: "printer.3d".into(),
                vendor: Some("Bambu Lab".into()),
                model: Some("N7".into()),
                firmware: Some("1.0".into()),
                serial: Some("SERIAL1".into()),
                observed_at: 42,
                addresses: BTreeSet::from([ip(address)]),
                attributes: BTreeMap::new(),
                services: vec![DiscoveredService {
                    name: "bambu-mqtt-tls".into(),
                    transport: "tcp".into(),
                    port: 8883,
                }],
            },
            origin: Origin::new("spark", "bambu-lan").at_site("lab"),
        };
        let mut topology = Topology::empty();
        topology.observe_all([observed("10.0.0.3")]);
        topology.observe_all([observed("10.0.0.33")]);

        assert_eq!(topology.nodes.len(), 1);
        let node = &topology.nodes["bambu:SERIAL1"];
        assert_eq!(node.annotation.kind.as_deref(), Some("printer.3d"));
        assert_eq!(
            node.facts.get("serial").map(String::as_str),
            Some("SERIAL1")
        );
        assert!(node.ips.contains_key(&ip("10.0.0.3")));
        assert!(node.ips.contains_key(&ip("10.0.0.33")));
        assert!(node.services.contains_key("tcp:8883/bambu-mqtt-tls"));
    }
}
