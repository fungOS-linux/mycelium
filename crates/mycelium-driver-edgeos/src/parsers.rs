//! Pure parsers for EdgeOS (vyos) CLI text. Kept side-effect free so the
//! driver's behavior is testable without hardware (tenet #6).

use std::collections::BTreeMap;
use std::net::IpAddr;

use mycelium_core::MacAddress;

#[derive(Clone, Debug, PartialEq, serde::Serialize)]
pub struct VersionInfo {
    pub vendor: Option<String>,
    pub model: Option<String>,
    pub firmware: Option<String>,
}

pub fn parse_show_version(text: &str) -> VersionInfo {
    let mut info = VersionInfo {
        vendor: None,
        model: None,
        firmware: None,
    };
    for line in text.lines() {
        let line = line.trim();
        if let Some(v) = line.strip_prefix("Version:") {
            info.firmware = Some(v.trim().to_owned());
        } else if let Some(v) = line.strip_prefix("HW model:") {
            info.model = Some(v.trim().to_owned());
        } else if let Some(v) = line.strip_prefix("Board:") {
            if info.model.is_none() {
                info.model = Some(v.trim().to_owned());
            }
        } else if line.contains("Ubiquiti") && info.vendor.is_none() {
            info.vendor = Some("Ubiquiti".into());
        }
    }
    info
}

pub fn parse_host_name(text: &str) -> Option<String> {
    for line in text.lines() {
        if let Some(v) = line.trim().strip_prefix("Host name:") {
            let v = v.trim();
            if !v.is_empty() {
                return Some(v.to_owned());
            }
        }
    }
    None
}

#[derive(Clone, Debug, PartialEq, serde::Serialize)]
pub struct VlanMember {
    pub port: String,
    pub tagged: bool,
    pub address: Option<(IpAddr, u8)>,
    pub description: Option<String>,
}

#[derive(Clone, Debug, PartialEq, serde::Serialize)]
pub struct VlanInfo {
    pub id: u16,
    pub description: Option<String>,
    pub address: Option<(IpAddr, u8)>,
    pub members: Vec<VlanMember>,
}

#[derive(Clone, Debug, PartialEq, serde::Serialize)]
pub struct DhcpRange {
    pub start: Option<IpAddr>,
    pub stop: Option<IpAddr>,
}

#[derive(Clone, Debug, PartialEq, serde::Serialize)]
pub struct StaticLease {
    pub mac: MacAddress,
    pub ip: Option<IpAddr>,
    pub name: Option<String>,
}

#[derive(Clone, Debug, PartialEq, serde::Serialize)]
pub struct DhcpSubnet {
    pub cidr: String,
    pub ranges: Vec<DhcpRange>,
    pub default_router: Option<IpAddr>,
    pub domain_name: Option<String>,
    pub lease_time: Option<u32>,
    pub name_servers: Vec<IpAddr>,
    pub static_leases: Vec<StaticLease>,
}

#[derive(Clone, Debug, PartialEq, serde::Serialize)]
pub struct DhcpPool {
    pub name: String,
    pub subnets: Vec<DhcpSubnet>,
}

#[derive(Clone, Debug, PartialEq, serde::Serialize)]
pub struct EdgeConfig {
    pub hostname: Option<String>,
    pub vlans: BTreeMap<u16, VlanInfo>,
    /// physical ports with an address on the base interface
    pub ports: BTreeMap<String, (IpAddr, u8)>,
    pub dhcp: Vec<DhcpPool>,
}

/// Tokenize one `set ...` command line, honoring single quotes.
fn tokenize(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut in_quote = false;
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\'' => in_quote = !in_quote,
            ' ' | '\t' if !in_quote => {
                if !cur.is_empty() {
                    out.push(std::mem::take(&mut cur));
                }
            }
            _ => cur.push(c),
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

fn parse_cidr(s: &str) -> Option<(IpAddr, u8)> {
    let (addr, pfx) = s.split_once('/')?;
    Some((addr.parse().ok()?, pfx.parse().ok()?))
}

fn parse_maybe_cidr(s: &str) -> Option<(IpAddr, u8)> {
    if let Some(c) = parse_cidr(s) {
        return Some(c);
    }
    Some((s.parse().ok()?, if s.contains(':') { 128 } else { 32 }))
}

impl EdgeConfig {
    /// Parse the output of `show configuration commands`.
    pub fn from_commands(text: &str) -> Self {
        let mut cfg = EdgeConfig {
            hostname: None,
            vlans: BTreeMap::new(),
            ports: BTreeMap::new(),
            dhcp: Vec::new(),
        };
        let mut subnets: BTreeMap<(String, String), DhcpSubnet> = BTreeMap::new();

        for line in text.lines() {
            let line = line.trim();
            if !line.starts_with("set ") {
                continue;
            }
            let t = tokenize(line);
            let rest = &t[1..]; // drop "set"
            match rest {
                [w, rest @ ..] => match w.as_str() {
                    "system" => {
                        if rest.starts_with(&["host".into(), "name".into()]) {
                            cfg.hostname = rest.get(2).cloned();
                        }
                    }
                    "interfaces" => Self::parse_interfaces(&mut cfg, rest),
                    "service" => {
                        if rest.first().map(|s| s.as_str()) == Some("dhcp-server") {
                            Self::parse_dhcp(&mut subnets, &rest[1..]);
                        }
                    }
                    _ => {}
                },
                [] => {}
            }
        }

        // group subnets back into pools, sorted by name for determinism
        let mut pools: BTreeMap<String, Vec<DhcpSubnet>> = BTreeMap::new();
        for ((pool, _cidr), subnet) in subnets {
            pools.entry(pool).or_default().push(subnet);
        }
        cfg.dhcp = pools
            .into_iter()
            .map(|(name, mut subnets)| {
                subnets.sort_by(|a, b| a.cidr.cmp(&b.cidr));
                DhcpPool { name, subnets }
            })
            .collect();
        cfg
    }

    fn parse_interfaces(cfg: &mut EdgeConfig, rest: &[String]) {
        // rest = [<type>, <name>, ...]
        let (itype, iname) = match rest {
            [ty, name, ..] => (ty.as_str(), name.clone()),
            _ => return,
        };
        let port = match itype {
            "ethernet" | "switch" => iname,
            _ => return, // vif on non-ports (e.g. vlan bridge) handled below
        };
        let tail = &rest[2.min(rest.len())..];
        // find optional "vif <id>" segment
        let (vif, tail) = match tail {
            [v, id, tail @ ..] if v == "vif" => (id.parse::<u16>().ok(), tail.to_vec()),
            _ => (None, tail.to_vec()),
        };
        let key = tail.first().map(|s| s.as_str());

        // vyos truth: the bare `... vif <id>` line itself declares membership.
        if let Some(id) = vif {
            let vlan = cfg.vlans.entry(id).or_insert_with(|| VlanInfo {
                id,
                description: None,
                address: None,
                members: Vec::new(),
            });
            if !vlan.members.iter().any(|m| m.port == port) {
                vlan.members.push(VlanMember {
                    port: port.clone(),
                    tagged: true,
                    address: None,
                    description: None,
                });
            }
        }

        match key {
            Some("address") => {
                let Some(addr) = tail.get(1).and_then(|s| parse_maybe_cidr(s)) else {
                    return;
                };
                match vif {
                    None => {
                        cfg.ports.insert(port, addr);
                    }
                    Some(id) => {
                        let vlan = cfg.vlans.entry(id).or_insert_with(|| VlanInfo {
                            id,
                            description: None,
                            address: None,
                            members: Vec::new(),
                        });
                        vlan.address = vlan.address.or(Some(addr));
                        if let Some(m) = vlan.members.iter_mut().find(|m| m.port == port) {
                            m.address = Some(addr);
                        } else {
                            vlan.members.push(VlanMember {
                                port: port.clone(),
                                tagged: true,
                                address: Some(addr),
                                description: None,
                            });
                        }
                    }
                }
            }
            Some("description") => {
                let desc = tail.get(1).cloned();
                match vif {
                    None => {
                        // base-port description: attach to any vlan membership
                        for vlan in cfg.vlans.values_mut() {
                            if let Some(m) = vlan.members.iter_mut().find(|m| m.port == port) {
                                m.description = m.description.take().or_else(|| desc.clone());
                            }
                        }
                        let _ = desc;
                    }
                    Some(id) => {
                        let vlan = cfg.vlans.entry(id).or_insert_with(|| VlanInfo {
                            id,
                            description: None,
                            address: None,
                            members: Vec::new(),
                        });
                        if vlan.description.is_none() {
                            vlan.description = desc.clone();
                        }
                        if let Some(m) = vlan.members.iter_mut().find(|m| m.port == port) {
                            m.description = m.description.take().or(desc);
                        } else {
                            vlan.members.push(VlanMember {
                                port,
                                tagged: true,
                                address: None,
                                description: desc,
                            });
                        }
                    }
                }
            }
            Some("mode") => {
                let tagged = tail.get(1).map(|s| s != "access").unwrap_or(true);
                if let Some(id) = vif {
                    if let Some(vlan) = cfg.vlans.get_mut(&id) {
                        if let Some(m) = vlan.members.iter_mut().find(|m| m.port == port) {
                            m.tagged = tagged;
                        }
                    }
                }
            }
            _ => {}
        }
    }

    fn parse_dhcp(subnets: &mut BTreeMap<(String, String), DhcpSubnet>, rest: &[String]) {
        // rest = shared-network-name NAME subnet CIDR ...
        if rest.len() < 4 || rest[0] != "shared-network-name" || rest[2] != "subnet" {
            return;
        }
        let pool = rest[1].clone();
        let cidr = rest[3].clone();
        let subnet = subnets
            .entry((pool, cidr.clone()))
            .or_insert_with(|| DhcpSubnet {
                cidr,
                ranges: Vec::new(),
                default_router: None,
                domain_name: None,
                lease_time: None,
                name_servers: Vec::new(),
                static_leases: Vec::new(),
            });
        match &rest[4..] {
            [k, tail @ ..] => match k.as_str() {
                "range" => {
                    let Some(what) = tail.get(1) else { return };
                    let Some(value) = tail.get(2).and_then(|v| v.parse::<IpAddr>().ok()) else {
                        return;
                    };
                    let existing = match what.as_str() {
                        "start" => subnet
                            .ranges
                            .iter()
                            .position(|r| r.start.is_none() && r.stop.is_none()),
                        "stop" => subnet
                            .ranges
                            .iter()
                            .position(|r| r.start.is_some() && r.stop.is_none()),
                        _ => None,
                    };
                    let idx = match existing {
                        Some(i) => i,
                        None => {
                            subnet.ranges.push(DhcpRange {
                                start: None,
                                stop: None,
                            });
                            subnet.ranges.len() - 1
                        }
                    };
                    let range = &mut subnet.ranges[idx];
                    match what.as_str() {
                        "start" => range.start = Some(value),
                        "stop" => range.stop = Some(value),
                        _ => {}
                    }
                }
                "default-router" => {
                    subnet.default_router = tail.first().and_then(|v| v.parse::<IpAddr>().ok())
                }
                "domain-name" => subnet.domain_name = tail.first().cloned(),
                "lease" | "lease-time" => {
                    subnet.lease_time = tail.first().and_then(|v| v.parse::<u32>().ok())
                }
                "dns-server" | "name-server" => {
                    if let Some(ip) = tail.first().and_then(|v| v.parse::<IpAddr>().ok()) {
                        if !subnet.name_servers.contains(&ip) {
                            subnet.name_servers.push(ip);
                        }
                    }
                }
                // classic EdgeOS range: `start X stop Y`
                "start" => {
                    let Some(value) = tail.first().and_then(|v| v.parse::<IpAddr>().ok()) else {
                        return;
                    };
                    let stop = tail.get(2).and_then(|v| v.parse::<IpAddr>().ok());
                    subnet.ranges.push(DhcpRange {
                        start: Some(value),
                        stop,
                    });
                }
                "stop" => {
                    if let Some(stop) = tail.first().and_then(|v| v.parse::<IpAddr>().ok()) {
                        if let Some(open) = subnet
                            .ranges
                            .iter_mut()
                            .find(|r| r.start.is_some() && r.stop.is_none())
                        {
                            open.stop = Some(stop);
                        } else {
                            subnet.ranges.push(DhcpRange {
                                start: None,
                                stop: Some(stop),
                            });
                        }
                    }
                }
                // classic EdgeOS leases: `static-mapping NAME ip-address X` / `mac-address Y`
                "static-mapping" => {
                    let Some(name) = tail.first() else { return };
                    let entry = match subnet
                        .static_leases
                        .iter_mut()
                        .find(|l| l.name.as_deref() == Some(name.as_str()))
                    {
                        Some(e) => e,
                        None => {
                            subnet.static_leases.push(StaticLease {
                                mac: MacAddress([0; 6]),
                                ip: None,
                                name: Some(name.clone()),
                            });
                            subnet.static_leases.last_mut().unwrap()
                        }
                    };
                    match (tail.get(1).map(|s| s.as_str()), tail.get(2)) {
                        (Some("ip-address"), Some(ip)) => entry.ip = ip.parse().ok(),
                        (Some("mac-address"), Some(mac)) => {
                            if let Some(m) = MacAddress::parse(mac) {
                                entry.mac = m;
                            }
                        }
                        _ => {}
                    }
                }
                "static-mac" => {
                    let Some(mac) = tail.first().and_then(|m| MacAddress::parse(m)) else {
                        return;
                    };
                    let entry = match subnet.static_leases.iter_mut().find(|l| l.mac == mac) {
                        Some(e) => e,
                        None => {
                            subnet.static_leases.push(StaticLease {
                                mac,
                                ip: None,
                                name: None,
                            });
                            subnet.static_leases.last_mut().unwrap()
                        }
                    };
                    match (tail.get(1).map(|s| s.as_str()), tail.get(2)) {
                        (Some("ip") | Some("ip-address"), Some(ip)) => entry.ip = ip.parse().ok(),
                        (Some("name"), Some(n)) => entry.name = Some(n.clone()),
                        _ => {}
                    }
                }
                _ => {}
            },
            [] => {}
        }
    }
}

#[derive(Clone, Debug, PartialEq, serde::Serialize)]
pub struct ArpEntry {
    pub ip: IpAddr,
    pub mac: MacAddress,
    pub iface: String,
    pub kind: String,
}

/// Parse the ARP/neigh table. Two real shapes:
/// - classic: `10.0.7.25  aa:bb:cc:dd:ee:ff  eth0  dynamic`
/// - `show arp` on EdgeOS (ip neigh): `192.168.99.12  ether  c0:ff:...  C  eth1.99`
/// `(incomplete)` rows carry no MAC and are skipped.
pub fn parse_arp_table(text: &str) -> Vec<ArpEntry> {
    let mut out = Vec::new();
    for line in text.lines() {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() < 2 {
            continue;
        }
        let Ok(ip) = cols[0].parse::<IpAddr>() else {
            continue;
        };
        let Some(mac_idx) = cols[1..]
            .iter()
            .position(|c| MacAddress::parse(c).is_some())
        else {
            continue;
        };
        let mac_idx = mac_idx + 1;
        let mac = MacAddress::parse(cols[mac_idx]).unwrap();
        let (iface, kind) =
            if cols.get(mac_idx + 1) == Some(&"C") || cols.get(mac_idx + 1) == Some(&"R") {
                // ip neigh: flags then iface
                (
                    cols.get(mac_idx + 2).unwrap_or(&"?").to_string(),
                    "dynamic".to_string(),
                )
            } else {
                (
                    cols.get(mac_idx + 1).unwrap_or(&"?").to_string(),
                    cols.get(mac_idx + 2).unwrap_or(&"dynamic").to_string(),
                )
            };
        out.push(ArpEntry {
            ip,
            mac,
            iface,
            kind,
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const SHOW_VERSION: &str = "\
Version:             v2.0.9.hotfix.11277
Build ID:            11277
Build on:            12/20/19 16:41
Copyright:(C) 2020
       Ubiquiti Networks, Inc.
HW model:            EdgeRouter 10X
HW S/N:              00D041XXXXXX
Uptime:              18:28:09 up 118 days
";

    const CONFIG: &str = "\
set interfaces ethernet eth0 address '10.0.7.1/24'
set interfaces ethernet eth0 description 'UPLINK'
set interfaces ethernet eth1 vif '35' address '10.0.35.1/24'
set interfaces ethernet eth1 vif '35' description 'LAB'
set interfaces ethernet eth2 vif '35'
set interfaces ethernet eth2 vif '35' mode 'access'
set service dhcp-server shared-network-name LAN subnet 10.0.7.0/24 default-router '10.0.7.1'
set service dhcp-server shared-network-name LAN subnet 10.0.7.0/24 domain-name 'home.arpa'
set service dhcp-server shared-network-name LAN subnet 10.0.7.0/24 lease-time '86400'
set service dhcp-server shared-network-name LAN subnet 10.0.7.0/24 name-server '10.0.7.1'
set service dhcp-server shared-network-name LAN subnet 10.0.7.0/24 range 0 start '10.0.7.100'
set service dhcp-server shared-network-name LAN subnet 10.0.7.0/24 range 0 stop '10.0.7.199'
set service dhcp-server shared-network-name LAB35 subnet 10.0.35.0/24 static-mac aa:bb:cc:dd:ee:01 ip '10.0.35.50'
set service dhcp-server shared-network-name LAB35 subnet 10.0.35.0/24 static-mac aa:bb:cc:dd:ee:01 name 'nas'
set system host name 'er-10x'
";

    #[test]
    fn parses_show_version() {
        let v = parse_show_version(SHOW_VERSION);
        assert_eq!(v.firmware.as_deref(), Some("v2.0.9.hotfix.11277"));
        assert_eq!(v.model.as_deref(), Some("EdgeRouter 10X"));
        assert_eq!(v.vendor.as_deref(), Some("Ubiquiti"));
    }

    #[test]
    fn parses_config_commands() {
        let cfg = EdgeConfig::from_commands(CONFIG);
        assert_eq!(cfg.hostname.as_deref(), Some("er-10x"));
        assert_eq!(cfg.ports.len(), 1);
        let (ip, pfx) = cfg.ports["eth0"];
        assert_eq!((ip.to_string().as_str(), pfx), ("10.0.7.1", 24));

        let vlan = &cfg.vlans[&35];
        assert_eq!(vlan.description.as_deref(), Some("LAB"));
        assert_eq!(vlan.members.len(), 2);
        let tagged = vlan.members.iter().find(|m| m.port == "eth1").unwrap();
        assert!(tagged.tagged);
        assert_eq!(tagged.address.unwrap().1, 24);
        let access = vlan.members.iter().find(|m| m.port == "eth2").unwrap();
        assert!(!access.tagged);

        assert_eq!(cfg.dhcp.len(), 2);
        let lan = cfg.dhcp.iter().find(|p| p.name == "LAN").unwrap();
        let subnet = &lan.subnets[0];
        assert_eq!(subnet.lease_time, Some(86400));
        assert_eq!(subnet.default_router.unwrap().to_string(), "10.0.7.1");
        assert_eq!(subnet.ranges.len(), 1);
        assert!(subnet.ranges[0].start.is_some() && subnet.ranges[0].stop.is_some());
        let lab = cfg.dhcp.iter().find(|p| p.name == "LAB35").unwrap();
        let lease = &lab.subnets[0].static_leases[0];
        assert_eq!(lease.ip.unwrap().to_string(), "10.0.35.50");
        assert_eq!(lease.name.as_deref(), Some("nas"));
    }

    #[test]
    fn parses_arp_table() {
        let text = "\
Address                  HWtype  HWaddress           Flags Mask            Iface
192.168.99.12            ether   c0:ff:d4:a7:ec:c4   C                     eth1.99
192.168.1.7                      (incomplete)                              eth1
192.168.10.74            ether   dc:a6:32:fb:86:68   C                     eth1.10
192.168.30.12                    (incomplete)                              eth1.30
";
        let entries = parse_arp_table(text);
        assert_eq!(entries.len(), 2, "{entries:?}");
        assert_eq!(entries[0].ip.to_string(), "192.168.99.12");
        assert_eq!(entries[0].mac.to_string(), "c0:ff:d4:a7:ec:c4");
        assert_eq!(entries[0].iface, "eth1.99");
        assert_eq!(entries[1].iface, "eth1.10");
    }

    #[test]
    fn parses_classic_arp_table() {
        let text = "\
Address          Mac Address        Interface   Type
10.0.7.25        dc:a6:32:11:22:33  eth0        dynamic
10.0.7.1         00:d0:41:aa:bb:cc  eth0        static
garbage line here
";
        let entries = parse_arp_table(text);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].iface, "eth0");
        assert_eq!(entries[1].kind, "static");
    }

    #[test]
    fn parses_host_name() {
        assert_eq!(
            parse_host_name("Host name: er-10x").as_deref(),
            Some("er-10x")
        );
    }

    // The classic EdgeOS 2.x dialect, captured from a live EdgeRouter 6P.
    #[test]
    fn parses_classic_vyos_dhcp_dialect() {
        let text = "\
set service dhcp-server shared-network-name CCTV subnet 192.168.30.0/24 default-router 192.168.30.1
set service dhcp-server shared-network-name CCTV subnet 192.168.30.0/24 dns-server 1.1.1.1
set service dhcp-server shared-network-name CCTV subnet 192.168.30.0/24 dns-server 9.9.9.9
set service dhcp-server shared-network-name CCTV subnet 192.168.30.0/24 lease 86400
set service dhcp-server shared-network-name CCTV subnet 192.168.30.0/24 start 192.168.30.10 stop 192.168.30.250
set service dhcp-server shared-network-name CCTV subnet 192.168.30.0/24 static-mapping Camera1 ip-address 192.168.30.11
set service dhcp-server shared-network-name CCTV subnet 192.168.30.0/24 static-mapping Camera1 mac-address 'a0:60:32:05:00:ca'
";
        let cfg = EdgeConfig::from_commands(text);
        let pool = &cfg.dhcp[0];
        assert_eq!(pool.name, "CCTV");
        let sub = &pool.subnets[0];
        assert_eq!(sub.lease_time, Some(86400));
        assert_eq!(sub.name_servers.len(), 2);
        assert_eq!(sub.ranges[0].start.unwrap().to_string(), "192.168.30.10");
        assert_eq!(sub.ranges[0].stop.unwrap().to_string(), "192.168.30.250");
        let cam = &sub.static_leases[0];
        assert_eq!(cam.name.as_deref(), Some("Camera1"));
        assert_eq!(cam.mac.to_string(), "a0:60:32:05:00:ca");
        assert_eq!(cam.ip.unwrap().to_string(), "192.168.30.11");
    }
}
