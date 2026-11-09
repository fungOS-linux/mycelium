use std::net::IpAddr;

use mycelium_core::{LinkDuplex, LinkMedium, MacAddress};

#[derive(Clone, Debug, PartialEq)]
pub struct Interface {
    pub name: String,
    pub mac: Option<MacAddress>,
    pub addresses: Vec<(IpAddr, u8)>,
    pub up: bool,
    pub medium: LinkMedium,
    pub speed_mbps: Option<u32>,
    pub duplex: Option<LinkDuplex>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Neighbor {
    pub ip: IpAddr,
    pub iface: String,
    pub mac: MacAddress,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Listener {
    pub transport: String,
    pub port: u16,
    pub process: Option<String>,
    /// The listener is bound to loopback, so only this host can reach it.
    pub host_local: bool,
}

pub fn parse_interfaces(text: &str) -> Vec<Interface> {
    let mut out = Vec::new();
    let mut current: Option<Interface> = None;
    for line in text.lines() {
        if !line.starts_with([' ', '\t']) {
            if let Some(interface) = current.take() {
                out.push(interface);
            }
            let Some((name, rest)) = line.split_once(':') else {
                continue;
            };
            current = Some(Interface {
                name: name.into(),
                mac: None,
                addresses: Vec::new(),
                up: rest.contains("<UP,") || rest.contains(",UP,") || rest.contains("<UP>"),
                medium: if name == "lo0" {
                    LinkMedium::Loopback
                } else if name.starts_with("utun") {
                    LinkMedium::Virtual
                } else {
                    LinkMedium::Unknown
                },
                speed_mbps: None,
                duplex: None,
            });
            continue;
        }
        let Some(interface) = current.as_mut() else {
            continue;
        };
        let words: Vec<_> = line.split_whitespace().collect();
        match words.first().copied() {
            Some("ether") => interface.mac = words.get(1).and_then(|mac| MacAddress::parse(mac)),
            Some("inet") => {
                if let (Some(ip), Some(mask)) = (
                    words.get(1).and_then(|ip| ip.parse().ok()),
                    words
                        .windows(2)
                        .find(|w| w[0] == "netmask")
                        .and_then(|w| parse_hex_prefix(w[1])),
                ) {
                    interface.addresses.push((ip, mask));
                }
            }
            Some("inet6") => {
                if let Some(ip) = words
                    .get(1)
                    .and_then(|ip| ip.split('%').next())
                    .and_then(|ip| ip.parse::<IpAddr>().ok())
                {
                    if !ip.is_loopback()
                        && !matches!(ip, IpAddr::V6(ip) if ip.is_unicast_link_local())
                    {
                        let prefix = words
                            .windows(2)
                            .find(|w| w[0] == "prefixlen")
                            .and_then(|w| w[1].parse().ok())
                            .unwrap_or(128);
                        interface.addresses.push((ip, prefix));
                    }
                }
            }
            Some("media:") => {
                interface.speed_mbps = words.iter().find_map(|word| {
                    word.trim_start_matches(|ch: char| !ch.is_ascii_digit())
                        .strip_suffix("baseT")
                        .and_then(|speed| speed.parse().ok())
                });
                if line.contains("full-duplex") {
                    interface.duplex = Some(LinkDuplex::Full);
                }
                if line.contains("half-duplex") {
                    interface.duplex = Some(LinkDuplex::Half);
                }
            }
            _ => {}
        }
    }
    if let Some(interface) = current {
        out.push(interface);
    }
    out
}

pub fn parse_hardware_ports(text: &str, interfaces: &mut [Interface]) {
    let mut hardware = "";
    for line in text.lines() {
        if let Some(value) = line.strip_prefix("Hardware Port: ") {
            hardware = value;
        }
        if let Some(device) = line.strip_prefix("Device: ") {
            if let Some(interface) = interfaces
                .iter_mut()
                .find(|interface| interface.name == device)
            {
                interface.medium = if hardware.contains("Wi-Fi") || hardware.contains("AirPort") {
                    LinkMedium::Wifi
                } else {
                    LinkMedium::Ethernet
                };
            }
        }
    }
}

pub fn parse_neighbors(text: &str) -> Vec<Neighbor> {
    text.lines()
        .filter_map(|line| {
            let ip = line.split_once('(')?.1.split_once(')')?.0.parse().ok()?;
            let mac = line
                .split(" at ")
                .nth(1)?
                .split_whitespace()
                .next()
                .and_then(MacAddress::parse)?;
            let iface = line
                .split(" on ")
                .nth(1)?
                .split_whitespace()
                .next()?
                .to_owned();
            Some(Neighbor { ip, iface, mac })
        })
        .collect()
}

pub fn parse_listeners(text: &str) -> Vec<Listener> {
    let mut out: Vec<_> = text
        .lines()
        .skip(1)
        .filter_map(|line| {
            let words: Vec<_> = line.split_whitespace().collect();
            let transport_index = words
                .iter()
                .position(|word| *word == "TCP" || *word == "UDP")?;
            let transport = words[transport_index].to_ascii_lowercase();
            // lsof prints the bound socket address here; keep it so a
            // loopback-only listener is not advertised as a mesh endpoint.
            let (host, port) = words.iter().rev().find_map(|word| {
                let (host, port) = word.trim_end_matches("(LISTEN)").rsplit_once(':')?;
                Some((host.to_owned(), port.parse::<u16>().ok()?))
            })?;
            Some(Listener {
                transport,
                port,
                process: words.first().map(|value| (*value).to_owned()),
                host_local: mycelium_core::is_host_local_listener(&host),
            })
        })
        .collect();
    out.sort();
    out.dedup();
    out
}

fn parse_hex_prefix(value: &str) -> Option<u8> {
    let mask = u32::from_str_radix(value.trim_start_matches("0x"), 16).ok()?;
    Some(mask.count_ones() as u8)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ifconfig_hardware_and_arp() {
        let mut interfaces = parse_interfaces("en0: flags=8863<UP,BROADCAST,RUNNING> mtu 1500\n\tether c2:d9:80:ba:f1:ee\n\tinet 192.168.10.82 netmask 0xffffff00 broadcast 192.168.10.255\n\tmedia: autoselect (1000baseT <full-duplex>)\n\tstatus: active\n");
        parse_hardware_ports("Hardware Port: Wi-Fi\nDevice: en0\n", &mut interfaces);
        assert_eq!(interfaces[0].medium, LinkMedium::Wifi);
        assert_eq!(interfaces[0].speed_mbps, Some(1000));
        assert_eq!(interfaces[0].addresses[0].1, 24);
        let neighbors =
            parse_neighbors("? (192.168.10.1) at f4:e2:c6:d5:63:2d on en0 ifscope [ethernet]");
        assert_eq!(neighbors[0].iface, "en0");
    }
}
