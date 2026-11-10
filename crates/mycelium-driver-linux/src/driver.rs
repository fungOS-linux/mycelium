use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use mycelium_core::{
    host_target, required_str, stable_slug, CapResult, CapSpec, CredentialSet, Device, DeviceId,
    DeviceKind, DeviceMeta, Driver, ExecContext, Inventory, LinkState, MyceliumError, Observation,
    Origin, Params, PortRef, Result, Segment, SegmentKind, ServiceRecord, ServiceState, Target,
    Value, ID_IDENTIFY, ID_NET_FORWARD_ENSURE, ID_NET_VIP_ENSURE, ID_SYSTEM_HEALTH,
};
use mycelium_driver_edgeos::SshSession;
use mycelium_network_types::{Ipv4Prefix, PortForward, TransportProtocol};

use crate::parsers::{
    parse_interfaces, parse_link_properties, parse_listeners, parse_neighbors, parse_routes,
};
use mycelium_dnssd::parse_avahi;
use mycelium_ssdp::parse_probes as parse_ssdp_probes;
use mycelium_tailscale::{parse_control_plane, parse_status, topology_observations};

pub const DRIVER_NAME: &str = "linux";
const OBSERVE_COMMAND: &str = "printf '__MYCELIUM_LINKS__\\n'; ip -o link show; printf '__MYCELIUM_LINK_META__\\n'; for p in /sys/class/net/*; do n=${p##*/}; if [ \"$n\" = lo ]; then m=loopback; elif [ -d \"$p/wireless\" ]; then m=wifi; elif [ -e \"$p/device\" ]; then m=ethernet; else m=virtual; fi; printf '%s\\t%s\\t%s\\t%s\\n' \"$n\" \"$m\" \"$(cat \"$p/speed\" 2>/dev/null || true)\" \"$(cat \"$p/duplex\" 2>/dev/null || true)\"; done; printf '__MYCELIUM_ADDRS__\\n'; ip -o -4 addr show scope global; printf '__MYCELIUM_NEIGH__\\n'; ip neigh show; printf '__MYCELIUM_ROUTES__\\n'; ip -4 route show proto kernel scope link; printf '__MYCELIUM_SERVICES__\\n'; ss -H -lntup; printf '__MYCELIUM_TAILSCALE__\\n'; tailscale status --json 2>/dev/null || true; printf '\\n__MYCELIUM_TAILSCALE_PREFS__\\n'; tailscale debug prefs 2>/dev/null || true; printf '\\n__MYCELIUM_MDNS__\\n'; command -v avahi-browse >/dev/null 2>&1 && avahi-browse --all --resolve --parsable --terminate 2>/dev/null || true; printf '\\n__MYCELIUM_SSDP__\\n'; if command -v nc >/dev/null 2>&1; then ip -o -4 route show proto kernel scope link | awk '{ dev=\"\"; src=\"\"; for (i=1; i<=NF; i++) { if ($i == \"dev\") dev=$(i+1); if ($i == \"src\") src=$(i+1) } if (dev != \"\" && src != \"\") print dev, src }' | sort -u | while read -r iface addr; do case \"$iface\" in lo|docker*|br-*|veth*|tailscale*|sh-*|sv*) continue ;; esac; printf '__MYCELIUM_SSDP_PROBE__\\t%s\\t%s\\n' \"$iface\" \"$addr\"; printf 'M-SEARCH * HTTP/1.1\\r\\nHOST: 239.255.255.250:1900\\r\\nMAN: \"ssdp:discover\"\\r\\nMX: 2\\r\\nST: ssdp:all\\r\\n\\r\\n' | nc -4 -u -s \"$addr\" -w 3 239.255.255.250 1900 2>/dev/null || true; done; fi";
const HEALTH_COMMAND: &str = "printf '__UPTIME__\\n'; cat /proc/uptime; printf '__LOAD__\\n'; cat /proc/loadavg; printf '__MEMORY__\\n'; awk '/^(MemTotal|MemAvailable|SwapTotal|SwapFree):/ {print $1, $2}' /proc/meminfo; printf '__DISK__\\n'; df -P -B1 / | tail -n 1; printf '__PRESSURE__\\n'; for p in cpu memory io; do [ -r /proc/pressure/$p ] && { printf '%s ' \"$p\"; tr '\\n' ' ' </proc/pressure/$p; printf '\\n'; }; done; printf '__SOCKETS__\\n'; ss -s; printf '__SSH__\\n'; ss -Htan 2>/dev/null | awk '$4 ~ /:22$/ {count[$1]++} END {for (state in count) print state, count[state]}'; printf '__PROCESSES__\\n'; ps -eo pid=,ppid=,stat=,pcpu=,pmem=,comm= --sort=-pcpu | head -n 10";

const PASSIVE_ADVERTISEMENTS_COMMAND: &str = "if command -v nc >/dev/null 2>&1 && command -v timeout >/dev/null 2>&1; then printf '__MYCELIUM_SSDP_PROBE__\\tbroadcast\\t0.0.0.0\\n'; timeout 4 nc -4 -u -k -l -p 2021 2>/dev/null || true; fi";

fn parse_health(text: &str) -> Result<Value> {
    const SECTIONS: [&str; 8] = [
        "UPTIME",
        "LOAD",
        "MEMORY",
        "DISK",
        "PRESSURE",
        "SOCKETS",
        "SSH",
        "PROCESSES",
    ];
    let mut output = Params::new();
    for (index, name) in SECTIONS.iter().enumerate() {
        let marker = format!("__{name}__\n");
        let start = text
            .find(&marker)
            .ok_or_else(|| MyceliumError::Parse(format!("missing health marker {marker:?}")))?
            + marker.len();
        let end = SECTIONS
            .get(index + 1)
            .and_then(|next| text[start..].find(&format!("__{next}__\n")))
            .map(|offset| start + offset)
            .unwrap_or(text.len());
        output.insert(
            name.to_ascii_lowercase(),
            Value::Str(text[start..end].trim().into()),
        );
    }
    Ok(Value::Map(output))
}

pub struct LinuxDriver {
    timeout: Duration,
}

impl Default for LinuxDriver {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(8),
        }
    }
}

pub struct LinuxDevice {
    session: SshSession,
    meta: DeviceMeta,
    site: String,
}

async fn identity(session: &SshSession) -> Result<(String, String)> {
    let out = session
        .exec("printf '%s\\n' \"$(hostname)\" \"$(uname -srm)\"")
        .await?;
    if !out.success() {
        return Err(MyceliumError::Device {
            exit_code: out.exit_code,
            stderr: out.stderr,
        });
    }
    let mut lines = out.stdout.lines();
    let hostname = lines.next().unwrap_or_default().trim().to_owned();
    let uname = lines.next().unwrap_or_default().trim().to_owned();
    if hostname.is_empty() || !uname.starts_with("Linux ") {
        return Err(MyceliumError::Validation(
            "SSH target is not a recognizable Linux host".into(),
        ));
    }
    Ok((hostname, uname))
}

fn vip_command(params: &Params) -> Result<(Ipv4Prefix, String, String)> {
    let interface = string_param(params, "interface")?;
    if interface.is_empty()
        || interface.len() > 15
        || !interface
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:-".contains(&byte))
    {
        return Err(MyceliumError::Validation(
            "interface must be a Linux interface name of at most 15 safe ASCII characters".into(),
        ));
    }
    let address = string_param(params, "address")?;
    let (ip, prefix) = address
        .split_once('/')
        .ok_or_else(|| MyceliumError::Validation("address must be IPv4 CIDR notation".into()))?;
    let ip = ip.parse::<std::net::Ipv4Addr>().map_err(|_| {
        MyceliumError::Validation("address must contain a valid IPv4 address".into())
    })?;
    let prefix = prefix
        .parse::<u8>()
        .ok()
        .and_then(|prefix| Ipv4Prefix::new(ip.octets(), prefix))
        .ok_or_else(|| {
            MyceliumError::Validation("IPv4 prefix length must be 0 through 32".into())
        })?;
    let canonical = format_prefix(prefix);
    let command = format!("sudo -n ip address replace {canonical} dev {interface}");
    Ok((prefix, interface.into(), command))
}

fn forwarding_rule(params: &Params) -> Result<PortForward> {
    let protocol = match string_param(params, "protocol")? {
        "tcp" => TransportProtocol::Tcp,
        "udp" => TransportProtocol::Udp,
        _ => {
            return Err(MyceliumError::Validation(
                "protocol must be `tcp` or `udp`".into(),
            ))
        }
    };
    Ok(PortForward {
        protocol,
        listen_address: ipv4_param(params, "listen_address")?,
        listen_port: port_param(params, "listen_port")?,
        target_address: ipv4_param(params, "target_address")?,
        target_port: port_param(params, "target_port")?,
    })
}

fn string_param<'a>(params: &'a Params, name: &str) -> Result<&'a str> {
    required_str(params, name)
}

fn ipv4_param(params: &Params, name: &str) -> Result<[u8; 4]> {
    string_param(params, name)?
        .parse::<std::net::Ipv4Addr>()
        .map(|address| address.octets())
        .map_err(|_| MyceliumError::Validation(format!("param `{name}` must be an IPv4 address")))
}

fn port_param(params: &Params, name: &str) -> Result<u16> {
    let value = params
        .get(name)
        .and_then(Value::as_i64)
        .ok_or_else(|| MyceliumError::Validation(format!("param `{name}` must be an integer")))?;
    u16::try_from(value)
        .ok()
        .filter(|port| *port != 0)
        .ok_or_else(|| MyceliumError::Validation(format!("param `{name}` must be 1 through 65535")))
}

fn format_prefix(prefix: Ipv4Prefix) -> String {
    format!(
        "{}/{}",
        std::net::Ipv4Addr::from(prefix.address),
        prefix.prefix_length
    )
}

fn protocol_name(protocol: TransportProtocol) -> &'static str {
    match protocol {
        TransportProtocol::Tcp => "tcp",
        TransportProtocol::Udp => "udp",
    }
}

#[async_trait]
impl Driver for LinuxDriver {
    fn name(&self) -> &str {
        DRIVER_NAME
    }

    async fn recognizes(&self, target: &Target, creds: &CredentialSet) -> Result<bool> {
        let session =
            SshSession::connect_target(target, creds, self.timeout, "linux observer").await?;
        Ok(identity(&session).await.is_ok())
    }

    async fn attach(
        &self,
        target: &Target,
        creds: &CredentialSet,
        inventory: &Inventory,
    ) -> Result<DeviceId> {
        let endpoint = host_target(target, 22, "linux observer")?;
        let session =
            SshSession::connect_target(target, creds, self.timeout, "linux observer").await?;
        let (hostname, uname) = identity(&session).await?;
        let slug = stable_slug(&hostname);
        let meta = DeviceMeta {
            id: DeviceId::new(format!("linux-{slug}")),
            kind: DeviceKind::Other,
            driver: DRIVER_NAME.into(),
            vendor: Some("Linux".into()),
            model: Some(uname),
            firmware: None,
            address: endpoint.host.to_owned(),
        };
        let id = meta.id.clone();
        inventory.add(Arc::new(LinuxDevice {
            session,
            meta,
            site: hostname.to_lowercase(),
        }));
        Ok(id)
    }
}

#[async_trait]
impl Device for LinuxDevice {
    fn meta(&self) -> &DeviceMeta {
        &self.meta
    }

    fn capabilities(&self) -> BTreeMap<String, CapSpec> {
        BTreeMap::from_iter([
            (
                ID_IDENTIFY.into(),
                CapSpec::readonly("Linux SSH vantage-point identity"),
            ),
            (
                ID_SYSTEM_HEALTH.into(),
                CapSpec::readonly(
                    "load, memory, disk, pressure, sockets, SSH sessions, and process leaders",
                ),
            ),
            (
                ID_NET_VIP_ENSURE.into(),
                CapSpec::mutation("ensure an IPv4 address is present on a Linux interface")
                    .param(
                        "interface",
                        mycelium_core::ParamType::Str,
                        "kernel interface name",
                    )
                    .param("address", mycelium_core::ParamType::Str, "IPv4 CIDR prefix"),
            ),
            (
                ID_NET_FORWARD_ENSURE.into(),
                CapSpec::mutation("plan an nftables DNAT forwarding rule")
                    .param("protocol", mycelium_core::ParamType::Str, "tcp or udp")
                    .param(
                        "listen_address",
                        mycelium_core::ParamType::Str,
                        "IPv4 listen address",
                    )
                    .param("listen_port", mycelium_core::ParamType::Int, "listen port")
                    .param(
                        "target_address",
                        mycelium_core::ParamType::Str,
                        "IPv4 target address",
                    )
                    .param("target_port", mycelium_core::ParamType::Int, "target port"),
            ),
        ])
    }

    async fn exec(&self, ctx: &ExecContext, cap: &str, params: Params) -> Result<CapResult> {
        match cap {
            ID_IDENTIFY => Ok(CapResult::ok(Value::Map(Params::from_iter([
                ("vendor".into(), Value::Str("Linux".into())),
                ("hostname".into(), Value::Str(self.site.clone())),
                (
                    "model".into(),
                    self.meta
                        .model
                        .clone()
                        .map(Value::Str)
                        .unwrap_or(Value::Null),
                ),
            ])))),
            ID_SYSTEM_HEALTH => {
                let result = self.session.exec(HEALTH_COMMAND).await?;
                if !result.success() {
                    return Err(MyceliumError::Device {
                        exit_code: result.exit_code,
                        stderr: result.stderr,
                    });
                }
                Ok(CapResult::ok(parse_health(&result.stdout)?))
            }
            ID_NET_VIP_ENSURE => {
                let (prefix, interface, command) = vip_command(&params)?;
                let output = Value::Map(Params::from_iter([
                    ("interface".into(), Value::Str(interface)),
                    ("address".into(), Value::Str(format_prefix(prefix))),
                    ("command".into(), Value::Str(command.clone())),
                ]));
                if ctx.dry_run {
                    return Ok(CapResult::dry_run(output));
                }
                let result = self.session.exec(&command).await?;
                if !result.success() {
                    return Err(MyceliumError::Device {
                        exit_code: result.exit_code,
                        stderr: result.stderr,
                    });
                }
                Ok(CapResult::ok(output))
            }
            ID_NET_FORWARD_ENSURE => {
                let rule = forwarding_rule(&params)?;
                let output = Value::Map(Params::from_iter([
                    (
                        "protocol".into(),
                        Value::Str(protocol_name(rule.protocol).into()),
                    ),
                    (
                        "listen".into(),
                        Value::Str(format!(
                            "{}:{}",
                            std::net::Ipv4Addr::from(rule.listen_address),
                            rule.listen_port
                        )),
                    ),
                    (
                        "target".into(),
                        Value::Str(format!(
                            "{}:{}",
                            std::net::Ipv4Addr::from(rule.target_address),
                            rule.target_port
                        )),
                    ),
                ]));
                if ctx.dry_run {
                    return Ok(CapResult::dry_run(output).with_message(
                        "nftables apply remains blocked until Mycelium owns a persistent table and can verify forwarding",
                    ));
                }
                Err(MyceliumError::Unsupported {
                    device: self.meta.id.to_string(),
                    capability: ID_NET_FORWARD_ENSURE.into(),
                })
            }
            other => Err(MyceliumError::Unsupported {
                device: self.meta.id.to_string(),
                capability: other.into(),
            }),
        }
    }

    async fn observe(&self) -> Result<(Vec<Observation>, Vec<String>)> {
        let command = format!("{OBSERVE_COMMAND}; {PASSIVE_ADVERTISEMENTS_COMMAND}");
        let raw = self.session.exec(&command).await?;
        if !raw.success() {
            return Err(MyceliumError::Device {
                exit_code: raw.exit_code,
                stderr: raw.stderr,
            });
        }
        let sections = split_sections(&raw.stdout)?;
        let mut interfaces = parse_interfaces(sections[0], sections[2]);
        parse_link_properties(sections[1], &mut interfaces);
        let primary_mac = interfaces
            .iter()
            .find(|interface| {
                !interface.name.starts_with("br-")
                    && !interface.name.starts_with("docker")
                    && !interface.name.starts_with("tailscale")
                    && !interface.name.starts_with("veth")
                    && !interface.name.starts_with("sh-")
                    && !interface.name.starts_with("sv")
                    && interface.addresses.iter().any(|(address, _)| {
                        matches!(address, std::net::IpAddr::V4(address) if address.is_private())
                    })
            })
            .and_then(|interface| interface.mac);
        let mut out = Vec::new();
        let origin = |source: &str| {
            Origin::new(self.meta.id.to_string(), source.to_owned()).at_site(self.site.clone())
        };
        for iface in interfaces {
            out.push(Observation::DevicePort {
                device: self.meta.id.to_string(),
                port: iface.name,
                mac: iface.mac.filter(|mac| Some(*mac) == primary_mac),
                ips: iface.addresses.into_iter().map(|(ip, _)| ip).collect(),
                state: if iface.up {
                    LinkState::Up
                } else {
                    LinkState::Down
                },
                medium: Some(iface.medium),
                speed_mbps: iface.speed_mbps,
                duplex: iface.duplex,
                origin: origin("ip-link"),
            });
        }
        for neighbor in parse_neighbors(sections[3]) {
            out.push(Observation::Neighbor {
                mac: Some(neighbor.mac),
                ip: neighbor.ip,
                hostname: None,
                port: Some(PortRef {
                    device: self.meta.id.to_string(),
                    port: neighbor.iface,
                    vif: None,
                }),
                origin: origin("ip-neigh"),
            });
        }
        for route in parse_routes(sections[4]) {
            out.push(Observation::Segment {
                segment: Segment {
                    id: format!("{}/{}", route.network, route.prefix),
                    kind: SegmentKind::Lan,
                    vlan: None,
                    subnet: Some((route.network, route.prefix)),
                    gw: None,
                    domain_name: None,
                    origins: Default::default(),
                },
                origin: origin(&format!("ip-route:{}", route.iface)),
            });
        }
        let observed_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let mut warnings = Vec::new();
        let mut kubo_versions = BTreeMap::new();
        for (address, port) in crate::ipfs::candidates(sections[5]) {
            match self
                .session
                .exec(&crate::ipfs::version_command(address, port))
                .await
            {
                Ok(response) if response.success() => {
                    if let Some(version) = crate::ipfs::parse_version(&response.stdout) {
                        kubo_versions.insert(port, version);
                    }
                }
                Ok(_) => {} // A candidate listener need not speak Kubo.
                Err(error) => warnings.push(format!("Kubo loopback probe {port}: {error}")),
            }
        }
        for listener in parse_listeners(sections[5]) {
            let kubo_version = (listener.transport == "tcp")
                .then(|| kubo_versions.get(&listener.port))
                .flatten();
            out.push(Observation::Service {
                device: self.meta.id.to_string(),
                mac: None,
                ip: None,
                service: ServiceRecord {
                    name: if kubo_version.is_some() {
                        "ipfs-rpc".into()
                    } else {
                        service_name(listener.port, listener.process.as_deref())
                    },
                    transport: listener.transport,
                    port: listener.port,
                    product: kubo_version
                        .map(|version| format!("IPFS Kubo/{version}"))
                        .or(listener.process),
                    state: ServiceState::Up,
                    observed_at,
                    host_local: listener.host_local,
                    origin: origin(if kubo_version.is_some() {
                        "kubo-loopback-version"
                    } else {
                        "ss-listen"
                    }),
                },
            });
        }
        let control_plane = match parse_control_plane(sections[7]) {
            Ok(control_plane) => control_plane,
            Err(error) => {
                warnings.push(format!("tailscale preferences: {error}"));
                Default::default()
            }
        };
        match parse_status(sections[6]) {
            Ok(status) => {
                out.extend(topology_observations(
                    status,
                    control_plane,
                    &self.meta.id.to_string(),
                    &self.site,
                    observed_at,
                ));
            }
            Err(error) => warnings.push(format!("tailscale status: {error}")),
        }
        out.extend(
            parse_avahi(sections[8], observed_at)
                .into_iter()
                .map(|advertisement| Observation::ServiceAdvertisement {
                    advertisement,
                    origin: origin("avahi-browse"),
                }),
        );
        out.extend(
            parse_ssdp_probes(sections[9], observed_at)
                .into_iter()
                .map(|advertisement| Observation::ServiceAdvertisement {
                    advertisement,
                    origin: origin("ssdp-m-search"),
                }),
        );
        Ok((out, warnings))
    }
}

fn service_name(port: u16, process: Option<&str>) -> String {
    match port {
        22 => "ssh".into(),
        25 => "smtp".into(),
        53 => "dns".into(),
        111 => "rpcbind".into(),
        631 => "ipp".into(),
        2049 => "nfs".into(),
        2222 => "ssh".into(),
        3000 | 3001 | 3002 => "http".into(),
        5432 | 5433 | 5435 => "postgres".into(),
        5900 => "vnc".into(),
        7878 => "radarr".into(),
        8123 => "home-assistant".into(),
        80 | 5000 | 8080 => "http".into(),
        443 | 8443 | 8888 | 8971 => "https".into(),
        8554 => "rtsp".into(),
        8555 => "webrtc".into(),
        8989 => "sonarr".into(),
        11434 => "ollama".into(),
        32400 => "plex".into(),
        _ => process.unwrap_or("unknown").to_owned(),
    }
}

fn split_sections(text: &str) -> Result<[&str; 10]> {
    let (_, after_links) = text
        .split_once("__MYCELIUM_LINKS__\n")
        .ok_or_else(|| MyceliumError::Parse("missing links marker".into()))?;
    let (links, after_meta) = after_links
        .split_once("__MYCELIUM_LINK_META__\n")
        .ok_or_else(|| MyceliumError::Parse("missing link metadata marker".into()))?;
    let (link_meta, after_addrs) = after_meta
        .split_once("__MYCELIUM_ADDRS__\n")
        .ok_or_else(|| MyceliumError::Parse("missing addresses marker".into()))?;
    let (addrs, after_neigh) = after_addrs
        .split_once("__MYCELIUM_NEIGH__\n")
        .ok_or_else(|| MyceliumError::Parse("missing neighbors marker".into()))?;
    let (neigh, after_routes) = after_neigh
        .split_once("__MYCELIUM_ROUTES__\n")
        .ok_or_else(|| MyceliumError::Parse("missing routes marker".into()))?;
    let (routes, after_services) = after_routes
        .split_once("__MYCELIUM_SERVICES__\n")
        .ok_or_else(|| MyceliumError::Parse("missing services marker".into()))?;
    let (services, tailscale_and_prefs) = after_services
        .split_once("__MYCELIUM_TAILSCALE__\n")
        .ok_or_else(|| MyceliumError::Parse("missing tailscale marker".into()))?;
    let (tailscale, prefs_and_mdns) = tailscale_and_prefs
        .split_once("__MYCELIUM_TAILSCALE_PREFS__\n")
        .ok_or_else(|| MyceliumError::Parse("missing tailscale preferences marker".into()))?;
    let (tailscale_prefs, mdns_and_ssdp) = prefs_and_mdns
        .split_once("__MYCELIUM_MDNS__\n")
        .ok_or_else(|| MyceliumError::Parse("missing mDNS marker".into()))?;
    let (mdns, ssdp) = mdns_and_ssdp
        .split_once("__MYCELIUM_SSDP__\n")
        .ok_or_else(|| MyceliumError::Parse("missing SSDP marker".into()))?;
    Ok([
        links,
        link_meta,
        addrs,
        neigh,
        routes,
        services,
        tailscale,
        tailscale_prefs,
        mdns,
        ssdp,
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vip_command_is_canonical_and_rejects_shell_input() {
        let params = Params::from_iter([
            ("interface".into(), Value::Str("eth0".into())),
            ("address".into(), Value::Str("192.0.2.20/24".into())),
        ]);
        let (_, _, command) = vip_command(&params).unwrap();
        assert_eq!(command, "sudo -n ip address replace 192.0.2.20/24 dev eth0");

        let malicious = Params::from_iter([
            ("interface".into(), Value::Str("eth0;reboot".into())),
            ("address".into(), Value::Str("192.0.2.20/24".into())),
        ]);
        assert!(vip_command(&malicious).is_err());
    }

    #[test]
    fn forwarding_rule_uses_bounded_shared_type() {
        let params = Params::from_iter([
            ("protocol".into(), Value::Str("tcp".into())),
            ("listen_address".into(), Value::Str("192.0.2.10".into())),
            ("listen_port".into(), Value::Int(8443)),
            ("target_address".into(), Value::Str("10.0.0.20".into())),
            ("target_port".into(), Value::Int(443)),
        ]);
        let rule = forwarding_rule(&params).unwrap();
        assert_eq!(rule.protocol, TransportProtocol::Tcp);
        assert_eq!(rule.listen_address, [192, 0, 2, 10]);
        assert_eq!(rule.target_address, [10, 0, 0, 20]);
        assert_eq!(rule.target_port, 443);
    }

    #[test]
    fn health_snapshot_requires_and_names_every_section() {
        let value = parse_health(
            "__UPTIME__\n12.0 3.0\n__LOAD__\n1.0 2.0 3.0 1/2 3\n__MEMORY__\nMemTotal: 10\n__DISK__\n/dev/a 10 2 8 20% /\n__PRESSURE__\ncpu some avg10=0.00\n__SOCKETS__\nTCP: 2\n__SSH__\nESTAB 1\n__PROCESSES__\n1 0 S 1.0 2.0 init\n",
        )
        .unwrap();
        let map = match value {
            Value::Map(map) => map,
            other => panic!("expected map, got {other:?}"),
        };
        assert_eq!(map.len(), 8);
        assert_eq!(map["ssh"].as_str(), Some("ESTAB 1"));
        assert!(parse_health("__UPTIME__\n1").is_err());
    }
}
