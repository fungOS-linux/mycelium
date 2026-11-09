//! Read-only Darwin SSH vantage-point driver.

mod parsers;

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use mycelium_core::{
    host_target, stable_slug, CapResult, CapSpec, CredentialSet, Device, DeviceId, DeviceKind,
    DeviceMeta, Driver, ExecContext, Inventory, LinkState, MyceliumError, Observation, Origin,
    Params, PortRef, Result, Segment, SegmentKind, ServiceRecord, ServiceState, Target, Value,
    ID_IDENTIFY,
};
use mycelium_dnssd::parse_dns_sd_zone;
use mycelium_driver_edgeos::SshSession;
use mycelium_ssdp::parse_probes as parse_ssdp_probes;
use mycelium_tailscale::{parse_control_plane, parse_status, topology_observations};

use parsers::{parse_hardware_ports, parse_interfaces, parse_listeners, parse_neighbors};

pub const DRIVER_NAME: &str = "darwin";
const OBSERVE_COMMAND: &str = "printf '__MYCELIUM_IFCONFIG__\\n'; /sbin/ifconfig -a; printf '__MYCELIUM_HARDWARE_PORTS__\\n'; /usr/sbin/networksetup -listallhardwareports 2>/dev/null || true; printf '__MYCELIUM_ARP__\\n'; /usr/sbin/arp -an; printf '__MYCELIUM_SERVICES__\\n'; /usr/sbin/lsof -nP -iTCP -sTCP:LISTEN -iUDP 2>/dev/null || true; t=/Applications/Tailscale.app/Contents/MacOS/Tailscale; command -v tailscale >/dev/null 2>&1 && t=$(command -v tailscale); printf '__MYCELIUM_TAILSCALE__\\n'; \"$t\" status --json 2>/dev/null || true; printf '\\n__MYCELIUM_TAILSCALE_PREFS__\\n'; \"$t\" debug prefs 2>/dev/null || true; printf '\\n__MYCELIUM_MDNS__\\n'; if [ -x /usr/bin/dns-sd ] && [ -x /usr/bin/perl ]; then for type in _http._tcp _https._tcp _ssh._tcp _airplay._tcp _raop._tcp _googlecast._tcp _hap._tcp _ipp._tcp _printer._tcp _workstation._tcp; do /usr/bin/perl -e '$SIG{ALRM}=sub{kill 2,$p if $p; exit}; $p=fork(); if(!$p){exec @ARGV} alarm 3; wait' /usr/bin/dns-sd -Z \"$type\" local. & done; wait; fi; printf '\\n__MYCELIUM_SSDP__\\n'; if command -v nc >/dev/null 2>&1; then for iface in $(/sbin/ifconfig -l); do case \"$iface\" in en[0-9]*|bridge[0-9]*) ;; *) continue ;; esac; addr=$(/sbin/ifconfig \"$iface\" 2>/dev/null | awk '$1 == \"inet\" && $2 !~ /^127\\./ { print $2; exit }'); [ -n \"$addr\" ] || continue; printf '__MYCELIUM_SSDP_PROBE__\\t%s\\t%s\\n' \"$iface\" \"$addr\"; printf 'M-SEARCH * HTTP/1.1\\r\\nHOST: 239.255.255.250:1900\\r\\nMAN: \"ssdp:discover\"\\r\\nMX: 2\\r\\nST: ssdp:all\\r\\n\\r\\n' | nc -4 -u -s \"$addr\" -w 3 239.255.255.250 1900 2>/dev/null || true; done; fi";

pub struct DarwinDriver {
    timeout: Duration,
}

impl Default for DarwinDriver {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(8),
        }
    }
}

pub struct DarwinDevice {
    session: SshSession,
    meta: DeviceMeta,
    site: String,
}

async fn identity(session: &SshSession) -> Result<(String, String)> {
    let out = session
        .exec("printf '%s\\n' \"$(hostname -s)\" \"$(uname -srm)\" \"$(sw_vers -productVersion 2>/dev/null)\"")
        .await?;
    if !out.success() {
        return Err(MyceliumError::Device {
            exit_code: out.exit_code,
            stderr: out.stderr,
        });
    }
    let mut lines = out.stdout.lines();
    let hostname = lines.next().unwrap_or_default().trim().to_owned();
    let uname = lines.next().unwrap_or_default().trim();
    let version = lines.next().unwrap_or_default().trim();
    if hostname.is_empty() || !uname.starts_with("Darwin ") {
        return Err(MyceliumError::Validation(
            "SSH target is not a recognizable Darwin host".into(),
        ));
    }
    let model = if version.is_empty() {
        uname.to_owned()
    } else {
        format!("macOS {version} ({uname})")
    };
    Ok((hostname, model))
}

#[async_trait]
impl Driver for DarwinDriver {
    fn name(&self) -> &str {
        DRIVER_NAME
    }

    async fn recognizes(&self, target: &Target, creds: &CredentialSet) -> Result<bool> {
        let session =
            SshSession::connect_target(target, creds, self.timeout, "darwin observer").await?;
        Ok(identity(&session).await.is_ok())
    }

    async fn attach(
        &self,
        target: &Target,
        creds: &CredentialSet,
        inventory: &Inventory,
    ) -> Result<DeviceId> {
        let endpoint = host_target(target, 22, "darwin observer")?;
        let session =
            SshSession::connect_target(target, creds, self.timeout, "darwin observer").await?;
        let (hostname, model) = identity(&session).await?;
        let slug = stable_slug(&hostname);
        let meta = DeviceMeta {
            id: DeviceId::new(format!("darwin-{slug}")),
            kind: DeviceKind::Other,
            driver: DRIVER_NAME.into(),
            vendor: Some("Apple".into()),
            model: Some(model),
            firmware: None,
            address: endpoint.host.to_owned(),
        };
        let id = meta.id.clone();
        inventory.add(Arc::new(DarwinDevice {
            session,
            meta,
            site: hostname.to_lowercase(),
        }));
        Ok(id)
    }
}

#[async_trait]
impl Device for DarwinDevice {
    fn meta(&self) -> &DeviceMeta {
        &self.meta
    }

    fn capabilities(&self) -> BTreeMap<String, CapSpec> {
        BTreeMap::from([(
            ID_IDENTIFY.into(),
            CapSpec::readonly("Darwin/macOS SSH vantage-point identity"),
        )])
    }

    async fn exec(&self, _ctx: &ExecContext, cap: &str, _params: Params) -> Result<CapResult> {
        match cap {
            ID_IDENTIFY => Ok(CapResult::ok(Value::Map(Params::from_iter([
                ("vendor".into(), Value::Str("Apple".into())),
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
            other => Err(MyceliumError::Unsupported {
                device: self.meta.id.to_string(),
                capability: other.into(),
            }),
        }
    }

    async fn observe(&self) -> Result<(Vec<Observation>, Vec<String>)> {
        let raw = self.session.exec(OBSERVE_COMMAND).await?;
        if !raw.success() {
            return Err(MyceliumError::Device {
                exit_code: raw.exit_code,
                stderr: raw.stderr,
            });
        }
        let sections = split_sections(&raw.stdout)?;
        let mut interfaces = parse_interfaces(sections[0]);
        parse_hardware_ports(sections[1], &mut interfaces);
        let primary_mac = interfaces
            .iter()
            .find(|interface| {
                interface.name.starts_with("en")
                    && interface.addresses.iter().any(|(address, _)| {
                        matches!(address, std::net::IpAddr::V4(address) if address.is_private())
                    })
            })
            .and_then(|interface| interface.mac);
        let origin =
            |source: &str| Origin::new(self.meta.id.to_string(), source).at_site(self.site.clone());
        let mut out = Vec::new();
        for interface in interfaces {
            for (address, prefix) in &interface.addresses {
                if let std::net::IpAddr::V4(address) = address {
                    if address.is_private() && prefix < &32 {
                        let mask = u32::MAX.checked_shl(32 - u32::from(*prefix)).unwrap_or(0);
                        let network = std::net::Ipv4Addr::from(u32::from(*address) & mask);
                        out.push(Observation::Segment {
                            segment: Segment {
                                id: format!("{network}/{prefix}"),
                                kind: SegmentKind::Lan,
                                subnet: Some((network.into(), *prefix)),
                                ..Segment::default()
                            },
                            origin: origin(&format!("ifconfig:{}", interface.name)),
                        });
                    }
                }
            }
            out.push(Observation::DevicePort {
                device: self.meta.id.to_string(),
                port: interface.name,
                mac: interface.mac.filter(|mac| Some(*mac) == primary_mac),
                ips: interface.addresses.into_iter().map(|(ip, _)| ip).collect(),
                state: if interface.up {
                    LinkState::Up
                } else {
                    LinkState::Down
                },
                medium: Some(interface.medium),
                speed_mbps: interface.speed_mbps,
                duplex: interface.duplex,
                origin: origin("ifconfig"),
            });
        }
        for neighbor in parse_neighbors(sections[2]) {
            out.push(Observation::Neighbor {
                mac: Some(neighbor.mac),
                ip: neighbor.ip,
                hostname: None,
                port: Some(PortRef {
                    device: self.meta.id.to_string(),
                    port: neighbor.iface,
                    vif: None,
                }),
                origin: origin("arp"),
            });
        }
        let observed_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        for listener in parse_listeners(sections[3]) {
            out.push(Observation::Service {
                device: self.meta.id.to_string(),
                mac: None,
                ip: None,
                service: ServiceRecord {
                    name: listener.process.clone().unwrap_or_else(|| "unknown".into()),
                    transport: listener.transport,
                    port: listener.port,
                    product: listener.process,
                    state: ServiceState::Up,
                    observed_at,
                    host_local: listener.host_local,
                    origin: origin("lsof-listen"),
                },
            });
        }
        let mut warnings = Vec::new();
        let control_plane = match parse_control_plane(sections[5]) {
            Ok(value) => value,
            Err(error) => {
                warnings.push(format!("tailscale preferences: {error}"));
                Default::default()
            }
        };
        match parse_status(sections[4]) {
            Ok(status) => out.extend(topology_observations(
                status,
                control_plane,
                &self.meta.id.to_string(),
                &self.site,
                observed_at,
            )),
            Err(error) => warnings.push(format!("tailscale status: {error}")),
        }
        out.extend(
            parse_dns_sd_zone(sections[6], observed_at)
                .into_iter()
                .map(|advertisement| Observation::ServiceAdvertisement {
                    advertisement,
                    origin: origin("dns-sd"),
                }),
        );
        out.extend(
            parse_ssdp_probes(sections[7], observed_at)
                .into_iter()
                .map(|advertisement| Observation::ServiceAdvertisement {
                    advertisement,
                    origin: origin("ssdp-m-search"),
                }),
        );
        Ok((out, warnings))
    }
}

fn split_sections(text: &str) -> Result<[&str; 8]> {
    let (_, after_interfaces) = text
        .split_once("__MYCELIUM_IFCONFIG__\n")
        .ok_or_else(|| MyceliumError::Parse("missing ifconfig marker".into()))?;
    let (interfaces, after_ports) = after_interfaces
        .split_once("__MYCELIUM_HARDWARE_PORTS__\n")
        .ok_or_else(|| MyceliumError::Parse("missing hardware ports marker".into()))?;
    let (ports, after_arp) = after_ports
        .split_once("__MYCELIUM_ARP__\n")
        .ok_or_else(|| MyceliumError::Parse("missing arp marker".into()))?;
    let (arp, after_services) = after_arp
        .split_once("__MYCELIUM_SERVICES__\n")
        .ok_or_else(|| MyceliumError::Parse("missing services marker".into()))?;
    let (services, after_tailscale) = after_services
        .split_once("__MYCELIUM_TAILSCALE__\n")
        .ok_or_else(|| MyceliumError::Parse("missing tailscale marker".into()))?;
    let (tailscale, prefs_and_mdns) = after_tailscale
        .split_once("__MYCELIUM_TAILSCALE_PREFS__\n")
        .ok_or_else(|| MyceliumError::Parse("missing tailscale preferences marker".into()))?;
    let (prefs, mdns_and_ssdp) = prefs_and_mdns
        .split_once("__MYCELIUM_MDNS__\n")
        .ok_or_else(|| MyceliumError::Parse("missing mDNS marker".into()))?;
    let (mdns, ssdp) = mdns_and_ssdp
        .split_once("__MYCELIUM_SSDP__\n")
        .ok_or_else(|| MyceliumError::Parse("missing SSDP marker".into()))?;
    Ok([
        interfaces, ports, arp, services, tailscale, prefs, mdns, ssdp,
    ])
}
