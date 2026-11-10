use std::collections::BTreeMap;
use std::net::IpAddr;
use std::sync::OnceLock;

use async_trait::async_trait;
use mycelium_core::{
    CapResult, CapSpec, Device, DeviceMeta, DiscoveryProtocol, DiscoveryRequest, ExecContext,
    IntoValue, MacAddress, MyceliumError, Observation, Origin, ParamType, Params, Result, Value,
    VlanId,
};
use mycelium_core::{
    DhcpManagement, Identity, VlanManagement, ID_CAPABILITIES, ID_DHCP_ADD_STATIC_LEASE,
    ID_DHCP_ENSURE_POOL, ID_DHCP_LIST_POOLS, ID_IDENTIFY, ID_VLAN_ASSIGN, ID_VLAN_LIST,
};
use mycelium_ssdp::parse_responses as parse_ssdp_responses;

use crate::parsers::{parse_show_version, EdgeConfig};
use crate::transport::SshSession;

pub const DRIVER_NAME: &str = "edgeos";

/// Read-only command whose output carries hostname/version/config; the
/// daemon's inventory format and topology ingest both key off it.
pub const PRIMARY_COMMAND: &str = "show configuration commands";

fn caps() -> &'static BTreeMap<String, CapSpec> {
    static CAPS: OnceLock<BTreeMap<String, CapSpec>> = OnceLock::new();
    CAPS.get_or_init(|| {
        BTreeMap::from_iter([
            (
                ID_IDENTIFY.to_owned(),
                CapSpec::readonly("vendor/model/firmware/hostname as inferred from the device")
                    .returns("map: {vendor, model, firmware, hostname}"),
            ),
            (
                ID_CAPABILITIES.to_owned(),
                CapSpec::readonly("raw vyos `set` command list of this device").returns("string"),
            ),
            (
                ID_VLAN_LIST.to_owned(),
                CapSpec::readonly("configured VLANs with members, addresses, descriptions")
                    .returns("list of {id, name, subnet, members:[{port, tagged, address}]}"),
            ),
            (
                ID_VLAN_ASSIGN.to_owned(),
                CapSpec::mutation(
                    "attach a port to a VLAN (vyos: vif); creates the VLAN on this port",
                )
                .param("port", ParamType::Str, "physical port, e.g. eth1")
                .param("id", ParamType::Int, "802.1q VLAN id")
                .param("name", ParamType::Str, "VLAN/description label")
                .param("tagged", ParamType::Bool, "true=trunk vif, false=access")
                .param(
                    "address",
                    ParamType::Str,
                    "CIDR for this VLAN on this port, e.g. 10.0.35.1/24",
                ),
            ),
            (
                ID_DHCP_LIST_POOLS.to_owned(),
                CapSpec::readonly("dhcp-server shared networks, subnets, ranges, static leases")
                    .returns("list of {name, subnets:[{cidr, ranges, static-leases, ...}]}"),
            ),
            (
                ID_DHCP_ENSURE_POOL.to_owned(),
                CapSpec::mutation("ensure a DHCP pool matches declared network intent")
                    .param("pool", ParamType::Str, "shared-network name")
                    .param("subnet", ParamType::Str, "IPv4 subnet CIDR")
                    .param("gateway", ParamType::Str, "default router address")
                    .param("range_start", ParamType::Str, "first dynamic address")
                    .param("range_end", ParamType::Str, "last dynamic address")
                    .param(
                        "dns_servers",
                        ParamType::List,
                        "ordered DNS server addresses",
                    ),
            ),
            (
                ID_DHCP_ADD_STATIC_LEASE.to_owned(),
                CapSpec::mutation("reserve an address for a MAC in a dhcp pool")
                    .param("mac", ParamType::Str, "aa:bb:cc:dd:ee:ff")
                    .param("ip", ParamType::Str, "reserved address")
                    .param(
                        "pool",
                        ParamType::Str,
                        "shared-network-name; auto-detected from ip when omitted",
                    )
                    .param("name", ParamType::Str, "lease hostname"),
            ),
        ])
    })
}

/// Characters acceptable in vyos CLI tokens we interpolate. Anything else
/// is rejected before it ever reaches the shell string (no quoting games).
fn check_token(what: &str, v: &str) -> Result<()> {
    if v.is_empty()
        || !v
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || ".:-_/=@+".contains(c))
    {
        return Err(MyceliumError::Validation(format!(
            "`{what}` contains characters outside the vyos token set: {v:?}"
        )));
    }
    Ok(())
}

fn get_str(params: &Params, key: &str) -> Result<String> {
    let v = params
        .get(key)
        .and_then(|v| v.as_str())
        .ok_or_else(|| MyceliumError::Validation(format!("param `{key}` missing/not a string")))?
        .to_owned();
    check_token(key, &v)?;
    Ok(v)
}

fn get_optional_str(params: &Params, key: &str) -> Result<Option<String>> {
    match params.get(key) {
        None | Some(mycelium_core::Value::Null) => Ok(None),
        Some(v) => {
            let s = v
                .as_str()
                .ok_or_else(|| MyceliumError::Validation(format!("param `{key}` not a string")))?
                .to_owned();
            check_token(key, &s)?;
            Ok(Some(s))
        }
    }
}

pub struct EdgeOsDevice {
    session: SshSession,
    meta: DeviceMeta,
}

impl EdgeOsDevice {
    /// Identify over an already-connected session (used by the driver and
    /// by Lua plugins that borrow this transport).
    pub async fn identify(session: &SshSession) -> Result<(EdgeIdentity, EdgeConfig)> {
        let out = session
            .cli("show version")
            .await
            .map_err(|e| MyceliumError::Transport(format!("identify: {e}")))?;
        if !out.success() {
            return Err(MyceliumError::Device {
                exit_code: out.exit_code,
                stderr: out.stderr,
            });
        }
        let cfg_out = session.cli(PRIMARY_COMMAND).await?;
        if !cfg_out.success() {
            return Err(MyceliumError::Device {
                exit_code: cfg_out.exit_code,
                stderr: cfg_out.stderr,
            });
        }
        let version = parse_show_version(&out.stdout);
        let mut config = EdgeConfig::from_commands(&cfg_out.stdout);
        Ok((
            EdgeIdentity {
                vendor: version.vendor,
                model: version.model,
                firmware: version.firmware,
                hostname: config.hostname.take(),
            },
            config,
        ))
    }

    pub fn new(session: SshSession, meta: DeviceMeta) -> Self {
        Self { session, meta }
    }

    /// Execute a vyos config sequence. Honors dry_run (plans only) and
    /// scans output for `Error:` lines even when exit code is 0 — vyos
    /// famously exits 0 on config mistakes (fail loud, tenet #12).
    async fn run_config(&self, ctx: &ExecContext, cmds: Vec<String>) -> Result<CapResult> {
        if ctx.dry_run {
            return Ok(CapResult::dry_run(
                cmds.into_iter()
                    .map(|c| c.into_value())
                    .collect::<Vec<_>>()
                    .into_value(),
            ));
        }
        let mut script = String::from("configure\n");
        script.reserve(cmds.iter().map(|c| c.len() + 1).sum::<usize>() + 32);
        script.push_str(&cmds.join("\n"));
        script.push_str("\ndetect commit\nsave\nexit\n");
        let out = self.session.cli(&script).await?;
        let failed = !out.success() || line_error(&out.stdout).is_some();
        if failed {
            let detail = line_error(&out.stdout)
                .map(str::to_owned)
                .unwrap_or_else(|| format!("exit {}", out.exit_code));
            return Err(MyceliumError::Device {
                exit_code: out.exit_code,
                stderr: detail,
            });
        }
        Ok(CapResult::ok(Value::Str(out.stdout)))
    }

    async fn show(&self, command: &str) -> Result<String> {
        let out = self.session.cli(command).await?;
        if out.success() && line_error(&out.stdout).is_none() {
            Ok(out.stdout)
        } else {
            Err(MyceliumError::Device {
                exit_code: out.exit_code,
                stderr: line_error(&out.stdout)
                    .map(str::to_owned)
                    .unwrap_or_else(|| out.stderr.trim().to_owned()),
            })
        }
    }

    /// Raw `show …` passthrough for plugin transports and debugging.
    pub async fn show_raw(&self, command: &str) -> Result<String> {
        self.show(command).await
    }

    /// Topology facts as seen from this appliance, plus non-fatal scan
    /// warnings. The daemon pulls this on `mycelium scan`.
    async fn observations_impl(&self) -> Result<(Vec<mycelium_core::Observation>, Vec<String>)> {
        use mycelium_core::{
            LeaseRecord, LinkState, Observation, Origin, PortRef, Segment, SegmentKind,
        };
        let cfg_text = self.show(PRIMARY_COMMAND).await?;
        let arp_text = self.show("show arp").await;
        let mut warnings = Vec::new();
        let config = EdgeConfig::from_commands(&cfg_text);
        let me = self.meta.id.to_string();
        let mut out: Vec<Observation> = Vec::new();

        for vlan in config.vlans.values() {
            out.push(Observation::VlanMember {
                device: me.clone(),
                vlan: VlanId(vlan.id),
                members: vlan.members.iter().map(|m| m.port.clone()).collect(),
                origin: Origin::new(me.clone(), "config"),
            });
            if let Some((gw, pfx)) = vlan.address {
                out.push(Observation::Segment {
                    segment: Segment {
                        id: format!("vlan:{}", vlan.id),
                        kind: SegmentKind::Vlan,
                        vlan: Some(VlanId(vlan.id)),
                        subnet: Some((gw, pfx)),
                        gw: Some(gw),
                        domain_name: None,
                        origins: Default::default(),
                    },
                    origin: Origin::new(me.clone(), "config"),
                });
            }
        }

        for pool in &config.dhcp {
            for subnet in &pool.subnets {
                if let Some((addr, pfx)) = parse_cidr_str(&subnet.cidr) {
                    out.push(Observation::Segment {
                        segment: Segment {
                            id: subnet.cidr.clone(),
                            kind: match subnet.cidr.as_str() {
                                c if c.starts_with("10.0.0.") => SegmentKind::Wan,
                                _ if pool.name.to_lowercase().contains("wan") => SegmentKind::Wan,
                                _ => SegmentKind::Lan,
                            },
                            vlan: None,
                            subnet: Some((addr, pfx)),
                            gw: subnet.default_router,
                            domain_name: subnet.domain_name.clone(),
                            origins: Default::default(),
                        },
                        origin: Origin::new(me.clone(), "dhcp-config"),
                    });
                }
                for lease in &subnet.static_leases {
                    let Some(ip) = lease.ip else { continue };
                    out.push(Observation::Lease {
                        lease: LeaseRecord {
                            ip,
                            mac: lease.mac,
                            hostname: lease.name.clone(),
                            pool: Some(pool.name.clone()),
                            origin: Origin::new(me.clone(), "dhcp-config"),
                        },
                        origin: Origin::new(me.clone(), "dhcp-config"),
                    });
                    out.push(Observation::Neighbor {
                        mac: Some(lease.mac),
                        ip,
                        hostname: lease.name.clone(),
                        port: None,
                        origin: Origin::new(me.clone(), "dhcp-config"),
                    });
                }
            }
        }

        match arp_text {
            Ok(text) => {
                for e in crate::parsers::parse_arp_table(&text) {
                    out.push(Observation::Neighbor {
                        mac: Some(e.mac),
                        ip: e.ip,
                        hostname: None,
                        port: Some(PortRef {
                            device: me.clone(),
                            port: e.iface,
                            vif: None,
                        }),
                        origin: Origin::new(me.clone(), "arp"),
                    });
                }
            }
            Err(e) => {
                // degraded scan, not a crash: the daemon surfaces warnings.
                warnings.push(format!("arp table unavailable: {e}"));
            }
        }

        for (port, (addr, _pfx)) in &config.ports {
            out.push(Observation::DevicePort {
                device: me.clone(),
                port: port.clone(),
                mac: None,
                ips: vec![*addr],
                state: LinkState::Unknown,
                medium: None,
                speed_mbps: None,
                duplex: None,
                origin: Origin::new(me.clone(), "config"),
            });
        }

        Ok((out, warnings))
    }
}

fn parse_cidr_str(s: &str) -> Option<(IpAddr, u8)> {
    let (a, p) = s.split_once('/')?;
    Some((a.parse().ok()?, p.parse().ok()?))
}

pub struct EdgeIdentity {
    pub vendor: Option<String>,
    pub model: Option<String>,
    pub firmware: Option<String>,
    pub hostname: Option<String>,
}

fn line_error(text: &str) -> Option<&str> {
    text.lines()
        .map(|l| l.trim_start())
        .find(|l| l.starts_with("Error") || l.starts_with("ERROR"))
}

#[async_trait]
impl Device for EdgeOsDevice {
    fn meta(&self) -> &DeviceMeta {
        &self.meta
    }

    fn capabilities(&self) -> BTreeMap<String, CapSpec> {
        caps().clone()
    }

    async fn observe(&self) -> Result<(Vec<mycelium_core::Observation>, Vec<String>)> {
        self.observations_impl().await
    }

    async fn discover(&self, request: &DiscoveryRequest) -> Result<Vec<Observation>> {
        if request.protocol != DiscoveryProtocol::Ssdp {
            return Err(MyceliumError::Unsupported {
                device: self.id().to_string(),
                capability: format!("discovery.{:?}", request.protocol).to_ascii_lowercase(),
            });
        }
        let command = format!(
            "command -v nc >/dev/null 2>&1 && nc -h 2>&1 | grep -q -- '-u' || {{ echo 'UDP-capable nc unavailable' >&2; exit 127; }}; printf 'M-SEARCH * HTTP/1.1\\r\\nHOST: 239.255.255.250:1900\\r\\nMAN: \\\"ssdp:discover\\\"\\r\\nMX: 2\\r\\nST: ssdp:all\\r\\n\\r\\n' | nc -4 -u -s '{}' -w 3 239.255.255.250 1900",
            request.source
        );
        let output = self.session.exec(&command).await?;
        if !output.success() {
            return Err(MyceliumError::Device {
                exit_code: output.exit_code,
                stderr: output.stderr,
            });
        }
        let observed_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        Ok(parse_ssdp_responses(&output.stdout, observed_at)
            .into_iter()
            .map(|mut advertisement| {
                advertisement.interface = Some(request.segment.clone());
                Observation::ServiceAdvertisement {
                    advertisement,
                    origin: Origin::new(
                        self.id().to_string(),
                        format!("ssdp-m-search:{}", request.segment),
                    ),
                }
            })
            .collect())
    }

    async fn exec(&self, ctx: &ExecContext, cap: &str, params: Params) -> Result<CapResult> {
        match cap {
            ID_IDENTIFY => {
                let cfg = self.show(PRIMARY_COMMAND).await?;
                let config = EdgeConfig::from_commands(&cfg);
                let ver = parse_show_version(&self.show("show version").await?);
                let mut m = Params::new();
                m.insert("vendor".into(), ver.vendor.into_value());
                m.insert("model".into(), ver.model.into_value());
                m.insert("firmware".into(), ver.firmware.into_value());
                m.insert("hostname".into(), config.hostname.into_value());
                Ok(CapResult::ok(mycelium_core::Value::Map(m)))
            }
            ID_CAPABILITIES => {
                let text = self.show(PRIMARY_COMMAND).await?;
                Ok(CapResult::ok(text.into_value()))
            }
            ID_VLAN_LIST => {
                let cfg = self.show(PRIMARY_COMMAND).await?;
                let config = EdgeConfig::from_commands(&cfg);
                Ok(CapResult::ok(serde_json_to_value(
                    &config.vlans.values().collect::<Vec<_>>(),
                )?))
            }
            ID_VLAN_ASSIGN => {
                let port = get_str(&params, "port")?;
                let id = params
                    .get("id")
                    .and_then(|v| v.as_i64())
                    .filter(|i| (1..4095).contains(i))
                    .ok_or_else(|| {
                        MyceliumError::Validation("param `id` must be a VLAN id 1..4094".into())
                    })? as u16;
                let name = get_optional_str(&params, "name")?;
                let address = get_optional_str(&params, "address")?;
                let tagged = params
                    .get("tagged")
                    .map(|v| v.as_bool())
                    .unwrap_or(Some(true))
                    .unwrap_or(true);
                let base = format!("set interfaces ethernet {port} vif {id}");
                let mut cmds = vec![base.clone()];
                if let Some(name) = name {
                    cmds.push(format!("{base} description '{name}'"));
                }
                if let Some(address) = address {
                    parse_cidr_str(&address).ok_or_else(|| {
                        MyceliumError::Validation(format!("`address` must be CIDR, got {address}"))
                    })?;
                    cmds.push(format!("{base} address '{address}'"));
                }
                if !tagged {
                    cmds.push(format!("{base} mode access"));
                }
                self.run_config(ctx, cmds).await
            }
            ID_DHCP_LIST_POOLS => {
                let cfg = self.show(PRIMARY_COMMAND).await?;
                let config = EdgeConfig::from_commands(&cfg);
                Ok(CapResult::ok(serde_json_to_value(&config.dhcp)?))
            }
            ID_DHCP_ENSURE_POOL => {
                let pool = get_str(&params, "pool")?;
                let subnet = get_str(&params, "subnet")?;
                let gateway = get_str(&params, "gateway")?;
                let range_start = get_str(&params, "range_start")?;
                let range_end = get_str(&params, "range_end")?;
                check_token("pool", &pool)?;
                let (network, prefix) = parse_cidr_str(&subnet).ok_or_else(|| {
                    MyceliumError::Validation(format!("invalid DHCP subnet `{subnet}`"))
                })?;
                let parse_address = |name: &str, value: &str| -> Result<IpAddr> {
                    let address = value.parse::<IpAddr>().map_err(|_| {
                        MyceliumError::Validation(format!("invalid {name} address `{value}`"))
                    })?;
                    if !mycelium_core::ipv4_in_cidr(address, network, prefix) {
                        return Err(MyceliumError::Validation(format!(
                            "{name} address `{value}` is outside {subnet}"
                        )));
                    }
                    Ok(address)
                };
                let gateway = parse_address("gateway", &gateway)?;
                let range_start = parse_address("range_start", &range_start)?;
                let range_end = parse_address("range_end", &range_end)?;
                if u32::from(match range_start {
                    IpAddr::V4(value) => value,
                    _ => unreachable!(),
                }) > u32::from(match range_end {
                    IpAddr::V4(value) => value,
                    _ => unreachable!(),
                }) {
                    return Err(MyceliumError::Validation(
                        "DHCP range start must not exceed range end".into(),
                    ));
                }
                let dns_servers = params
                    .get("dns_servers")
                    .and_then(Value::as_list)
                    .ok_or_else(|| MyceliumError::Validation("dns_servers must be a list".into()))?
                    .iter()
                    .map(|value| {
                        value
                            .as_str()
                            .and_then(|value| value.parse::<IpAddr>().ok())
                            .ok_or_else(|| MyceliumError::Validation("invalid DNS server".into()))
                    })
                    .collect::<Result<Vec<_>>>()?;
                let base =
                    format!("set service dhcp-server shared-network-name {pool} subnet {subnet}");
                let mut commands = vec![
                    format!("{base} default-router '{gateway}'"),
                    format!("{base} range 0 start '{range_start}'"),
                    format!("{base} range 0 stop '{range_end}'"),
                ];
                commands.extend(
                    dns_servers
                        .into_iter()
                        .map(|server| format!("{base} name-server '{server}'")),
                );
                self.run_config(ctx, commands).await
            }
            ID_DHCP_ADD_STATIC_LEASE => {
                let mac_s = get_str(&params, "mac")?;
                let ip_s = get_str(&params, "ip")?;
                let name = get_optional_str(&params, "name")?;
                let requested_pool = get_optional_str(&params, "pool")?;
                let mac = MacAddress::parse(&mac_s)
                    .ok_or_else(|| MyceliumError::Validation(format!("invalid mac {mac_s}")))?;
                let ip: IpAddr = ip_s
                    .parse()
                    .map_err(|_| MyceliumError::Validation(format!("invalid ip {ip_s}")))?;
                let cfg = self.show(PRIMARY_COMMAND).await?;
                let config = EdgeConfig::from_commands(&cfg);

                let mut matches: Vec<(String, String)> = Vec::new(); // pool, cidr
                for pool in &config.dhcp {
                    for subnet in &pool.subnets {
                        let Some((net, pfx)) = parse_cidr_str(&subnet.cidr) else {
                            continue;
                        };
                        let in_pool = if subnet.static_leases.iter().any(|l| l.mac == mac) {
                            true
                        } else {
                            mycelium_core::ipv4_in_cidr(ip, net, pfx)
                        };
                        if in_pool {
                            matches.push((pool.name.clone(), subnet.cidr.clone()));
                        }
                    }
                }
                let (pool, cidr) = match requested_pool {
                    Some(p) => {
                        let cidr = matches
                            .iter()
                            .find(|(name, _)| *name == p)
                            .map(|(_, c)| c.clone())
                            .or_else(|| {
                                config
                                    .dhcp
                                    .iter()
                                    .find(|x| x.name == p)
                                    .and_then(|x| x.subnets.first())
                                    .map(|s| s.cidr.clone())
                            })
                            .ok_or_else(|| {
                                MyceliumError::Validation(format!(
                                    "no dhcp pool `{p}` on this device (known: {})",
                                    config
                                        .dhcp
                                        .iter()
                                        .map(|p| p.name.as_str())
                                        .collect::<Vec<_>>()
                                        .join(", ")
                                ))
                            })?;
                        (p, cidr)
                    }
                    None => match matches.len() {
                        0 => {
                            return Err(MyceliumError::Validation(format!(
                                "{ip} does not fall in any dhcp pool; specify `pool` (known: {})",
                                config
                                    .dhcp
                                    .iter()
                                    .map(|p| p.name.as_str())
                                    .collect::<Vec<_>>()
                                    .join(", ")
                            )))
                        }
                        1 => matches.pop().unwrap(),
                        n => {
                            return Err(MyceliumError::Validation(format!(
                                "{ip} matches {n} pools ({matches:?}); specify `pool`"
                            )))
                        }
                    },
                };
                let base = format!("set service dhcp-server shared-network-name {pool} subnet {cidr} static-mac {mac}");
                let mut cmds = vec![format!("{base} ip '{ip}'")];
                if let Some(name) = name {
                    cmds.push(format!("{base} name '{name}'"));
                }
                self.run_config(ctx, cmds).await
            }
            other => Err(MyceliumError::Unsupported {
                device: self.meta.id.to_string(),
                capability: other.to_owned(),
            }),
        }
    }
}

fn serde_json_to_value<T: serde::Serialize>(v: &T) -> Result<Value> {
    // through *plain* JSON via the Value<->serde_json bridge; the serde
    // derive form of mycelium Value is Rust-tagged and not the wire shape
    let j = serde_json::to_value(v).map_err(|e| MyceliumError::Parse(e.to_string()))?;
    Ok(Value::from_json(&j))
}

#[async_trait]
impl Identity for EdgeOsDevice {}

#[async_trait]
impl VlanManagement for EdgeOsDevice {
    async fn create_vlan(
        &self,
        ctx: &ExecContext,
        id: u16,
        name: Option<&str>,
    ) -> Result<CapResult> {
        // vyos truth: a VLAN exists per-port only; there is no global VLAN
        // object to create. Point the caller at the honest capability.
        let _ = (ctx, id, name);
        Err(MyceliumError::Validation(format!(
            "edgeos has no standalone vlan objects; use `{ID_VLAN_ASSIGN}` (port + id)"
        )))
    }
}

#[async_trait]
impl DhcpManagement for EdgeOsDevice {
    async fn add_static_lease(
        &self,
        ctx: &ExecContext,
        pool: &str,
        mac: &str,
        ip: &str,
        name: Option<&str>,
    ) -> Result<CapResult> {
        let mut params = Params::new();
        params.insert("mac".into(), mac.to_owned().into_value());
        params.insert("ip".into(), ip.to_owned().into_value());
        params.insert("pool".into(), pool.to_owned().into_value());
        if let Some(name) = name {
            params.insert("name".into(), name.to_owned().into_value());
        }
        self.invoke(ctx, ID_DHCP_ADD_STATIC_LEASE, params).await
    }
}
