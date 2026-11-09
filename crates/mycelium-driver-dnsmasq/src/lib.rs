//! DNS is optional and replaceable. This adapter manages dnsmasq, not a new DNS server.
//! macOS activation is scoped to a suffix; DHCP/default DNS remain router policy.
use fpl_resource_observation::ServiceCatalog;
use mycelium_core::{
    ActionRisk, CapResult, CapSpec, Device, DeviceId, DeviceKind, DeviceMeta, ExecContext,
    MyceliumError, Params,
};
use mycelium_dns_policy::resolver::{usable_address, ResolverConfig, ResolverMode};
use mycelium_dns_policy::{canonical_domain, DnsRecord};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::Read,
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

const LABEL: &str = "dev.fpl.mycelium-dns";
const MARKER: &str = "# Managed by Mycelium DNS resolver\n";
fn mesh_sites_default() -> bool {
    true
}
mod linux;
mod linux_namespace;
mod service_address;
mod service_dns;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Settings {
    pub resolver: ResolverConfig,
    pub dnsmasq: PathBuf,
    pub mycelium: PathBuf,
    /// Explicit reachable address scopes; do not publish every remote private IP.
    pub reachable_prefixes: Vec<String>,
    /// Derive remote sites from fresh authenticated daemon peers. DNS is not a grant.
    #[serde(default = "mesh_sites_default")]
    pub mesh_sites: bool,
    /// Explicitly reviewed sites from peer identities; no site aliasing.
    #[serde(default)]
    pub additional_sites: Vec<String>,
    pub refresh_seconds: u64,
    pub expiry_seconds: u64,
    /// Opt-in application kind -> DNS service label. Only fresh owner leases
    /// qualify; scanned listeners never become browser entrances implicitly.
    #[serde(default)]
    pub service_aliases: BTreeMap<String, String>,
    /// Explicit reviewed Lua naming policies; disabled when empty.
    #[serde(default)]
    pub service_alias_plugins: Vec<PathBuf>,
    /// Explicit index owner. Root aliases never select an arbitrary discovered peer.
    #[serde(default)]
    pub service_index_peers: BTreeMap<String, String>,
}

impl Settings {
    fn admits_site(&self, site: &str) -> bool {
        self.mesh_sites
            || site == self.resolver.site
            || self.additional_sites.iter().any(|s| s == site)
    }

    fn render(&self, records: Vec<DnsRecord>) -> Result<String, String> {
        let mut sites: BTreeSet<String> = self.additional_sites.iter().cloned().collect();
        for record in &records {
            if !self.admits_site(&record.site) {
                return Err("DNS record outside site policy".into());
            }
            if record.site != self.resolver.site {
                sites.insert(record.site.clone());
            }
        }
        // Lists are read where the policy is applied, so the files stay the
        // only source of truth; a failed read fails the render.
        let blocks = self.resolver.blocks()?;
        self.resolver
            .render_with(records, &sites.into_iter().collect::<Vec<_>>(), &blocks)
    }
    fn validate(&self) -> Result<(), String> {
        let aliases = service_dns::aliases(self)?;
        if self.service_index_peers.len() > 32
            || self.service_index_peers.iter().any(|(kind, peer)| {
                !aliases.contains_key(kind)
                    || peer.is_empty()
                    || peer.len() > 128
                    || peer.chars().any(char::is_control)
            })
        {
            return Err("invalid service index peer identity".into());
        }
        self.resolver
            .render_with(vec![], &self.additional_sites, &self.resolver.blocks()?)?;
        if !self.dnsmasq.is_absolute() || !self.mycelium.is_absolute() {
            return Err("binary paths must be absolute".into());
        }
        if !(10..=3600).contains(&self.refresh_seconds)
            || !(30..=3600).contains(&self.expiry_seconds)
            || self.refresh_seconds > self.expiry_seconds
        {
            return Err("invalid refresh/expiry interval".into());
        }
        if self.reachable_prefixes.is_empty()
            || self.reachable_prefixes.len() > 64
            || self
                .reachable_prefixes
                .iter()
                .any(|s| mycelium_core::parse_cidr(s).is_none())
        {
            return Err("provide 1..64 valid reachable prefixes".into());
        }
        Ok(())
    }
}

/// Inputs for a generated resolver configuration. Every field is either the
/// node's own identity or a reviewed route; nothing here is inferred from a
/// default that could silently widen what the resolver publishes.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InitOptions {
    pub site: String,
    pub suffix: String,
    pub reachable_prefixes: Vec<String>,
    #[serde(default)]
    pub service_address: Option<mycelium_dns_policy::FleetDnsAddress>,
    #[serde(default)]
    pub listen: Vec<SocketAddr>,
    #[serde(default)]
    pub dnsmasq: Option<PathBuf>,
    #[serde(default)]
    pub mycelium: Option<PathBuf>,
    /// Forward non-`.myc` names over DoH instead of plaintext upstreams.
    #[serde(default)]
    pub doh: Option<mycelium_dns_policy::resolver::DohUpstream>,
}

fn default_dnsmasq() -> Result<PathBuf, String> {
    for candidate in [
        "/usr/sbin/dnsmasq",
        "/opt/homebrew/sbin/dnsmasq",
        "/usr/local/sbin/dnsmasq",
        "/usr/bin/dnsmasq",
    ] {
        let path = Path::new(candidate);
        if path.is_file() {
            return Ok(path.to_path_buf());
        }
    }
    Err("dnsmasq was not found at a known path".into())
}

/// Write the resolver policy for this node. An existing file is never
/// replaced without `force`: policy review is a human step, and a second
/// repair must not quietly change what the resolver publishes.
pub fn init(path: &Path, options: InitOptions, force: bool) -> Result<Value, String> {
    if fs::symlink_metadata(path).is_ok() && !force {
        return Err(format!(
            "{} already exists; refusing to replace reviewed DNS policy",
            path.display()
        ));
    }
    let settings = Settings {
        resolver: ResolverConfig {
            mode: ResolverMode::LocalhostOnly,
            site: options.site,
            suffix: options.suffix,
            // Port 53 needs root on both platforms. The resolver is a user
            // service and the OS wiring carries the port, so default to an
            // unprivileged one and let an operator ask for 53 explicitly.
            listen: if options.listen.is_empty() {
                vec!["127.0.0.1:5335".parse().expect("static listener")]
            } else {
                options.listen
            },
            upstreams: vec![],
            service_address: options.service_address,
            delegations: vec![],
            namespace_owners: BTreeMap::new(),
            blocklists: vec![],
            block_action: mycelium_dns_policy::BlockAction::default(),
            allowlist: vec![],
            doh: options.doh,
        },
        dnsmasq: match options.dnsmasq {
            Some(path) => path,
            None => default_dnsmasq()?,
        },
        mycelium: match options.mycelium {
            Some(path) => path,
            None => std::env::current_exe().map_err(|error| error.to_string())?,
        },
        reachable_prefixes: options.reachable_prefixes,
        mesh_sites: true,
        additional_sites: vec![],
        refresh_seconds: 30,
        expiry_seconds: 300,
        service_aliases: BTreeMap::new(),
        service_alias_plugins: Vec::new(),
        service_index_peers: BTreeMap::new(),
    };
    settings.validate()?;
    atomic_write(
        path,
        &serde_json::to_vec_pretty(&settings).map_err(|error| error.to_string())?,
    )?;
    Ok(json!({
        "config": path,
        "mode": "localhost-only",
        "site": settings.resolver.site,
        "suffix": settings.resolver.suffix,
        "listen": settings.resolver.listen,
        "reachable_prefixes": settings.reachable_prefixes,
        "service_address": settings.resolver.service_address,
        "default_dns_changed": false
    }))
}

fn failure(message: impl ToString) -> MyceliumError {
    MyceliumError::Validation(message.to_string())
}

/// Fold a step's report into the capability result instead of nesting it.
fn merge(target: &mut Value, extra: Value) {
    if let (Some(object), Value::Object(extra)) = (target.as_object_mut(), extra) {
        object.extend(extra);
    }
}
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T, String> {
    let mut bytes = vec![];
    fs::File::open(path)
        .map_err(|e| e.to_string())?
        .take(65537)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() > 65536 {
        return Err("configuration exceeds 64 KiB".into());
    }
    serde_json::from_slice(&bytes).map_err(|e| format!("invalid configuration: {e}"))
}
fn home() -> Result<PathBuf, String> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or("HOME is not set".into())
}
fn state_dir() -> Result<PathBuf, String> {
    Ok(home()?.join(".mycelium/dns"))
}
fn atomic_write(path: &Path, bytes: &[u8]) -> Result<(), String> {
    if fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_symlink()) {
        return Err(format!("refusing symlink {}", path.display()));
    }
    let parent = path.parent().ok_or("file needs parent")?;
    fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    let temporary = path.with_extension(format!("pending-{}", std::process::id()));
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let result = (|| {
        use std::io::Write;
        let mut file = options.open(&temporary).map_err(|e| e.to_string())?;
        file.write_all(bytes).map_err(|e| e.to_string())?;
        file.sync_all().map_err(|e| e.to_string())?;
        fs::rename(&temporary, path).map_err(|e| e.to_string())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn in_prefix(address: IpAddr, prefix: &str) -> bool {
    let Some((network, length)) = mycelium_core::parse_cidr(prefix) else {
        return false;
    };
    match (network, address) {
        (IpAddr::V4(n), IpAddr::V4(a)) => {
            let mask = if length == 0 {
                0
            } else {
                u32::MAX << (32 - length)
            };
            u32::from(n) & mask == u32::from(a) & mask
        }
        (IpAddr::V6(n), IpAddr::V6(a)) => {
            let mask = if length == 0 {
                0
            } else {
                u128::MAX << (128 - length)
            };
            u128::from(n) & mask == u128::from(a) & mask
        }
        _ => false,
    }
}

/// Adapt the daemon's JSON peer view, already subject to fleet authentication.
/// Expired identities cannot squat a name after re-enrollment. Competing live
/// owners fail closed instead of arbitrarily choosing an identity.
pub fn peer_records(
    settings: &Settings,
    peers: &Value,
    timestamp: u64,
) -> Result<Vec<DnsRecord>, String> {
    let peers = peers.as_array().ok_or("peers must be an array")?;
    let suffix = canonical_domain(&settings.resolver.suffix)?;
    let mut records = BTreeSet::new();
    let mut owners = BTreeMap::new();
    for peer in peers {
        let Some(hello) = peer.get("hello") else {
            continue;
        };
        let Some(peer_site) = hello["site"].as_str() else {
            continue;
        };
        if !settings.admits_site(peer_site) {
            continue;
        }
        let Some(seen) = peer["last_seen"].as_u64() else {
            continue;
        };
        if seen > timestamp + 30 || timestamp.saturating_sub(seen) > settings.expiry_seconds {
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
        let name = format!("{host}.{site}.{suffix}");
        // A configured delegation owns its subtree, even for authenticated peers.
        if settings
            .resolver
            .delegations
            .iter()
            .any(|d| name == d.zone || name.ends_with(&format!(".{}", d.zone)))
        {
            continue;
        }
        let Some(interfaces) = hello["interfaces"].as_array() else {
            continue;
        };
        for address in interfaces
            .iter()
            .filter_map(|i| i["addresses"].as_array())
            .flatten()
        {
            let Some(address) = address.as_str().and_then(|a| a.parse::<IpAddr>().ok()) else {
                continue;
            };
            if !usable_address(address)
                || !settings
                    .reachable_prefixes
                    .iter()
                    .any(|p| in_prefix(address, p))
            {
                continue;
            }
            if owners
                .insert(name.clone(), node.to_owned())
                .is_some_and(|owner| owner != node)
            {
                return Err(format!("competing live owners for {name}"));
            }
            records.insert(DnsRecord {
                name: name.clone(),
                address,
                site: peer_site.into(),
                node: node.into(),
            });
        }
    }
    Ok(records.into_iter().collect())
}

async fn observation(settings: &Settings) -> Result<(Vec<DnsRecord>, u64), String> {
    let resolved = service_dns::resolved(settings)?;
    let settings = &resolved;
    let mut command = tokio::process::Command::new(&settings.mycelium);
    command
        .args(["peers", "--names-only", "--json"])
        .kill_on_drop(true);
    let output = tokio::time::timeout(Duration::from_secs(10), command.output())
        .await
        .map_err(|_| "peer observation timed out")?
        .map_err(|e| e.to_string())?;
    if !output.status.success() {
        return Err("Mycelium peer observation failed".into());
    }
    if output.stdout.len() > 16 * 1024 * 1024 {
        return Err("peer response too large".into());
    }
    let peers: Value = serde_json::from_slice(&output.stdout).map_err(|e| e.to_string())?;
    let timestamp = now();
    let records = peer_records(settings, &peers, timestamp)?;
    let owners = records
        .iter()
        .map(|r| r.node.as_str())
        .collect::<BTreeSet<_>>();
    let deadline = peers
        .as_array()
        .ok_or("peers must be an array")?
        .iter()
        .filter(|p| {
            p["hello"]["node_id"]
                .as_str()
                .is_some_and(|id| owners.contains(id))
        })
        .filter_map(|p| p["last_seen"].as_u64())
        .map(|seen| seen.saturating_add(settings.expiry_seconds))
        .min()
        .unwrap_or(timestamp + settings.expiry_seconds);
    if service_dns::aliases(settings)?.is_empty() {
        return Ok((records, deadline));
    }
    Ok(with_service_observation(
        settings,
        records,
        service_observation(settings).await,
        timestamp,
        deadline,
    ))
}

async fn service_observation(settings: &Settings) -> Result<ServiceCatalog, String> {
    let mut command = tokio::process::Command::new(&settings.mycelium);
    command.args(["services", "--json"]).kill_on_drop(true);
    let output = tokio::time::timeout(Duration::from_secs(10), command.output())
        .await
        .map_err(|_| "service observation timed out")?
        .map_err(|e| e.to_string())?;
    if !output.status.success() || output.stdout.len() > 16 * 1024 * 1024 {
        return Err("Mycelium service observation failed or exceeded bounds".into());
    }
    serde_json::from_slice(&output.stdout).map_err(|_| "invalid service catalog".into())
}

fn with_service_observation(
    settings: &Settings,
    hosts: Vec<DnsRecord>,
    catalog: Result<ServiceCatalog, String>,
    timestamp: u64,
    deadline: u64,
) -> (Vec<DnsRecord>, u64) {
    match catalog.and_then(|catalog| {
        service_dns::project(settings, hosts.clone(), &catalog, timestamp, deadline)
    }) {
        Ok(result) => result,
        Err(error) => {
            // Never prolong a service lease or let optional discovery erase fresh
            // independently authenticated hosts. Invalid aliases are withdrawn.
            eprintln!("DNS degraded at {timestamp}: service aliases unavailable ({error}); retaining fresh host records until {deadline}");
            (hosts, deadline)
        }
    }
}
async fn observe(settings: &Settings) -> Result<Vec<DnsRecord>, String> {
    Ok(observation(settings).await?.0)
}

fn syntax(settings: &Settings, file: &Path) -> Result<(), String> {
    let output = Command::new(&settings.dnsmasq)
        .arg("--test")
        .arg(format!("--conf-file={}", file.display()))
        .output()
        .map_err(|e| e.to_string())?;
    if output.status.success() {
        Ok(())
    } else {
        Err(format!(
            "dnsmasq validation: {}",
            String::from_utf8_lossy(&output.stderr)
        ))
    }
}

/// Read-only postcondition: query a generated record and verify its actual RDATA.
pub fn verify(settings: &Settings, record: &DnsRecord) -> Result<(), String> {
    use std::net::UdpSocket;
    let server = settings
        .resolver
        .listen
        .iter()
        .find(|s| s.ip().is_loopback())
        .unwrap_or(&settings.resolver.listen[0]);
    let socket = UdpSocket::bind(if server.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    })
    .map_err(|e| e.to_string())?;
    socket.connect(server).map_err(|e| e.to_string())?;
    socket
        .set_read_timeout(Some(Duration::from_secs(2)))
        .map_err(|e| e.to_string())?;
    let id = (SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_nanos() as u16)
        .to_be_bytes();
    let mut query = vec![id[0], id[1], 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
    for label in record.name.split('.') {
        query.push(label.len() as u8);
        query.extend(label.as_bytes());
    }
    query.push(0);
    let kind = if record.address.is_ipv4() {
        1u16
    } else {
        28u16
    };
    query.extend(kind.to_be_bytes());
    query.extend([0, 1]);
    socket.send(&query).map_err(|e| e.to_string())?;
    let mut packet = [0u8; 4096];
    let size = socket.recv(&mut packet).map_err(|e| e.to_string())?;
    let packet = &packet[..size];
    if size < 12
        || packet[..2] != id
        || packet[2] & 0x80 == 0
        || packet[3] & 15 != 0
        || packet[2] & 2 != 0
    {
        return Err("invalid DNS verification response".into());
    }
    let mut offset = 12;
    for _ in 0..u16::from_be_bytes([packet[4], packet[5]]) {
        skip_name(packet, &mut offset)?;
        offset += 4;
    }
    let expected = match record.address {
        IpAddr::V4(a) => a.octets().to_vec(),
        IpAddr::V6(a) => a.octets().to_vec(),
    };
    for _ in 0..u16::from_be_bytes([packet[6], packet[7]]) {
        skip_name(packet, &mut offset)?;
        let header = packet
            .get(offset..offset + 10)
            .ok_or("truncated DNS answer")?;
        let answer_kind = u16::from_be_bytes([header[0], header[1]]);
        let class = u16::from_be_bytes([header[2], header[3]]);
        let length = u16::from_be_bytes([header[8], header[9]]) as usize;
        offset += 10;
        let data = packet
            .get(offset..offset + length)
            .ok_or("truncated DNS data")?;
        if answer_kind == kind && class == 1 && data == expected {
            return Ok(());
        }
        offset += length;
    }
    Err("DNS response lacks the expected address".into())
}
fn skip_name(packet: &[u8], offset: &mut usize) -> Result<(), String> {
    loop {
        let length = *packet.get(*offset).ok_or("truncated DNS name")?;
        *offset += 1;
        if length == 0 {
            return Ok(());
        }
        if length & 0xc0 == 0xc0 {
            if packet.get(*offset).is_none() {
                return Err("truncated DNS pointer".into());
            }
            *offset += 1;
            return Ok(());
        }
        if length > 63 {
            return Err("invalid DNS label".into());
        }
        *offset += length as usize;
        if *offset > packet.len() {
            return Err("truncated DNS label".into());
        }
    }
}

fn xml(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}
fn launch_plist(executable: &Path, config: &Path, directory: &Path) -> String {
    let mut args = vec![executable.display().to_string()];
    if executable.file_name().and_then(|n| n.to_str()) == Some("mycelium") {
        args.extend(["dns".into(), "resolver".into()]);
    }
    args.extend([
        "run".into(),
        "--config".into(),
        config.display().to_string(),
        "--write".into(),
    ]);
    let args = args
        .iter()
        .map(|a| format!("<string>{}</string>", xml(a)))
        .collect::<String>();
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?><!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\"><plist version=\"1.0\"><dict><key>Label</key><string>{LABEL}</string><key>ProgramArguments</key><array>{args}</array><key>RunAtLoad</key><true/><key>KeepAlive</key><true/><key>ThrottleInterval</key><integer>15</integer><key>StandardOutPath</key><string>{}</string><key>StandardErrorPath</key><string>{}</string></dict></plist>",
        xml(&directory.join("resolver.log").display().to_string()),
        xml(&directory.join("resolver.log").display().to_string())
    )
}
fn gui_domain() -> Result<String, String> {
    let output = Command::new("id")
        .arg("-u")
        .output()
        .map_err(|e| e.to_string())?;
    let id = String::from_utf8_lossy(&output.stdout)
        .trim()
        .parse::<u32>()
        .map_err(|e| e.to_string())?;
    if id == 0 {
        return Err("apply must run as the logged-in user, not root".into());
    }
    Ok(format!("gui/{id}"))
}

fn owned_namespace(config: &ResolverConfig, remove: bool) -> Result<Value, String> {
    if !cfg!(target_os = "macos") {
        return Err("OS namespace activation currently supports macOS only".into());
    }
    let mut active = config.clone();
    if remove && active.mode == ResolverMode::Off {
        active.mode = ResolverMode::LocalhostOnly;
    }
    let (zone, text) = active.macos_namespace()?;
    let directory = Path::new("/etc/resolver");
    if fs::symlink_metadata(directory).is_ok_and(|m| m.file_type().is_symlink()) {
        return Err("refusing symlink resolver directory".into());
    }
    let path = directory.join(zone);
    if fs::symlink_metadata(&path).is_ok_and(|m| m.file_type().is_symlink()) {
        return Err("refusing symlink namespace file".into());
    }
    if path.exists()
        && !fs::read_to_string(&path)
            .map_err(|e| e.to_string())?
            .starts_with(MARKER)
    {
        return Err("namespace already owned by another resolver; unchanged".into());
    }
    if remove {
        if path.exists() {
            fs::remove_file(&path).map_err(|e| e.to_string())?;
        }
    } else {
        atomic_write(&path, text.as_bytes())?;
        // This contains public namespace routing, not credentials. macOS
        // resolver clients and the unprivileged status capability must read it.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o644))
                .map_err(|e| e.to_string())?;
        }
    }
    Ok(json!({"namespace":path,"installed":!remove,"default_dns_changed":false}))
}

pub struct ResolverDevice {
    settings: Settings,
    config: PathBuf,
    meta: DeviceMeta,
}
impl ResolverDevice {
    fn load(path: &Path) -> Result<Self, String> {
        let settings: Settings = read_json(path)?;
        settings.validate()?;
        Ok(Self {
            settings,
            config: fs::canonicalize(path).map_err(|e| e.to_string())?,
            meta: DeviceMeta {
                id: DeviceId::new("local-dns"),
                kind: DeviceKind::Other,
                driver: "dnsmasq".into(),
                vendor: None,
                model: None,
                firmware: None,
                address: "localhost".into(),
            },
        })
    }
}

impl ResolverDevice {
    /// dnsmasq cannot bind an address the host does not own, so apply is a
    /// precondition check rather than a silent half-start.
    fn require_service_address(&self) -> Result<(), String> {
        match self.settings.resolver.service_address {
            Some(service) if !service_address::installed(&service)? => Err(format!(
                "fleet DNS service address {} is not assigned to loopback; run `mycelium dns resolver system-install --config FILE` as root",
                service.address()
            )),
            _ => Ok(()),
        }
    }
}

#[async_trait::async_trait]
impl Device for ResolverDevice {
    fn meta(&self) -> &DeviceMeta {
        &self.meta
    }
    fn capabilities(&self) -> BTreeMap<String, CapSpec> {
        let mut caps = BTreeMap::new();
        caps.insert(
            "dns.resolver.status".into(),
            CapSpec::readonly("Query the generated record and report namespace activation"),
        );
        for cap in [
            "dns.resolver.apply",
            "dns.resolver.system-install",
            "dns.resolver.system-remove",
            "dns.resolver.run",
        ] {
            caps.insert(
                cap.into(),
                CapSpec::mutation("Manage optional local resolver")
                    .verified_by(ActionRisk::Disruptive, "dns.resolver.status"),
            );
        }
        caps
    }
    async fn exec(
        &self,
        ctx: &ExecContext,
        cap: &str,
        _params: Params,
    ) -> mycelium_core::Result<CapResult> {
        ctx.gate(cap != "dns.resolver.status")?;
        if ctx.dry_run {
            if cfg!(target_os = "linux")
                && matches!(
                    cap,
                    "dns.resolver.system-install" | "dns.resolver.system-remove"
                )
            {
                return Ok(CapResult::dry_run(mycelium_core::Value::from_json(
                    &linux_namespace::plan(&self.settings).map_err(failure)?,
                )));
            }
            return Ok(CapResult::dry_run(mycelium_core::Value::from_json(
                &serde_json::to_value(&self.settings).map_err(failure)?,
            )));
        }
        let value = match cap {
            "dns.resolver.status" => {
                let records = observe(&self.settings).await.map_err(failure)?;
                let first = records
                    .first()
                    .ok_or_else(|| failure("no fresh reachable peer records"))?;
                verify(&self.settings, first).map_err(failure)?;
                let (zone, expected) = self.settings.resolver.macos_namespace().map_err(failure)?;
                let blocks = self.settings.resolver.blocks().map_err(failure)?;
                json!({"mode":self.settings.resolver.mode,"verified_record":first,
                    "service_address_installed":(match self.settings.resolver.service_address {
                        Some(service) => service_address::installed(&service).map_err(failure)?,
                        None => false,
                    }),
                    "blocking":{"zones":blocks.len(),"skipped":blocks.skipped(),
                        "action":self.settings.resolver.block_action.as_str(),
                        "sources":blocks.sources(),"allowlist":blocks.allowlist().len()},
                    "namespace_installed":if cfg!(target_os="linux") { linux_namespace::installed(&self.settings) } else { fs::read_to_string(Path::new("/etc/resolver").join(zone)).is_ok_and(|s|s==expected) },"default_dns_changed":false})
            }
            "dns.resolver.system-install" => {
                let mut value = if cfg!(target_os = "linux") {
                    linux_namespace::apply(&self.settings, false)
                        .await
                        .map_err(failure)?
                } else {
                    owned_namespace(&self.settings.resolver, false).map_err(failure)?
                };
                if let Some(service) = self.settings.resolver.service_address {
                    merge(
                        &mut value,
                        service_address::ensure(&service).map_err(failure)?,
                    );
                }
                value
            }
            "dns.resolver.system-remove" => {
                let mut value = if cfg!(target_os = "linux") {
                    linux_namespace::apply(&self.settings, true)
                        .await
                        .map_err(failure)?
                } else {
                    owned_namespace(&self.settings.resolver, true).map_err(failure)?
                };
                if let Some(service) = self.settings.resolver.service_address {
                    merge(
                        &mut value,
                        service_address::remove(&service).map_err(failure)?,
                    );
                }
                value
            }
            "dns.resolver.apply" => {
                self.require_service_address().map_err(failure)?;
                apply(&self.settings, &self.config).await.map_err(failure)?
            }
            "dns.resolver.run" => {
                supervise(&self.settings).await.map_err(failure)?;
                json!({"stopped":true})
            }
            _ => return Err(MyceliumError::UnknownCapability(cap.into())),
        };
        Ok(CapResult::ok(mycelium_core::Value::from_json(&value)))
    }
}

async fn apply(settings: &Settings, _config: &Path) -> Result<Value, String> {
    if cfg!(target_os = "linux") {
        return linux::apply(settings).await;
    }
    if !cfg!(target_os = "macos") {
        return Err("persistent activation currently supports macOS only".into());
    }
    if settings.resolver.mode == ResolverMode::LanServing {
        return Err("LAN activation requires a verified client-network firewall policy; plan only in this slice".into());
    }
    let directory = state_dir()?;
    let plist = home()?.join(format!("Library/LaunchAgents/{LABEL}.plist"));
    let domain = gui_domain()?;
    if settings.resolver.mode == ResolverMode::Off {
        if Command::new("launchctl")
            .args(["print", &format!("{domain}/{LABEL}")])
            .output()
            .map_err(|e| e.to_string())?
            .status
            .success()
            && !Command::new("launchctl")
                .args(["bootout", &format!("{domain}/{LABEL}")])
                .status()
                .map_err(|e| e.to_string())?
                .success()
        {
            return Err("resolver stop failed; files retained".into());
        }
        if plist.exists() {
            fs::remove_file(&plist).map_err(|e| e.to_string())?;
        }
        return Ok(json!({"mode":"off","namespace_removal_required":true}));
    }
    let records = observe(settings).await?;
    if records.is_empty() {
        return Err("no fresh reachable records; refusing empty initial activation".into());
    }
    let candidate = directory.join("candidate.conf");
    atomic_write(&candidate, settings.render(records.clone())?.as_bytes())?;
    syntax(settings, &candidate)?;
    // Do not disrupt an unrelated process already listening on our socket.
    let print = Command::new("launchctl")
        .args(["print", &format!("{domain}/{LABEL}")])
        .output()
        .map_err(|e| e.to_string())?;
    if !print.status.success() {
        for listener in &settings.resolver.listen {
            std::net::UdpSocket::bind(listener)
                .map_err(|e| format!("listener unavailable: {e}"))?;
            std::net::TcpListener::bind(listener)
                .map_err(|e| format!("TCP listener unavailable: {e}"))?;
        }
    }
    if plist.exists()
        && !fs::read_to_string(&plist)
            .map_err(|e| e.to_string())?
            .contains(&format!("<string>{LABEL}</string>"))
    {
        return Err("existing launch agent has another owner".into());
    }
    let old = fs::read(&plist).ok();
    let stored = directory.join("active-settings.json");
    let old_settings = fs::read(&stored).ok();
    if print.status.success()
        && !Command::new("launchctl")
            .args(["bootout", &format!("{domain}/{LABEL}")])
            .status()
            .map_err(|e| e.to_string())?
            .success()
    {
        return Err("previous resolver stop failed; configuration unchanged".into());
    }
    atomic_write(
        &stored,
        &serde_json::to_vec(settings).map_err(|e| e.to_string())?,
    )?;
    atomic_write(
        &plist,
        launch_plist(
            &std::env::current_exe().map_err(|e| e.to_string())?,
            &stored,
            &directory,
        )
        .as_bytes(),
    )?;
    let status = Command::new("launchctl")
        .arg("bootstrap")
        .arg(&domain)
        .arg(&plist)
        .status()
        .map_err(|e| e.to_string())?;
    let mut verified = false;
    if status.success() {
        // Initial observation can consume two ten-second CLI deadlines before
        // dnsmasq starts. Allow that bounded work rather than false rollback.
        for _ in 0..60 {
            tokio::time::sleep(Duration::from_millis(500)).await;
            if verify(settings, &records[0]).is_ok() {
                verified = true;
                break;
            }
        }
    }
    if !verified {
        let _ = Command::new("launchctl")
            .args(["bootout", &format!("{domain}/{LABEL}")])
            .status();
        if let Some(old) = old {
            if let Some(old_settings) = old_settings {
                atomic_write(&stored, &old_settings)?;
            }
            atomic_write(&plist, &old)?;
            Command::new("launchctl")
                .arg("bootstrap")
                .arg(&domain)
                .arg(&plist)
                .status()
                .map_err(|e| e.to_string())?;
        } else {
            fs::remove_file(&plist).map_err(|e| e.to_string())?;
        }
        return Err("resolver postcondition failed; restored previous launch agent".into());
    }
    Ok(
        json!({"mode":settings.resolver.mode,"listening":settings.resolver.listen,
        "records":records.len(),"verified_record":records[0],"namespace_install_required":true,"default_dns_changed":false}),
    )
}

struct Running(Child);
impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
fn start(settings: &Settings, config: &Path) -> Result<Running, String> {
    Command::new(&settings.dnsmasq)
        .args(["--keep-in-foreground", "--pid-file="])
        .arg(format!("--conf-file={}", config.display()))
        .stdin(Stdio::null())
        .spawn()
        .map(Running)
        .map_err(|e| e.to_string())
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Retained {
    #[serde(default)]
    mesh_sites: bool,
    #[serde(default)]
    additional_sites: Vec<String>,
    site: String,
    suffix: String,
    records: Vec<DnsRecord>,
    expires_at: u64,
    #[serde(default)]
    service_aliases: BTreeMap<String, String>,
    #[serde(default)]
    service_index_peers: BTreeMap<String, String>,
}
impl Retained {
    fn usable(self, settings: &Settings, timestamp: u64) -> Result<(Vec<DnsRecord>, u64), String> {
        if self.site != settings.resolver.site
            || self.mesh_sites != settings.mesh_sites
            || self.additional_sites != settings.additional_sites
            || self.service_aliases != service_dns::aliases(settings)?
            || self.service_index_peers != settings.service_index_peers
            || self.suffix != settings.resolver.suffix
            || self.expires_at <= timestamp
            || self.expires_at > timestamp.saturating_add(settings.expiry_seconds)
            || self.records.iter().any(|r| {
                !settings.admits_site(&r.site)
                    || !usable_address(r.address)
                    || !settings
                        .reachable_prefixes
                        .iter()
                        .any(|p| in_prefix(r.address, p))
            })
        {
            return Err("retained DNS snapshot expired or outside current policy".into());
        }
        settings.render(self.records.clone())?;
        Ok((self.records, self.expires_at))
    }
}
fn retain(
    path: &Path,
    settings: &Settings,
    records: Vec<DnsRecord>,
    expires_at: u64,
) -> Result<(), String> {
    let retained = Retained {
        mesh_sites: settings.mesh_sites,
        additional_sites: settings.additional_sites.clone(),
        service_aliases: service_dns::aliases(settings)?,
        service_index_peers: settings.service_index_peers.clone(),
        site: settings.resolver.site.clone(),
        suffix: settings.resolver.suffix.clone(),
        records,
        expires_at,
    };
    atomic_write(
        path,
        &serde_json::to_vec(&retained).map_err(|e| e.to_string())?,
    )
}
async fn supervise(settings: &Settings) -> Result<(), String> {
    if settings.resolver.mode != ResolverMode::LocalhostOnly {
        return Err("supervisor currently activates localhost-only".into());
    }
    let directory = state_dir()?;
    let path = directory.join("dnsmasq.conf");
    let snapshot = directory.join("retained.json");
    let initial_settings = service_dns::resolved(settings)?;
    let (records, mut expires_at) = match observation(&initial_settings).await {
        Ok(result) => result,
        Err(error) => {
            eprintln!("DNS initial observation failed: {error}; checking retained state");
            match read_json::<Retained>(&snapshot).and_then(|s| s.usable(&initial_settings, now()))
            {
                Ok(result) => result,
                Err(error) => {
                    eprintln!("DNS retained state unavailable: {error}; serving no mesh addresses");
                    (vec![], now())
                }
            }
        }
    };
    // Bind before dnsmasq starts asking. A forwarder that cannot bind must
    // fail the supervisor rather than leave every non-.myc name unanswered.
    let forwarder = match &settings.resolver.doh {
        Some(doh) => {
            let forwarder = mycelium_doh::Forwarder::bind(doh).await?;
            Some(tokio::spawn(async move {
                if let Err(error) = forwarder.serve().await {
                    eprintln!("DNS DoH forwarder stopped: {error}");
                }
            }))
        }
        None => None,
    };
    let mut active = settings.render(records.clone())?;
    let mut active_aliases = initial_settings.service_aliases.clone();
    atomic_write(&path, active.as_bytes())?;
    syntax(settings, &path)?;
    let mut running = start(settings, &path)?;
    retain(&snapshot, &initial_settings, records, expires_at)?;
    #[cfg(unix)]
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .map_err(|e| e.to_string())?;
    loop {
        #[cfg(unix)]
        tokio::select! {
            _=tokio::time::sleep(Duration::from_secs(settings.refresh_seconds))=>{},
            _=terminate.recv()=>return Ok(()),
            _=tokio::signal::ctrl_c()=>return Ok(()),
        }
        #[cfg(not(unix))]
        tokio::time::sleep(Duration::from_secs(settings.refresh_seconds)).await;
        if let Some(status) = running.0.try_wait().map_err(|e| e.to_string())? {
            return Err(format!("dnsmasq exited: {status}"));
        }
        if forwarder
            .as_ref()
            .is_some_and(|handle| handle.is_finished())
        {
            return Err("DoH forwarder stopped; refusing to serve without an upstream".into());
        }
        // Re-evaluate reviewed local policy on each refresh. Invalid policy
        // fails closed; a changed policy cannot retain the previous DNS aliases.
        let next_settings = service_dns::resolved(settings)?;
        let next_aliases = next_settings.service_aliases.clone();
        #[cfg(unix)]
        let observed = tokio::select! {
            result=observation(&next_settings)=>result,
            _=terminate.recv()=>return Ok(()),
            _=tokio::signal::ctrl_c()=>return Ok(()),
        };
        #[cfg(not(unix))]
        let observed = observation(&next_settings).await;
        let (records, next_expiry) = match observed {
            Ok(result) => result,
            Err(error) => {
                eprintln!("DNS observation failed: {error}");
                if now() < expires_at && next_aliases == active_aliases {
                    continue;
                }
                eprintln!("Retained records expired; withdrawing mesh addresses");
                (vec![], now())
            }
        };
        let next = settings.render(records.clone())?;
        if next == active {
            active_aliases = next_aliases;
            expires_at = next_expiry;
            retain(&snapshot, &next_settings, records, expires_at)?;
            continue;
        }
        let candidate = directory.join("candidate.conf");
        atomic_write(&candidate, next.as_bytes())?;
        syntax(settings, &candidate)?;
        drop(running);
        atomic_write(&path, next.as_bytes())?;
        running = start(settings, &path)?;
        tokio::time::sleep(Duration::from_millis(250)).await;
        let healthy = running.0.try_wait().map_err(|e| e.to_string())?.is_none()
            && records
                .first()
                .is_none_or(|record| verify(settings, record).is_ok());
        if healthy {
            active_aliases = next_aliases;
            active = next;
            expires_at = next_expiry;
            retain(&snapshot, &next_settings, records, expires_at)?;
        } else {
            if next_aliases != active_aliases {
                return Err("DNS candidate failed after naming policy changed; refusing old policy rollback".into());
            }
            drop(running);
            atomic_write(&path, active.as_bytes())?;
            running = start(settings, &path)?;
            eprintln!("DNS refresh postcondition failed; previous configuration restored");
        }
    }
}

pub async fn command(args: &[String]) -> Result<String, String> {
    let action = args
        .first()
        .map(String::as_str)
        .ok_or("expected plan|init|apply|status|run|system-install|system-remove --config FILE")?;
    if !matches!(
        action,
        "plan" | "init" | "apply" | "status" | "run" | "system-install" | "system-remove"
    ) {
        return Err("unknown resolver action".into());
    }
    let mut config = None;
    let mut write = false;
    let mut dry_run = false;
    let mut force = false;
    let mut site = None;
    let mut suffix = None;
    let mut service_address: Option<mycelium_dns_policy::FleetDnsAddress> = None;
    let mut reachable = Vec::new();
    let mut listen = Vec::new();
    let mut dnsmasq = None;
    let mut mycelium = None;
    let mut doh_endpoint = None;
    let mut doh_listen: Option<SocketAddr> = None;
    let mut rest = args[1..].iter();
    let mut seen = BTreeSet::new();
    while let Some(flag) = rest.next() {
        // Route and listener lists are repeated by design.
        if !matches!(flag.as_str(), "--reachable" | "--listen") && !seen.insert(flag) {
            return Err("duplicate resolver option".into());
        }
        match flag.as_str() {
            "--config" => {
                config = Some(PathBuf::from(
                    rest.next().ok_or("--config requires a file")?,
                ))
            }
            "--write" => write = true,
            "--dry-run" => dry_run = true,
            "--force" if action == "init" => force = true,
            "--site" if action == "init" => {
                site = Some(rest.next().ok_or("--site requires a name")?.to_string())
            }
            "--suffix" if action == "init" => {
                suffix = Some(rest.next().ok_or("--suffix requires a domain")?.to_string())
            }
            "--service-address" if action == "init" => {
                service_address = Some(
                    rest.next()
                        .ok_or("--service-address requires a ULA CIDR")?
                        .parse()?,
                )
            }
            "--reachable" if action == "init" => reachable.push(
                rest.next()
                    .ok_or("--reachable requires a CIDR")?
                    .to_string(),
            ),
            "--listen" if action == "init" => listen.push(
                rest.next()
                    .ok_or("--listen requires an address")?
                    .parse()
                    .map_err(|_| "invalid --listen address".to_string())?,
            ),
            "--dnsmasq" if action == "init" => {
                dnsmasq = Some(PathBuf::from(
                    rest.next().ok_or("--dnsmasq requires a path")?,
                ))
            }
            "--mycelium" if action == "init" => {
                mycelium = Some(PathBuf::from(
                    rest.next().ok_or("--mycelium requires a path")?,
                ))
            }
            "--doh" if action == "init" => {
                doh_endpoint = Some(
                    rest.next()
                        .ok_or("--doh requires an https URL")?
                        .to_string(),
                )
            }
            "--doh-listen" if action == "init" => {
                doh_listen = Some(
                    rest.next()
                        .ok_or("--doh-listen requires an address")?
                        .parse()
                        .map_err(|_| "invalid --doh-listen address".to_string())?,
                )
            }
            _ => return Err("unknown resolver option".into()),
        }
    }
    let config = config.ok_or("--config is required")?;
    if action == "init" {
        let doh = match (doh_endpoint, doh_listen) {
            (Some(endpoint), listen) => Some(mycelium_dns_policy::resolver::DohUpstream {
                endpoint,
                listen: listen.unwrap_or_else(|| "127.0.0.1:5353".parse().expect("static")),
                timeout_seconds: 5,
                max_inflight: 8,
            }),
            (None, Some(_)) => return Err("--doh-listen requires --doh".into()),
            (None, None) => None,
        };
        let options = InitOptions {
            site: site.ok_or("dns resolver init requires --site")?,
            suffix: suffix.ok_or("dns resolver init requires --suffix")?,
            reachable_prefixes: reachable,
            service_address,
            listen,
            dnsmasq,
            mycelium,
            doh,
        };
        if dry_run {
            return Ok(json!({"dry_run": true, "config": config, "options": options}).to_string());
        }
        if !write {
            return Err("dns resolver init requires --write".into());
        }
        return Ok(init(&config, options, force)?.to_string());
    }
    let device = ResolverDevice::load(&config)?;
    if action == "plan" {
        let records = observe(&device.settings).await?;
        let blocks = device.settings.resolver.blocks()?;
        return Ok(
            json!({"mode":device.settings.resolver.mode,"records":records,
            "blocking":{"zones":blocks.len(),"skipped":blocks.skipped(),
                "action":device.settings.resolver.block_action.as_str(),
                "sources":blocks.sources(),"allowlist":blocks.allowlist().len()},
            "dnsmasq":device.settings.render(records.clone())?,
            "lan_activation_supported":false,"dhcp_changed":false})
            .to_string(),
        );
    }
    let cap = format!("dns.resolver.{action}");
    let result = device
        .invoke(
            &ExecContext {
                capability: cap.clone(),
                allow_writes: write,
                dry_run,
            },
            &cap,
            Params::new(),
        )
        .await
        .map_err(|e| e.to_string())?;
    Ok(result.output.to_json().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    pub(super) fn settings() -> Settings {
        Settings {
            mesh_sites: true,
            additional_sites: vec![],
            resolver: ResolverConfig {
                namespace_owners: Default::default(),
                mode: ResolverMode::LocalhostOnly,
                site: "lab".into(),
                suffix: "myc".into(),
                listen: vec!["127.0.0.1:1053".parse().unwrap()],
                service_address: None,
                upstreams: vec![],
                delegations: vec![],
                blocklists: vec![],
                block_action: mycelium_dns_policy::BlockAction::default(),
                allowlist: vec![],
                doh: None,
            },
            dnsmasq: "/bin/dnsmasq".into(),
            mycelium: "/bin/mycelium".into(),
            reachable_prefixes: vec!["192.0.2.0/24".into()],
            refresh_seconds: 30,
            expiry_seconds: 300,
            service_aliases: BTreeMap::new(),
            service_alias_plugins: Vec::new(),
            service_index_peers: BTreeMap::new(),
        }
    }
    fn peer(node: &str, seen: u64) -> Value {
        json!({"hello":{"node_id":node,"hostname":"gpu","site":"lab","interfaces":[{"addresses":["192.0.2.12","198.51.100.1","fe80::1"]}]},"last_seen":seen})
    }
    #[test]
    fn reviewed_remote_sites_preserve_signed_names_and_reachability() {
        let mut s = settings();
        s.mesh_sites = false;
        let mut remote = peer("remote", 999);
        remote["hello"]["site"] = json!("titan");
        assert!(peer_records(&s, &json!([remote.clone()]), 1000)
            .unwrap()
            .is_empty());
        s.additional_sites = vec!["titan".into()];
        let records = peer_records(&s, &json!([remote]), 1000).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].site, "titan");
        assert_eq!(records[0].name, "gpu.titan.myc");
        let rendered = s
            .resolver
            .render_for_sites(records.clone(), &s.additional_sites)
            .unwrap();
        assert!(rendered.contains("host-record=gpu.titan.myc,192.0.2.12"));
        assert!(!s
            .resolver
            .render(records)
            .unwrap()
            .contains("gpu.titan.myc"));
        s.additional_sites = vec!["*.myc".into()];
        assert!(s.validate().is_err());
    }
    #[test]
    fn mesh_sites_derive_names_without_configuration() {
        let s = settings();
        let mut remote = peer("remote", 999);
        remote["hello"]["site"] = json!("titan");
        let records = peer_records(&s, &json!([remote.clone()]), 1000).unwrap();
        assert_eq!(records.len(), 1); // Unreachable and link-local IPs remain excluded.
        assert!(s
            .render(records.clone())
            .unwrap()
            .contains("host-record=gpu.titan.myc,192.0.2.12"));
        assert!(peer_records(&s, &json!([remote.clone()]), 1400)
            .unwrap()
            .is_empty());
        let mut restricted = s.clone();
        restricted.mesh_sites = false;
        assert!(peer_records(&restricted, &json!([remote.clone()]), 1000)
            .unwrap()
            .is_empty());
        assert!(restricted.render(records).is_err());
        remote["hello"]["site"] = json!("fake.site");
        assert!(peer_records(&s, &json!([remote]), 1000).is_err());
        let mut config = serde_json::to_value(&s).unwrap();
        config.as_object_mut().unwrap().remove("mesh_sites");
        assert!(
            serde_json::from_value::<Settings>(config)
                .unwrap()
                .mesh_sites
        );
    }

    #[test]
    fn mesh_projection_respects_delegated_namespaces() {
        let mut s = settings();
        s.resolver
            .delegations
            .push(mycelium_dns_policy::Delegation {
                zone: "titan.myc".into(),
                site: "lab".into(),
                owner: "dns-owner".into(),
                server: "192.0.2.53".parse().unwrap(),
                port: 53,
            });
        let mut remote = peer("remote", 999);
        remote["hello"]["site"] = json!("titan");
        assert!(peer_records(&s, &json!([remote]), 1000).unwrap().is_empty());
        assert!(s.render(vec![]).unwrap().contains("server=/titan.myc/"));
    }

    #[test]
    fn unavailable_service_catalog_does_not_discard_or_extend_fresh_hosts() {
        let mut s = settings();
        s.service_aliases
            .insert("mycelium-host-web".into(), "mycelium".into());
        let hosts = peer_records(&s, &json!([peer("a", 999)]), 1000).unwrap();
        let (records, deadline) = with_service_observation(
            &s,
            hosts.clone(),
            Err("service observation timed out".into()),
            1000,
            1299,
        );
        assert_eq!(records, hosts);
        assert_eq!(deadline, 1299);
        assert!(records.iter().all(|r| !r.name.starts_with("mycelium.")));
        let (records, deadline) = with_service_observation(
            &s,
            hosts.clone(),
            serde_json::from_value(json!({"invalid":"catalog"})).map_err(|e| e.to_string()),
            1000,
            1299,
        );
        assert_eq!(records, hosts);
        assert_eq!(deadline, 1299);
        assert!(peer_records(&s, &json!([peer("a", 999)]), 1300)
            .unwrap()
            .is_empty());
    }

    #[test]
    fn fresh_scoped_addresses_and_expired_identity() {
        let records = peer_records(
            &settings(),
            &json!([peer("old", 1), peer("new", 999)]),
            1000,
        )
        .unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].node, "new");
        assert_eq!(records[0].name, "gpu.lab.myc");
    }
    #[test]
    fn competing_live_identity_fails_closed() {
        assert!(peer_records(&settings(), &json!([peer("a", 999), peer("b", 999)]), 1000).is_err());
    }
    #[test]
    fn settings_roundtrip_and_invalid_refresh() {
        let s = settings();
        let text = serde_json::to_string(&s).unwrap();
        let mut s: Settings = serde_json::from_str(&text).unwrap();
        s.validate().unwrap();
        s.refresh_seconds = 1;
        assert!(s.validate().is_err());
    }
    #[test]
    fn plist_escapes_paths_and_contains_no_shell() {
        let p = launch_plist(
            Path::new("/Users/A & B/mycelium"),
            Path::new("/tmp/config"),
            Path::new("/tmp/state"),
        );
        assert!(p.contains("A &amp; B"));
        assert!(p.contains("<string>resolver</string>"));
        assert!(!p.contains("/bin/sh"));
    }
    #[test]
    fn truncated_dns_names_fail_without_panicking() {
        for packet in [vec![0xc0], vec![4, 1], vec![64, 0], vec![]] {
            assert!(skip_name(&packet, &mut 0).is_err());
        }
    }
    #[test]
    fn retained_records_cannot_extend_expiry_or_cross_policy() {
        let s = settings();
        let records = peer_records(&s, &json!([peer("a", 999)]), 1000).unwrap();
        let mesh_sites = s.mesh_sites;
        let make = |expiry| Retained {
            mesh_sites,
            additional_sites: vec![],
            service_aliases: BTreeMap::new(),
            service_index_peers: BTreeMap::new(),
            site: "lab".into(),
            suffix: "myc".into(),
            records: records.clone(),
            expires_at: expiry,
        };
        assert!(make(1100).usable(&s, 1000).is_ok());
        assert!(make(1000).usable(&s, 1000).is_err());
        assert!(make(1301).usable(&s, 1000).is_err());
        let mut local_only = s.clone();
        local_only.mesh_sites = false;
        assert!(make(1100).usable(&local_only, 1000).is_err());
        let mut changed = s.clone();
        changed
            .service_aliases
            .insert("unibus-viewer".into(), "unibus".into());
        assert!(make(1100).usable(&changed, 1000).is_err());
        let mut s = s;
        s.reachable_prefixes = vec!["198.51.100.0/24".into()];
        assert!(make(1100).usable(&s, 1000).is_err());
    }
    #[test]
    fn verification_checks_address_not_only_success_rcode() {
        for correct in [true, false] {
            let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
            let mut s = settings();
            s.resolver.listen = vec![socket.local_addr().unwrap()];
            let server = std::thread::spawn(move || {
                let mut bytes = [0u8; 512];
                let (size, client) = socket.recv_from(&mut bytes).unwrap();
                let mut reply = bytes[..size].to_vec();
                reply[2] = 0x81;
                reply[3] = 0x80;
                reply[7] = 1;
                reply.extend([0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 30, 0, 4]);
                reply.extend(if correct {
                    [192, 0, 2, 12]
                } else {
                    [192, 0, 2, 13]
                });
                socket.send_to(&reply, client).unwrap();
            });
            let record = DnsRecord {
                name: "gpu.lab.myc".into(),
                address: "192.0.2.12".parse().unwrap(),
                site: "lab".into(),
                node: "a".into(),
            };
            assert_eq!(verify(&s, &record).is_ok(), correct);
            server.join().unwrap();
        }
    }
    #[tokio::test]
    async fn device_write_gate_runs_before_mutation() {
        let d = ResolverDevice {
            settings: settings(),
            config: "/missing".into(),
            meta: DeviceMeta {
                id: DeviceId::new("test"),
                kind: DeviceKind::Other,
                driver: "dnsmasq".into(),
                vendor: None,
                model: None,
                firmware: None,
                address: "localhost".into(),
            },
        };
        assert!(matches!(
            d.invoke(
                &ExecContext::readonly("dns.resolver.apply"),
                "dns.resolver.apply",
                Params::new()
            )
            .await,
            Err(MyceliumError::WritesNotPermitted(_))
        ));
        assert!(
            d.invoke(
                &ExecContext {
                    capability: "dns.resolver.apply".into(),
                    allow_writes: false,
                    dry_run: true
                },
                "dns.resolver.apply",
                Params::new()
            )
            .await
            .unwrap()
            .dry_run
        );
    }

    #[test]
    fn init_writes_reviewed_policy_and_refuses_to_replace_it() {
        let path = std::env::temp_dir().join(format!("resolver-init-{}.json", std::process::id()));
        let options = || InitOptions {
            site: "lab".into(),
            suffix: "myc".into(),
            reachable_prefixes: vec!["192.0.2.0/24".into()],
            service_address: None,
            listen: vec![],
            dnsmasq: Some("/bin/dnsmasq".into()),
            mycelium: Some("/bin/mycelium".into()),
            doh: None,
        };
        let _ = fs::remove_file(&path);
        let created = init(&path, options(), false).unwrap();
        assert_eq!(created["site"], "lab");
        let stored: Settings = read_json(&path).unwrap();
        assert_eq!(stored.resolver.mode, ResolverMode::LocalhostOnly);
        assert_eq!(stored.resolver.listen[0].to_string(), "127.0.0.1:5335");
        assert_eq!(stored.reachable_prefixes, ["192.0.2.0/24"]);
        // A repaired node must not silently widen what it publishes.
        assert!(init(&path, options(), false).is_err());
        assert!(init(&path, options(), true).is_ok());
        // Invalid input fails before anything is written.
        let mut bad = options();
        bad.reachable_prefixes = vec!["not-a-cidr".into()];
        assert!(init(&path, bad, true).is_err());
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn blocking_sources_render_into_the_config_and_never_shadow_the_namespace() {
        let mut settings = settings();
        let path = std::env::temp_dir().join(format!("driver-block-{}", std::process::id()));
        fs::write(&path, "0.0.0.0 ads.example.com\n||tracker.example.net^\n").unwrap();
        settings.resolver.blocklists =
            vec![mycelium_dns_policy::BlocklistSource { path: path.clone() }];
        settings.resolver.allowlist = vec!["example.org".into()];
        let recorded = DnsRecord {
            name: "neo.lab.myc".into(),
            address: "192.0.2.20".parse().unwrap(),
            site: "lab".into(),
            node: "neo".into(),
        };
        let text = settings.render(vec![recorded.clone()]).unwrap();
        assert!(text.contains("address=/ads.example.com/0.0.0.0\n"));
        assert!(text.contains("address=/ads.example.com/::\n"));
        assert!(text.contains("address=/tracker.example.net/0.0.0.0\n"));
        // Blocking never displaces an authoritative mesh name.
        assert!(text.contains("host-record=neo.lab.myc,192.0.2.20\n"));
        settings.resolver.block_action = mycelium_dns_policy::BlockAction::Nxdomain;
        let text = settings.render(vec![recorded.clone()]).unwrap();
        assert!(text.contains("local=/ads.example.com/\n"));
        assert!(!text.contains("address=/ads.example.com/"));
        // A mesh name in a list, and a list that is not a list, both stop the
        // render instead of being silently dropped.
        fs::write(&path, "node.lab.myc\n").unwrap();
        assert!(settings.render(vec![recorded.clone()]).is_err());
        fs::write(&path, "<html>rate limited</html>\n").unwrap();
        assert!(settings.render(vec![recorded]).is_err());
        let _ = fs::remove_file(&path);
    }
}
