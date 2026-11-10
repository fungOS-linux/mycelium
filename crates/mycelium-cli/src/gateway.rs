//! Local `.myc` HTTPS gateway lifecycle.
//!
//! The gateway itself is an ordinary loopback process that terminates TLS. This
//! module owns the parts that belong to the host: certificate material, route
//! defaults, launchd wiring, and the privileged-socket split.
use rcgen::{
    date_time_ymd, BasicConstraints, CertificateParams, DistinguishedName, DnType,
    ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose,
};
use serde_json::{json, Value};
use std::{
    fs,
    io::Write,
    net::{SocketAddr, TcpStream},
    path::{Path, PathBuf},
    process::Command,
    time::Duration,
};

const DEFAULT_GATEWAY_LISTEN: &str = "127.0.0.1:8443";
const HTTPS_ADDR: &str = "127.0.0.1:443";
const HTTPS_PORT: u16 = 443;
const GATEWAY_LABEL: &str = "dev.fpl.mycelium-gateway";
const HTTPS_LABEL: &str = "dev.fpl.mycelium-https";
const GATEWAY_UNIT: &str = "mycelium-gateway.service";
const HTTPS_SOCKET_UNIT: &str = "mycelium-https.socket";
const HTTPS_SERVICE_UNIT: &str = "mycelium-https.service";
const SYSTEM_CA_PATH: &str = "/usr/local/share/ca-certificates/mycelium-gateway.crt";

const USAGE: &str = "mycelium gateway status [--json] [--path MYCELIUM-HOME]\n\
mycelium gateway usage [--json] [--fleet] [--path MYCELIUM-HOME]\n\
mycelium gateway install [--write|--dry-run] [--trust-cert] [--listen ADDR] [--routes PATH] [--cert PATH --key PATH] [--gateway-bin PATH] [--forwarder-bin PATH] [--path MYCELIUM-HOME]\n\
mycelium gateway uninstall [--write|--dry-run] [--path MYCELIUM-HOME]";

#[derive(Clone, Debug)]
pub struct Paths {
    pub home: PathBuf,
    pub dir: PathBuf,
    pub routes: PathBuf,
    pub usage: PathBuf,
    pub cert: PathBuf,
    pub key: PathBuf,
    pub ca: PathBuf,
    pub gateway_bin: PathBuf,
    pub forwarder_bin: PathBuf,
    pub listen: SocketAddr,
}

impl Paths {
    pub fn discover(home: &Path) -> Self {
        let dir = home.join("gateway");
        let modern_cert = dir.join("server.pem");
        let modern_key = dir.join("server-key.pem");
        let legacy_cert = dir.join("server.crt");
        let legacy_key = dir.join("server.key");
        let (cert, key) = if modern_cert.is_file() || modern_key.is_file() {
            (modern_cert, modern_key)
        } else if legacy_cert.is_file() || legacy_key.is_file() {
            (legacy_cert, legacy_key)
        } else {
            (modern_cert, modern_key)
        };
        Self {
            home: home.to_path_buf(),
            dir,
            routes: home.join("gateway/routes.json"),
            usage: home.join("gateway/usage.json"),
            cert,
            key,
            ca: home.join("gateway/ca.pem"),
            gateway_bin: home.join("bin/mycelium-gateway"),
            forwarder_bin: home.join("bin/mycelium-https-forwarder"),
            listen: installed_listen().unwrap_or_else(default_listen),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Platform {
    Macos,
    Linux,
}

fn platform() -> Result<Platform, String> {
    if cfg!(target_os = "macos") {
        Ok(Platform::Macos)
    } else if cfg!(target_os = "linux") {
        Ok(Platform::Linux)
    } else {
        Err("the local gateway supports macOS launchd and Linux systemd only".into())
    }
}

pub fn supported_platform() -> Result<(), String> {
    platform().map(|_| ())
}

fn default_listen() -> SocketAddr {
    DEFAULT_GATEWAY_LISTEN
        .parse()
        .expect("default gateway listen address is valid")
}

fn https_listen() -> SocketAddr {
    HTTPS_ADDR.parse().expect("https listen address is valid")
}

fn listen_addr(value: &str) -> Result<SocketAddr, String> {
    let address: SocketAddr = value
        .parse()
        .map_err(|_| format!("listen address must be IP:PORT, got `{value}`"))?;
    if !address.ip().is_loopback() {
        return Err(format!("gateway must listen on loopback, got {address}"));
    }
    if address.port() == 0 || address.port() == HTTPS_PORT {
        return Err(format!(
            "gateway must not bind port {HTTPS_PORT}; the privileged socket belongs to the forwarder"
        ));
    }
    Ok(address)
}

/// The installed service definition is the single source of truth for the
/// gateway address, so reinstall/status keep using a custom `--listen`.
fn installed_listen() -> Option<SocketAddr> {
    let path = match platform() {
        Ok(Platform::Macos) => launch_agent_path(GATEWAY_LABEL).ok()?,
        Ok(Platform::Linux) => systemd_unit_path(GATEWAY_UNIT),
        Err(_) => return None,
    };
    parse_listen(&fs::read_to_string(path).ok()?)
}

fn parse_listen(text: &str) -> Option<SocketAddr> {
    let raw = if cfg!(target_os = "macos") {
        let marker = "<string>--listen</string><string>";
        text.split_once(marker)?.1.split_once("</string>")?.0
    } else {
        let mut value = None;
        for line in text.lines() {
            let Some(rest) = line.trim().strip_prefix("ExecStart=") else {
                continue;
            };
            let mut parts = rest.split_whitespace();
            while let Some(part) = parts.next() {
                if part == "--listen" {
                    value = parts.next();
                    break;
                }
            }
            if value.is_some() {
                break;
            }
        }
        value?
    };
    listen_addr(raw).ok()
}

#[derive(Clone, Copy)]
enum Service {
    Gateway,
    HttpsSocket,
}

impl Service {
    fn macos_label(self) -> &'static str {
        match self {
            Self::Gateway => GATEWAY_LABEL,
            Self::HttpsSocket => HTTPS_LABEL,
        }
    }

    fn linux_unit(self) -> &'static str {
        match self {
            Self::Gateway => GATEWAY_UNIT,
            Self::HttpsSocket => HTTPS_SOCKET_UNIT,
        }
    }

    fn path(self) -> Result<PathBuf, String> {
        match platform()? {
            Platform::Macos => launch_agent_path(self.macos_label()),
            Platform::Linux => Ok(systemd_unit_path(self.linux_unit())),
        }
    }

    fn installed(self) -> bool {
        self.path().is_ok_and(|path| path.is_file())
    }
}

fn systemd_unit_path(name: &str) -> PathBuf {
    Path::new("/etc/systemd/system").join(name)
}

#[derive(Clone, Debug)]
struct InstallOptions {
    home: PathBuf,
    routes: Option<PathBuf>,
    cert: Option<PathBuf>,
    key: Option<PathBuf>,
    gateway_bin: Option<PathBuf>,
    forwarder_bin: Option<PathBuf>,
    listen: Option<SocketAddr>,
    trust: bool,
    write: bool,
    dry_run: bool,
}

impl InstallOptions {
    fn new() -> Self {
        Self {
            home: myceliumd::home_dir(),
            routes: None,
            cert: None,
            key: None,
            gateway_bin: None,
            forwarder_bin: None,
            listen: None,
            trust: false,
            write: false,
            dry_run: false,
        }
    }
}

pub async fn run(args: &[String]) -> Result<Vec<String>, String> {
    let (action, rest) = match args.split_first() {
        Some((action, rest)) => (action.as_str(), rest),
        None => ("status", &[][..]),
    };
    match action {
        "status" | "" => status(rest).await,
        "usage" => usage(rest).await,
        "install" => install(rest).await,
        "uninstall" => uninstall(rest),
        "help" | "--help" | "-h" => Ok(USAGE.lines().map(str::to_owned).collect()),
        other => Err(format!(
            "unknown gateway action `{other}` (see `mycelium gateway --help`)"
        )),
    }
}

pub async fn status(args: &[String]) -> Result<Vec<String>, String> {
    let (home, json_output) = status_options(args)?;
    let value = snapshot(&home).await;
    if json_output {
        return Ok(vec![value.to_string()]);
    }
    Ok(render_status(&value))
}

/// Token usage recorded by the local gateway, or rolled up across the fleet from
/// the `mycelium_ai.*` platform metrics every daemon gossips.
async fn usage(args: &[String]) -> Result<Vec<String>, String> {
    let mut json_output = false;
    let mut fleet = false;
    let mut home = myceliumd::home_dir();
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--json" => json_output = true,
            "--fleet" => fleet = true,
            "--path" => {
                index += 1;
                home = expand_home(args.get(index).ok_or("--path requires a directory")?);
            }
            other => return Err(format!("unknown gateway usage argument `{other}`")),
        }
        index += 1;
    }
    if fleet {
        return fleet_usage(json_output).await;
    }
    let path = Paths::discover(&home).usage;
    let bytes = fs::read(&path).map_err(|error| {
        format!(
            "no token usage at {}: {error} (the gateway records usage while it runs)",
            path.display()
        )
    })?;
    let snapshot: mycelium_peer_protocol::gateway_usage::GatewayUsageSnapshot =
        serde_json::from_slice(&bytes)
            .map_err(|error| format!("read {}: {error}", path.display()))?;
    if snapshot.schema_version
        != mycelium_peer_protocol::gateway_usage::GATEWAY_USAGE_SCHEMA_VERSION
    {
        return Err(format!(
            "{} was written by a different gateway (schema {})",
            path.display(),
            snapshot.schema_version
        ));
    }
    if json_output {
        return Ok(vec![
            serde_json::to_string(&snapshot).map_err(|error| format!("encode usage: {error}"))?
        ]);
    }
    Ok(render_usage(&snapshot))
}

fn render_usage(
    snapshot: &mycelium_peer_protocol::gateway_usage::GatewayUsageSnapshot,
) -> Vec<String> {
    let totals = &snapshot.totals;
    let mut lines = vec![format!(
        "gateway ai usage (recorded {}, window {}s):",
        snapshot.generated_at, snapshot.window_seconds
    )];
    lines.push(format!(
        "  requests: {} (metered {}, unmetered {})",
        totals.requests,
        totals.metered_requests,
        totals.unmetered_requests()
    ));
    lines.push(format!(
        "  tokens: {} prompt, {} completion, {} cached",
        totals.prompt_tokens, totals.completion_tokens, totals.cached_tokens
    ));
    lines.push(format!(
        "  throughput: {:.2} tok/s now, {:.2} tok/s while generating",
        snapshot.window.tokens_per_second(snapshot.window_seconds),
        snapshot.window.generation_tokens_per_second()
    ));
    if totals.metered_requests < totals.requests {
        lines.push("  note: unmetered requests are ones whose upstream reported no usage".into());
    }
    for (label, counts) in [("route", &snapshot.routes), ("model", &snapshot.models)] {
        if counts.is_empty() {
            continue;
        }
        lines.push(format!("  by {label}:"));
        for (name, counts) in counts {
            lines.push(format!(
                "    {name}: {} requests, {} prompt, {} completion",
                counts.requests, counts.prompt_tokens, counts.completion_tokens
            ));
        }
    }
    lines
}

async fn fleet_usage(json_output: bool) -> Result<Vec<String>, String> {
    use myceliumd::protocol::Request;
    let mut client = crate::connect().await.map_err(|error| error.to_string())?;
    let peers = client
        .call(&Request::PeerList)
        .await
        .map_err(|error| error.to_string())?;
    Ok(render_fleet_usage(&peers, unix_now(), json_output))
}

/// Aggregate the usage each peer gossiped. Hosts with no gateway, a stale
/// snapshot, or an older daemon simply do not appear: an absent row is honest,
/// a zero row would be a guess.
fn render_fleet_usage(peers: &Value, now: u64, json_output: bool) -> Vec<String> {
    use mycelium_peer_protocol::gateway_usage::{GatewayUsageMetrics, TokenCounts};
    let mut rows = Vec::new();
    let mut total = TokenCounts::default();
    let mut throughput = 0.0;
    let mut generating = 0.0;
    for peer in peers.as_array().into_iter().flatten() {
        let metrics: std::collections::BTreeMap<String, String> =
            serde_json::from_value(peer["health"]["platform_metrics"].clone()).unwrap_or_default();
        let Some(usage) = GatewayUsageMetrics::from_platform_metrics(&metrics) else {
            continue;
        };
        if !usage.is_fresh(now) {
            continue;
        }
        total.add(&usage.totals);
        throughput += usage.tokens_per_second();
        generating += usage.generation_tokens_per_second();
        rows.push(json!({
            "hostname": peer["hello"]["hostname"],
            "node_id": peer["hello"]["node_id"],
            "updated_at": usage.updated_at,
            "requests": usage.totals.requests,
            "metered_requests": usage.totals.metered_requests,
            "prompt_tokens": usage.totals.prompt_tokens,
            "completion_tokens": usage.totals.completion_tokens,
            "tokens_per_second": usage.tokens_per_second(),
            "generation_tokens_per_second": usage.generation_tokens_per_second(),
        }));
    }
    if json_output {
        return vec![json!({
            "hosts": rows.len(),
            "totals": json!({
                "requests": total.requests,
                "metered_requests": total.metered_requests,
                "prompt_tokens": total.prompt_tokens,
                "completion_tokens": total.completion_tokens,
                "cached_tokens": total.cached_tokens,
                "generation_millis": total.generation_millis,
                "tokens_per_second": throughput,
                "generation_tokens_per_second": generating,
            }),
            "rows": rows,
        })
        .to_string()];
    }
    if rows.is_empty() {
        return vec!["fleet ai usage: no gateway on any peer has recorded usage yet".into()];
    }
    let mut lines = vec![format!(
        "fleet ai usage ({} machines): {} requests, {} prompt tokens, {} completion tokens, {:.2} tok/s",
        rows.len(),
        total.requests,
        total.prompt_tokens,
        total.completion_tokens,
        throughput
    )];
    for row in rows {
        lines.push(format!(
            "  {} requests={} prompt={} completion={} tok/s={:.2}",
            row["hostname"].as_str().unwrap_or("?"),
            row["requests"],
            row["prompt_tokens"],
            row["completion_tokens"],
            row["tokens_per_second"].as_f64().unwrap_or(0.0)
        ));
    }
    lines.push(
        "  note: hosts without a gateway, or with one that stopped reporting, are absent".into(),
    );
    lines
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn status_options(args: &[String]) -> Result<(PathBuf, bool), String> {
    let mut home = myceliumd::home_dir();
    let mut json_output = false;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--json" => json_output = true,
            "--path" => {
                index += 1;
                home = expand_home(
                    args.get(index)
                        .ok_or("--path requires a Mycelium home directory")?,
                );
            }
            other => return Err(format!("unknown gateway status argument `{other}`")),
        }
        index += 1;
    }
    Ok((home, json_output))
}

fn render_status(value: &Value) -> Vec<String> {
    let installed = value["installed"].as_bool().unwrap_or(false);
    let mut lines = vec![format!(
        "gateway: {}",
        if installed {
            "installed"
        } else {
            "not installed"
        }
    )];
    for (label, key) in [
        ("gateway agent", "gateway_agent"),
        ("https agent", "https_agent"),
    ] {
        let agent = &value[key];
        let text = if agent["supported"].as_bool().unwrap_or(false) {
            format!(
                "{} ({})",
                agent["state"].as_str().unwrap_or("unknown"),
                if agent["loaded"].as_bool().unwrap_or(false) {
                    "loaded"
                } else {
                    "not loaded"
                }
            )
        } else {
            "unsupported platform".into()
        };
        lines.push(format!("  {label}: {text}"));
    }
    lines.push(format!(
        "  gateway listener: {}",
        if value["gateway_listening"].as_bool().unwrap_or(false) {
            value["listen"].as_str().unwrap_or("unknown")
        } else {
            "down"
        }
    ));
    lines.push(format!(
        "  https listener: {}",
        if value["https_listening"].as_bool().unwrap_or(false) {
            value["https_listen"].as_str().unwrap_or(HTTPS_ADDR)
        } else {
            "down"
        }
    ));
    lines.push(format!(
        "  certificate: {} ({})",
        value["certificate"].as_str().unwrap_or("missing"),
        if value["certificate_trusted"].as_bool().unwrap_or(false) {
            "trusted for ai.myc"
        } else {
            "not trusted"
        }
    ));
    lines.push(format!(
        "  routes: {} ({})",
        value["routes"].as_str().unwrap_or("missing"),
        if value["routes_valid"].as_bool().unwrap_or(false) {
            "valid"
        } else {
            "missing or invalid"
        }
    ));
    if let Some(health) = value["health"].as_object() {
        lines.push(format!(
            "  health: HTTP {} {}",
            health.get("status").and_then(Value::as_u64).unwrap_or(0),
            health.get("body").map(Value::to_string).unwrap_or_default()
        ));
    }
    match value["tls_verified"].as_bool() {
        Some(true) => lines.push("  tls: certificate and ai.myc identity verified".into()),
        _ => {
            if let Some(error) = value["tls_error"].as_str() {
                lines.push(format!("  tls: {error}"));
            }
        }
    }
    if let Some(path) = value["system_daemon"].as_str() {
        lines.push(format!(
            "  warning: system LaunchDaemon {path} also claims :{HTTPS_PORT}"
        ));
    }
    lines
}

pub async fn snapshot(home: &Path) -> Value {
    let paths = Paths::discover(home);
    let installed = Service::Gateway.installed() && Service::HttpsSocket.installed();
    let gateway_listening = tcp_probe(paths.listen);
    let https_listening = tcp_probe(https_listen());
    let certificate_trusted = paths.cert.is_file() && certificate_trusted(&paths.cert);
    let health = if gateway_listening {
        probe(paths.listen).await.ok()
    } else {
        None
    };
    let tls = if gateway_listening {
        Some(tls_chain_verified(&paths, paths.listen))
    } else {
        None
    };
    let tls_verified = tls.as_ref().is_some_and(|result| result.is_ok());
    let tls_error = match tls {
        Some(Err(error)) => Some(error),
        _ => None,
    };
    json!({
        "installed": installed,
        "gateway_agent": service_state(Service::Gateway),
        "https_agent": service_state(Service::HttpsSocket),
        "gateway_listening": gateway_listening,
        "https_listening": https_listening,
        "listen": paths.listen.to_string(),
        "https_listen": HTTPS_ADDR,
        "certificate": paths.cert.display().to_string(),
        "certificate_trusted": certificate_trusted,
        "routes": paths.routes.display().to_string(),
        "routes_valid": read_routes(&paths.routes).is_ok(),
        "gateway_binary": paths.gateway_bin.display().to_string(),
        "gateway_binary_present": paths.gateway_bin.is_file(),
        "forwarder_binary": paths.forwarder_bin.display().to_string(),
        "forwarder_binary_present": paths.forwarder_bin.is_file(),
        "health": health,
        "tls_verified": tls_verified,
        "tls_error": tls_error,
        "system_daemon": system_daemon_path().map(|path| path.display().to_string()),
    })
}

pub async fn install(args: &[String]) -> Result<Vec<String>, String> {
    install_with_options(parse_install(args)?).await
}

pub async fn install_default(home: &Path, trust: bool) -> Result<Vec<String>, String> {
    let mut options = InstallOptions::new();
    options.home = home.to_path_buf();
    options.trust = trust;
    options.write = true;
    install_with_options(options).await
}

async fn install_with_options(options: InstallOptions) -> Result<Vec<String>, String> {
    if options.write && options.dry_run {
        return Err("gateway install accepts only one of --write or --dry-run".into());
    }
    if !options.write && !options.dry_run {
        return Err("gateway install requires --write or --dry-run".into());
    }
    if options.cert.is_some() != options.key.is_some() {
        return Err("--cert and --key must be provided together".into());
    }

    platform()?;
    let paths = Paths::discover(&options.home);
    let listen = options.listen.unwrap_or(paths.listen);
    preflight(listen)?;
    let gateway_source = find_binary(
        "mycelium-gateway",
        options.gateway_bin.as_deref(),
        &paths.gateway_bin,
    )?;
    let forwarder_source = find_binary(
        "mycelium-https-forwarder",
        options.forwarder_bin.as_deref(),
        &paths.forwarder_bin,
    )?;
    let mut actions = Vec::new();
    let routes = prepare_routes(&paths, &options, &mut actions)?;
    let material = prepare_certificate(&paths, &options, &routes, &mut actions)?;

    if options.dry_run {
        actions.push(format!("would use gateway listen {listen}"));
        actions.push(format!(
            "would install {} from {}",
            paths.gateway_bin.display(),
            gateway_source.display()
        ));
        actions.push(format!(
            "would install {} from {}",
            paths.forwarder_bin.display(),
            forwarder_source.display()
        ));
        actions.push(format!(
            "would write {}",
            service_paths()?
                .iter()
                .map(|path| path.display().to_string())
                .collect::<Vec<_>>()
                .join(", ")
        ));
        if options.trust {
            actions.push(format!(
                "would trust {} in the {} trust store",
                material.trust_anchor().display(),
                match platform()? {
                    Platform::Macos => "login keychain",
                    Platform::Linux => "system CA",
                }
            ));
        }
        return Ok(actions);
    }

    create_private_dir(&paths.dir)?;
    let gateway_bin = install_binary(&gateway_source, &paths.gateway_bin)?;
    let forwarder_bin = install_binary(&forwarder_source, &paths.forwarder_bin)?;
    install_gateway_service(&paths, listen, &gateway_bin, &routes, &material)?;
    install_https_services(&paths, listen, &forwarder_bin)?;
    if options.trust {
        trust_certificate(material.trust_anchor())?;
    }

    start_services()?;
    wait_for_listener(listen)?;
    let health = wait_for_https(HTTPS_PORT).await?;
    if health["status"].as_u64() != Some(200) {
        return Err(format!(
            "installed the gateway, but https://ai.myc/healthz returned HTTP {}",
            health["status"]
        ));
    }
    tls_chain_verified(&paths, https_listen()).map_err(|error| {
        format!("installed the gateway, but the :{HTTPS_PORT} TLS check failed: {error}")
    })?;
    if options.trust && !certificate_trusted(&material.cert) {
        return Err(format!(
            "certificate {} does not verify for ai.myc after trust installation",
            material.cert.display()
        ));
    }

    let mut lines = vec![format!(
        "installed local HTTPS gateway for {}",
        options.home.display()
    )];
    lines.push(format!("  gateway: {}", gateway_bin.display()));
    lines.push(format!("  forwarder: {}", forwarder_bin.display()));
    lines.push(format!("  listen: {listen}"));
    lines.push(format!("  routes: {}", routes.display()));
    lines.push(format!("  certificate: {}", material.cert.display()));
    if material.generated {
        lines.push("  generated a local CA and gateway certificate".into());
    }
    if options.trust {
        lines.push(format!(
            "  certificate trust: {}",
            if certificate_trusted(&material.cert) {
                "verified for ai.myc"
            } else {
                "was installed but could not be verified"
            }
        ));
    } else if certificate_trusted(&material.cert) {
        lines.push("  certificate trust: already verified for ai.myc".into());
    } else {
        lines.push("  certificate trust: not installed; run `mycelium gateway install --write --trust-cert` or use `mycelium doctor --fix --trust-cert`".into());
    }
    lines.push("  browser URL: https://ai.myc/health".into());
    Ok(lines)
}

fn preflight(listen: SocketAddr) -> Result<(), String> {
    if let Some(path) = system_daemon_path() {
        return Err(format!(
            "{} also claims 127.0.0.1:{HTTPS_PORT} for the system launchd domain; remove it before installing the user agent: sudo launchctl bootout system/{HTTPS_LABEL} && sudo rm {}",
            path.display(),
            path.display()
        ));
    }
    ensure_port_available(Service::Gateway, listen)?;
    ensure_port_available(Service::HttpsSocket, https_listen())
}

/// Refuse to start when a listener is not the service we are about to replace.
/// A socket-activated service counts as ours while its manager reports it
/// healthy and its unit/plist is present.
fn ensure_port_available(service: Service, address: SocketAddr) -> Result<(), String> {
    if !tcp_probe(address) {
        return Ok(());
    }
    let state = service_state(service);
    let healthy = matches!(
        state["state"].as_str(),
        Some("running") | Some("waiting") | Some("active")
    );
    let owners = listener_pids(address);
    // The service must own the listener, not merely be active. Without this a
    // second gateway on the same port could pass preflight against the first
    // one's socket and only fail later.
    let owned = owners.is_empty()
        || service_pid(service).is_none_or(|pid| owners.iter().all(|owner| *owner == pid));
    if service.installed() && state["loaded"].as_bool() == Some(true) && healthy && owned {
        return Ok(());
    }
    Err(format!(
        "cannot install {}: {address} is already in use by {}; stop that listener and retry",
        service.path()?.display(),
        if owners.is_empty() {
            "another process".to_owned()
        } else {
            format!(
                "pid {}",
                owners
                    .iter()
                    .map(u32::to_string)
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        }
    ))
}

fn service_pid(service: Service) -> Option<u32> {
    match platform().ok()? {
        Platform::Macos => launchd_print(service.macos_label())
            .ok()
            .flatten()
            .and_then(|text| {
                text.lines().find_map(|line| {
                    line.trim()
                        .strip_prefix("pid = ")
                        .and_then(|value| value.trim().parse().ok())
                })
            }),
        Platform::Linux => {
            let output = Command::new("systemctl")
                .args(["show", "-p", "MainPID", "--value", service.linux_unit()])
                .output()
                .ok()?;
            let pid = String::from_utf8_lossy(&output.stdout)
                .trim()
                .parse()
                .ok()?;
            (pid != 0).then_some(pid)
        }
    }
}

fn parse_install(args: &[String]) -> Result<InstallOptions, String> {
    let mut options = InstallOptions::new();
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--write" => options.write = true,
            "--dry-run" => options.dry_run = true,
            "--trust-cert" => options.trust = true,
            "--listen" => {
                index += 1;
                options.listen = Some(listen_addr(
                    args.get(index).ok_or("--listen requires IP:PORT")?,
                )?);
            }
            "--path" => {
                index += 1;
                options.home = expand_home(args.get(index).ok_or("--path requires a directory")?);
            }
            "--routes" => {
                index += 1;
                options.routes = Some(expand_home(
                    args.get(index).ok_or("--routes requires a path")?,
                ));
            }
            "--cert" => {
                index += 1;
                options.cert = Some(expand_home(
                    args.get(index).ok_or("--cert requires a path")?,
                ));
            }
            "--key" => {
                index += 1;
                options.key = Some(expand_home(args.get(index).ok_or("--key requires a path")?));
            }
            "--gateway-bin" => {
                index += 1;
                options.gateway_bin = Some(expand_home(
                    args.get(index).ok_or("--gateway-bin requires a path")?,
                ));
            }
            "--forwarder-bin" => {
                index += 1;
                options.forwarder_bin = Some(expand_home(
                    args.get(index).ok_or("--forwarder-bin requires a path")?,
                ));
            }
            other => return Err(format!("unknown gateway install argument `{other}`")),
        }
        index += 1;
    }
    Ok(options)
}

fn prepare_certificate(
    paths: &Paths,
    options: &InstallOptions,
    routes: &Path,
    actions: &mut Vec<String>,
) -> Result<CertificateMaterial, String> {
    if let (Some(cert), Some(key)) = (&options.cert, &options.key) {
        if !cert.is_file() || !key.is_file() {
            return Err("--cert and --key must both name existing files".into());
        }
        return Ok(CertificateMaterial {
            cert: cert.clone(),
            key: key.clone(),
            ca: cert
                .parent()
                .map(|parent| parent.join("ca.pem"))
                .filter(|path| path.is_file()),
            generated: false,
        });
    }
    let cert_exists = paths.cert.is_file();
    let key_exists = paths.key.is_file();
    if cert_exists != key_exists {
        return Err(format!(
            "existing certificate pair is incomplete: {} / {}",
            paths.cert.display(),
            paths.key.display()
        ));
    }
    if cert_exists {
        return Ok(CertificateMaterial {
            cert: paths.cert.clone(),
            key: paths.key.clone(),
            ca: paths.ca.is_file().then(|| paths.ca.clone()),
            generated: false,
        });
    }
    if options.dry_run {
        actions.push(format!(
            "would generate a local CA and certificate under {}",
            paths.dir.display()
        ));
        return Ok(CertificateMaterial {
            cert: paths.cert.clone(),
            key: paths.key.clone(),
            ca: Some(paths.ca.clone()),
            generated: true,
        });
    }
    let material = generate_certificate(&paths.dir, &route_hosts(routes))?;
    actions.push(format!(
        "generated local certificate {}",
        material.cert.display()
    ));
    Ok(material)
}

fn prepare_routes(
    paths: &Paths,
    options: &InstallOptions,
    actions: &mut Vec<String>,
) -> Result<PathBuf, String> {
    if let Some(source) = &options.routes {
        if !source.is_file() {
            return Err(format!(
                "--routes file does not exist: {}",
                source.display()
            ));
        }
        if options.dry_run {
            actions.push(format!("would install routes from {}", source.display()));
            return Ok(paths.routes.clone());
        }
        if source != &paths.routes {
            write_file(
                &paths.routes,
                &fs::read(source).map_err(|error| format!("read routes: {error}"))?,
                0o644,
            )?;
        }
        return Ok(paths.routes.clone());
    }
    if paths.routes.is_file() {
        return Ok(paths.routes.clone());
    }
    if options.dry_run {
        actions.push(format!(
            "would write default routes to {}",
            paths.routes.display()
        ));
        return Ok(paths.routes.clone());
    }
    write_file(
        &paths.routes,
        serde_json::to_vec_pretty(&default_routes(paths.home.as_path()))
            .map_err(|error| format!("encode default routes: {error}"))?
            .as_slice(),
        0o644,
    )?;
    actions.push(format!(
        "wrote default routes to {}",
        paths.routes.display()
    ));
    Ok(paths.routes.clone())
}

#[derive(Clone, Debug)]
pub struct CertificateMaterial {
    pub cert: PathBuf,
    pub key: PathBuf,
    pub ca: Option<PathBuf>,
    pub generated: bool,
}

impl CertificateMaterial {
    pub fn trust_anchor(&self) -> &Path {
        self.ca.as_deref().unwrap_or(&self.cert)
    }
}

fn generate_certificate(dir: &Path, route_hosts: &[String]) -> Result<CertificateMaterial, String> {
    create_private_dir(dir)?;
    let ca_key = KeyPair::generate().map_err(|error| format!("generate CA key: {error}"))?;
    let mut ca_params = CertificateParams::new(Vec::new())
        .map_err(|error| format!("create CA parameters: {error}"))?;
    ca_params.distinguished_name = DistinguishedName::new();
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "Mycelium Local Gateway CA");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    ca_params.not_after = date_time_ymd(2036, 1, 1);
    let ca = ca_params
        .self_signed(&ca_key)
        .map_err(|error| format!("sign CA: {error}"))?;

    let leaf_key = KeyPair::generate().map_err(|error| format!("generate leaf key: {error}"))?;
    let mut leaf_params = CertificateParams::new(certificate_names(route_hosts))
        .map_err(|error| format!("create leaf parameters: {error}"))?;
    leaf_params.distinguished_name = DistinguishedName::new();
    leaf_params
        .distinguished_name
        .push(DnType::CommonName, "mycelium-gateway");
    leaf_params.is_ca = IsCa::NoCa;
    leaf_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    leaf_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    leaf_params.not_after = date_time_ymd(2036, 1, 1);
    let leaf = leaf_params
        .signed_by(&leaf_key, &ca, &ca_key)
        .map_err(|error| format!("sign leaf: {error}"))?;

    let ca_path = dir.join("ca.pem");
    let cert_path = dir.join("server.pem");
    let key_path = dir.join("server-key.pem");
    write_file(&ca_path, ca.pem().as_bytes(), 0o644)?;
    write_file(
        &cert_path,
        format!("{}{}", leaf.pem(), ca.pem()).as_bytes(),
        0o644,
    )?;
    write_file(&key_path, leaf_key.serialize_pem().as_bytes(), 0o600)?;
    Ok(CertificateMaterial {
        cert: cert_path,
        key: key_path,
        ca: Some(ca_path),
        generated: true,
    })
}

fn certificate_names(route_hosts: &[String]) -> Vec<String> {
    // `*.myc` alone is not accepted by OpenSSL/most browsers because the
    // wildcard sits in a single-label domain. List the bootstrap names and
    // every host in the installed route table so the generated certificate
    // covers what the gateway actually serves.
    let mut names = [
        "ai.myc",
        "api.myc",
        "mcp.myc",
        "home.myc",
        "webhook.myc",
        "*.myc",
        "localhost",
        "127.0.0.1",
    ]
    .iter()
    .map(|name| (*name).to_owned())
    .collect::<Vec<_>>();
    names.extend(route_hosts.iter().cloned());
    names.sort();
    names.dedup();
    names
}

fn route_hosts(path: &Path) -> Vec<String> {
    let Ok(routes) = read_routes(path) else {
        return Vec::new();
    };
    routes["routes"]
        .as_array()
        .into_iter()
        .flatten()
        .flat_map(|route| route["hosts"].as_array().into_iter().flatten())
        .filter_map(Value::as_str)
        .map(str::to_owned)
        .collect()
}

fn find_binary(name: &str, explicit: Option<&Path>, installed: &Path) -> Result<PathBuf, String> {
    if let Some(path) = explicit {
        return require_file(path, name);
    }
    if let Ok(current) = std::env::current_exe() {
        let sibling = current.with_file_name(name);
        if sibling.is_file() {
            return Ok(sibling);
        }
        if let Some(parent) = current.parent() {
            let bin = parent.join("bin").join(name);
            if bin.is_file() {
                return Ok(bin);
            }
        }
    }
    if installed.is_file() {
        return Ok(installed.to_path_buf());
    }
    if let Some(path) = std::env::var_os("PATH").and_then(|path| {
        std::env::split_paths(&path)
            .map(|dir| dir.join(name))
            .find(|candidate| candidate.is_file())
    }) {
        return Ok(path);
    }
    Err(format!(
        "{name} not found; place it next to the mycelium binary or pass {}",
        match name {
            "mycelium-gateway" => "--gateway-bin",
            "mycelium-https-forwarder" => "--forwarder-bin",
            _ => "the matching --*-bin flag",
        }
    ))
}

fn require_file(path: &Path, label: &str) -> Result<PathBuf, String> {
    if path.is_file() {
        Ok(path.to_path_buf())
    } else {
        Err(format!("{label} is not a file: {}", path.display()))
    }
}

fn install_binary(source: &Path, destination: &Path) -> Result<PathBuf, String> {
    if source == destination {
        return Ok(destination.to_path_buf());
    }
    if let Some(parent) = destination.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| format!("create {}: {error}", parent.display()))?;
    }
    if destination.exists() {
        let previous = destination.with_extension("previous");
        fs::copy(destination, &previous)
            .map_err(|error| format!("retain previous {}: {error}", destination.display()))?;
    }
    let staged = destination.with_extension(format!("new-{}", std::process::id()));
    fs::copy(source, &staged).map_err(|error| format!("copy {}: {error}", source.display()))?;
    set_mode(&staged, 0o755)?;
    fs::rename(&staged, destination)
        .map_err(|error| format!("install {}: {error}", destination.display()))?;
    Ok(destination.to_path_buf())
}

fn render_gateway_plist(
    paths: &Paths,
    gateway_bin: &Path,
    routes: &Path,
    material: &CertificateMaterial,
    listen: SocketAddr,
) -> String {
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\"><dict>\n<key>Label</key><string>{label}</string>\n<key>ProgramArguments</key><array><string>{gateway}</string><string>--listen</string><string>{listen}</string><string>--routes</string><string>{routes}</string><string>--usage</string><string>{usage}</string><string>--reload-secs</string><string>1</string><string>--tls-cert</string><string>{cert}</string><string>--tls-key</string><string>{key}</string></array>\n<key>RunAtLoad</key><true/><key>KeepAlive</key><true/><key>ThrottleInterval</key><integer>10</integer>\n<key>StandardOutPath</key><string>{log}</string>\n<key>StandardErrorPath</key><string>{log}</string>\n</dict></plist>\n",
        label = xml(GATEWAY_LABEL),
        gateway = xml(&gateway_bin.display().to_string()),
        listen = listen,
        routes = xml(&routes.display().to_string()),
        usage = xml(&paths.usage.display().to_string()),
        cert = xml(&material.cert.display().to_string()),
        key = xml(&material.key.display().to_string()),
        log = xml(&paths.dir.join("gateway.log").display().to_string()),
    )
}

fn render_https_plist(paths: &Paths, forwarder_bin: &Path, listen: SocketAddr) -> String {
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\"><dict>\n<key>Label</key><string>{label}</string>\n<key>ProgramArguments</key><array><string>{forwarder}</string><string>--target</string><string>{listen}</string></array>\n<key>RunAtLoad</key><true/><key>ThrottleInterval</key><integer>5</integer>\n<key>StandardErrorPath</key><string>{log}</string>\n<key>Sockets</key><dict><key>HTTPS</key><dict><key>SockNodeName</key><string>127.0.0.1</string><key>SockServiceName</key><integer>{port}</integer><key>SockFamily</key><string>IPv4</string><key>SockType</key><string>stream</string><key>SockProtocol</key><string>TCP</string></dict></dict>\n</dict></plist>\n",
        label = xml(HTTPS_LABEL),
        forwarder = xml(&forwarder_bin.display().to_string()),
        listen = listen,
        log = xml(&paths.dir.join("https-forwarder.log").display().to_string()),
        port = HTTPS_PORT,
    )
}

fn render_gateway_unit(
    usage: &Path,
    listen: SocketAddr,
    gateway_bin: &Path,
    routes: &Path,
    material: &CertificateMaterial,
) -> Result<String, String> {
    let user = current_user()?;
    let group = current_group()?;
    Ok(format!(
        "[Unit]\nDescription=Mycelium local .myc HTTPS gateway\nAfter=network-online.target\nWants=network-online.target\n\n[Service]\nType=simple\nUser={user}\nGroup={group}\nEnvironment={home}\nExecStart={gateway} --listen {listen} --routes {routes} --usage {usage} --reload-secs 1 --tls-cert {cert} --tls-key {key}\nRestart=on-failure\nRestartSec=2\nNoNewPrivileges=true\nPrivateTmp=true\n\n[Install]\nWantedBy=multi-user.target\n",
        home = systemd_quote(&format!(
            "HOME={}",
            user_home()?.display()
        )),
        gateway = systemd_quote(&gateway_bin.display().to_string()),
        routes = systemd_quote(&routes.display().to_string()),
        usage = systemd_quote(&usage.display().to_string()),
        cert = systemd_quote(&material.cert.display().to_string()),
        key = systemd_quote(&material.key.display().to_string()),
    ))
}

fn render_https_socket_unit() -> String {
    format!(
        "[Unit]\nDescription=Mycelium .myc HTTPS socket\n\n[Socket]\nListenStream={HTTPS_ADDR}\nAccept=no\nService={HTTPS_SERVICE_UNIT}\n\n[Install]\nWantedBy=sockets.target\n"
    )
}

fn render_https_service_unit(listen: SocketAddr, forwarder_bin: &Path) -> Result<String, String> {
    let user = current_user()?;
    let group = current_group()?;
    Ok(format!(
        "[Unit]\nDescription=Mycelium .myc HTTPS forwarder\nRequires={HTTPS_SOCKET_UNIT}\nAfter={GATEWAY_UNIT}\n\n[Service]\nUser={user}\nGroup={group}\nExecStart={forwarder} --target {listen}\nNoNewPrivileges=true\nPrivateTmp=true\n",
        forwarder = systemd_quote(&forwarder_bin.display().to_string()),
    ))
}

fn systemd_quote(value: &str) -> String {
    format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\""))
}

fn current_user() -> Result<String, String> {
    id_field("-un")
}

fn current_group() -> Result<String, String> {
    id_field("-gn")
}

fn id_field(flag: &str) -> Result<String, String> {
    let output = Command::new("id")
        .arg(flag)
        .output()
        .map_err(|error| format!("run id {flag}: {error}"))?;
    if !output.status.success() {
        return Err(format!("id {flag} failed"));
    }
    let value = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    if value.is_empty() || value.chars().any(char::is_whitespace) {
        return Err(format!("id {flag} returned an unusable name"));
    }
    Ok(value)
}

fn service_paths() -> Result<Vec<PathBuf>, String> {
    Ok(match platform()? {
        Platform::Macos => vec![
            launch_agent_path(GATEWAY_LABEL)?,
            launch_agent_path(HTTPS_LABEL)?,
        ],
        Platform::Linux => vec![
            systemd_unit_path(GATEWAY_UNIT),
            systemd_unit_path(HTTPS_SOCKET_UNIT),
            systemd_unit_path(HTTPS_SERVICE_UNIT),
        ],
    })
}

fn install_gateway_service(
    paths: &Paths,
    listen: SocketAddr,
    gateway_bin: &Path,
    routes: &Path,
    material: &CertificateMaterial,
) -> Result<(), String> {
    match platform()? {
        Platform::Macos => {
            write_named_plist(
                GATEWAY_LABEL,
                &render_gateway_plist(paths, gateway_bin, routes, material, listen),
            )?;
        }
        Platform::Linux => {
            let unit = render_gateway_unit(&paths.usage, listen, gateway_bin, routes, material)?;
            install_system_unit(&paths.dir, GATEWAY_UNIT, &unit)?;
        }
    }
    Ok(())
}

fn install_https_services(
    paths: &Paths,
    listen: SocketAddr,
    forwarder_bin: &Path,
) -> Result<(), String> {
    match platform()? {
        Platform::Macos => {
            write_named_plist(
                HTTPS_LABEL,
                &render_https_plist(paths, forwarder_bin, listen),
            )?;
        }
        Platform::Linux => {
            install_system_unit(&paths.dir, HTTPS_SOCKET_UNIT, &render_https_socket_unit())?;
            install_system_unit(
                &paths.dir,
                HTTPS_SERVICE_UNIT,
                &render_https_service_unit(listen, forwarder_bin)?,
            )?;
        }
    }
    Ok(())
}

fn install_system_unit(dir: &Path, name: &str, contents: &str) -> Result<(), String> {
    let destination = systemd_unit_path(name);
    let staged = dir.join(format!(".{name}.staged"));
    write_file(&staged, contents.as_bytes(), 0o644)?;
    let result = run_privileged(
        "install",
        &[
            "-m".to_owned(),
            "0644".to_owned(),
            staged.display().to_string(),
            destination.display().to_string(),
        ],
    );
    let _ = fs::remove_file(&staged);
    result
}

fn write_named_plist(label: &str, contents: &str) -> Result<PathBuf, String> {
    let path = launch_agent_path(label)?;
    write_file(&path, contents.as_bytes(), 0o644)?;
    Ok(path)
}

fn xml(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('\"', "&quot;")
        .replace('\'', "&apos;")
}

fn is_root() -> bool {
    Command::new("id")
        .arg("-u")
        .output()
        .ok()
        .is_some_and(|output| String::from_utf8_lossy(&output.stdout).trim() == "0")
}

fn run_privileged(program: &str, args: &[String]) -> Result<(), String> {
    let mut command = if is_root() {
        Command::new(program)
    } else {
        let mut command = Command::new("sudo");
        command.arg("-n").arg(program);
        command
    };
    let output = command
        .args(args)
        .output()
        .map_err(|error| format!("run {program}: {error}"))?;
    if output.status.success() {
        return Ok(());
    }
    Err(format!(
        "{program} failed: {} (system installation needs passwordless sudo; run `sudo -v` and retry)",
        String::from_utf8_lossy(&output.stderr).trim()
    ))
}

fn start_services() -> Result<(), String> {
    match platform()? {
        Platform::Macos => {
            bootstrap(GATEWAY_LABEL, &launch_agent_path(GATEWAY_LABEL)?)?;
            bootstrap(HTTPS_LABEL, &launch_agent_path(HTTPS_LABEL)?)?;
        }
        Platform::Linux => {
            run_privileged("systemctl", &["daemon-reload".to_owned()])?;
            run_privileged(
                "systemctl",
                &[
                    "enable".to_owned(),
                    GATEWAY_UNIT.to_owned(),
                    HTTPS_SOCKET_UNIT.to_owned(),
                ],
            )?;
            run_privileged(
                "systemctl",
                &["restart".to_owned(), GATEWAY_UNIT.to_owned()],
            )?;
            run_privileged(
                "systemctl",
                &["restart".to_owned(), HTTPS_SOCKET_UNIT.to_owned()],
            )?;
        }
    }
    Ok(())
}

fn bootstrap(label: &str, plist: &Path) -> Result<(), String> {
    let domain = launch_domain()?;
    let mut last_error = String::new();
    for _ in 0..10 {
        let _ = Command::new("launchctl")
            .args(["bootout", &format!("{domain}/{label}")])
            .output();
        let output = Command::new("launchctl")
            .args(["bootstrap", &domain])
            .arg(plist)
            .output()
            .map_err(|error| format!("run launchctl: {error}"))?;
        if output.status.success() {
            return Ok(());
        }
        last_error = String::from_utf8_lossy(&output.stderr).trim().to_owned();
        std::thread::sleep(Duration::from_millis(300));
    }
    Err(format!("launchctl bootstrap {label} failed: {last_error}"))
}

fn wait_for_listener(address: SocketAddr) -> Result<(), String> {
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        if TcpStream::connect_timeout(&address, Duration::from_millis(250)).is_ok() {
            return Ok(());
        }
        if std::time::Instant::now() >= deadline {
            return Err(format!(
                "gateway listener {address} did not become ready within 10 seconds"
            ));
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}

fn tcp_probe(address: SocketAddr) -> bool {
    // Prefer lsof: a bare TCP connect to the socket-activated :443 would wake
    // the forwarder and log a failed TLS handshake on every status check.
    if !listener_pids(address).is_empty() {
        return true;
    }
    TcpStream::connect_timeout(&address, Duration::from_millis(300)).is_ok()
}

fn listener_pids(address: SocketAddr) -> Vec<u32> {
    let Ok(output) = Command::new("lsof")
        .arg("-nP")
        .arg(format!("-iTCP@{}:{}", address.ip(), address.port()))
        .args(["-sTCP:LISTEN", "-t"])
        .output()
    else {
        return Vec::new();
    };
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|line| line.trim().parse().ok())
        .collect()
}

async fn wait_for_https(port: u16) -> Result<Value, String> {
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        match probe(https_listen()).await {
            Ok(health) => return Ok(health),
            Err(error) => {
                if std::time::Instant::now() >= deadline {
                    return Err(format!(
                        "https://ai.myc:{port}/healthz did not become ready within 10 seconds: {error}"
                    ));
                }
                tokio::time::sleep(Duration::from_millis(300)).await;
            }
        }
    }
}

fn launch_domain() -> Result<String, String> {
    Ok(format!("gui/{}", id_field("-u")?))
}

fn service_state(service: Service) -> Value {
    match platform() {
        Ok(Platform::Macos) => launchd_state(service.macos_label()),
        Ok(Platform::Linux) => systemctl_state(service.linux_unit()),
        Err(error) => json!({"supported": false, "loaded": false, "state": error}),
    }
}

fn systemctl_state(unit: &str) -> Value {
    let output = Command::new("systemctl").args(["is-active", unit]).output();
    match output {
        Ok(output) => {
            let state = String::from_utf8_lossy(&output.stdout).trim().to_owned();
            let state = if state.is_empty() {
                "inactive".to_owned()
            } else {
                state
            };
            json!({"supported": true, "loaded": state == "active", "state": state})
        }
        Err(error) => json!({"supported": false, "loaded": false, "state": error.to_string()}),
    }
}

fn launchd_state(label: &str) -> Value {
    match launchd_print(label) {
        Ok(Some(text)) => {
            let state = text
                .lines()
                .find_map(|line| line.trim().strip_prefix("state = "))
                .unwrap_or("unknown");
            json!({"supported": true, "loaded": true, "state": state})
        }
        Ok(None) => json!({"supported": true, "loaded": false, "state": "not loaded"}),
        Err(error) => json!({"supported": false, "loaded": false, "state": error}),
    }
}

fn launchd_print(label: &str) -> Result<Option<String>, String> {
    let domain = launch_domain()?;
    let output = Command::new("launchctl")
        .args(["print", &format!("{domain}/{label}")])
        .output()
        .map_err(|error| format!("run launchctl: {error}"))?;
    if output.status.success() {
        Ok(Some(String::from_utf8_lossy(&output.stdout).into_owned()))
    } else {
        Ok(None)
    }
}

fn launch_agent_path(label: &str) -> Result<PathBuf, String> {
    if platform()? != Platform::Macos {
        return Err("launchd is only available on macOS".into());
    }
    Ok(user_home()?
        .join("Library/LaunchAgents")
        .join(format!("{label}.plist")))
}

fn user_home() -> Result<PathBuf, String> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or_else(|| "HOME is not set".into())
}

fn expand_home(value: &str) -> PathBuf {
    value
        .strip_prefix("~/")
        .map(|suffix| user_home().unwrap_or_default().join(suffix))
        .unwrap_or_else(|| PathBuf::from(value))
}

fn create_private_dir(path: &Path) -> Result<(), String> {
    fs::create_dir_all(path).map_err(|error| format!("create {}: {error}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            .map_err(|error| format!("set permissions on {}: {error}", path.display()))?;
    }
    Ok(())
}

fn write_file(path: &Path, bytes: &[u8], mode: u32) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| format!("create {}: {error}", parent.display()))?;
    }
    let staged = path.with_extension(format!("tmp-{}", std::process::id()));
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&staged)
        .map_err(|error| format!("open {}: {error}", staged.display()))?;
    file.write_all(bytes)
        .map_err(|error| format!("write {}: {error}", staged.display()))?;
    file.sync_all()
        .map_err(|error| format!("sync {}: {error}", staged.display()))?;
    set_mode(&staged, mode)?;
    fs::rename(&staged, path).map_err(|error| format!("install {}: {error}", path.display()))?;
    Ok(())
}

fn set_mode(path: &Path, mode: u32) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(mode))
            .map_err(|error| format!("set permissions on {}: {error}", path.display()))?;
    }
    let _ = mode;
    Ok(())
}

fn default_routes(home: &Path) -> Value {
    let installed = home.join("bin/mycelium");
    let mycelium = if installed.is_file() {
        installed
    } else {
        std::env::current_exe().unwrap_or_else(|_| home.join("bin/mycelium"))
    };
    // `ai.myc` is the one AI endpoint every client is configured with. It serves
    // from this machine first, then an `ai` lease discovered on the mesh, and
    // finally the public Bifrost edge. The file only becomes a credential
    // override when it exists; without it the caller's own key reaches the edge.
    let cloud_key = user_home()
        .ok()
        .map(|home| home.join(".fpl/bifrost-api-key"));
    let mut ai_route = json!({
        "name": "ai",
        "hosts": ["ai.myc", "api.myc"],
        "upstream": ["http://127.0.0.1:4000", "https://ai.fpl.dev"],
        "service_kind": "ai",
        "priority": 10
    });
    if let Some(cloud_key) = cloud_key.as_deref().filter(|path| path.is_file()) {
        ai_route["remote_token_file"] = json!(cloud_key.display().to_string());
    }
    json!({
        "mycelium_bin": mycelium.display().to_string(),
        "service_refresh_secs": 15,
        "routes": [
            ai_route,
            {
                "name": "mcp",
                "hosts": ["mcp.myc"],
                "upstream": "http://127.0.0.1:8000",
                "service_kind": "mcp",
                "priority": 10
            },
            {
                "name": "home",
                "hosts": ["home.myc"],
                "service_kind": "home",
                "priority": 10
            },
            {
                "name": "webhook",
                "hosts": ["webhook.myc"],
                "service_kind": "webhook",
                "priority": 10
            }
        ]
    })
}

fn read_routes(path: &Path) -> Result<Value, String> {
    let bytes = fs::read(path).map_err(|error| format!("read {}: {error}", path.display()))?;
    let value: Value = serde_json::from_slice(&bytes)
        .map_err(|error| format!("parse {}: {error}", path.display()))?;
    if !value.get("routes").is_some_and(Value::is_array) {
        return Err(format!("{} has no routes array", path.display()));
    }
    Ok(value)
}

/// Probe the gateway over TLS without judging the certificate. Used for health
/// and forwarding checks; certificate validation is a separate handshake below
/// so a broken cert does not hide an otherwise reachable gateway.
async fn probe(address: SocketAddr) -> Result<Value, String> {
    let port = address.port();
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(3))
        .resolve("ai.myc", address)
        .danger_accept_invalid_certs(true)
        .build()
        .map_err(|error| format!("build gateway client: {error}"))?;
    let response = client
        .get(format!("https://ai.myc:{port}/healthz"))
        .send()
        .await
        .map_err(|error| format!("request https://ai.myc:{port}/healthz: {error}"))?;
    let status = response.status().as_u16();
    let body = response
        .json::<Value>()
        .await
        .map_err(|error| format!("parse gateway health: {error}"))?;
    Ok(json!({"status": status, "body": body}))
}

/// Verify the certificate the gateway actually presents against the local
/// trust anchor with an independent TLS implementation. `reqwest`'s rustls
/// backend rejects CA-as-leaf certificates (the legacy `server.crt` shape),
/// while macOS browsers and OpenSSL accept them, so `openssl s_client` is the
/// honest check for both generated and legacy material.
fn tls_chain_verified(paths: &Paths, address: SocketAddr) -> Result<(), String> {
    let anchor = if paths.ca.is_file() {
        &paths.ca
    } else {
        &paths.cert
    };
    if !anchor.is_file() {
        return Err(format!("trust anchor missing: {}", anchor.display()));
    }
    tls_verified(address, Some(anchor))
}

fn tls_verified(address: SocketAddr, anchor: Option<&Path>) -> Result<(), String> {
    let mut command = Command::new("openssl");
    command
        .args(["s_client", "-connect"])
        .arg(address.ip().to_string())
        .args(["-port"])
        .arg(address.port().to_string())
        .args(["-servername", "ai.myc"]);
    if let Some(anchor) = anchor {
        command.arg("-CAfile").arg(anchor);
    }
    let output = command
        .args(["-verify_return_error", "-verify_hostname", "ai.myc"])
        .stdin(std::process::Stdio::null())
        .output()
        .map_err(|error| format!("run openssl s_client: {error}"))?;
    if output.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    let detail = stderr
        .lines()
        .find(|line| line.contains("verify error") || line.contains("connect:"))
        .unwrap_or("TLS handshake failed")
        .trim();
    Err(format!("{address} certificate check failed: {detail}"))
}

fn system_daemon_path() -> Option<PathBuf> {
    let path = Path::new("/Library/LaunchDaemons").join(format!("{HTTPS_LABEL}.plist"));
    path.is_file().then_some(path)
}

fn certificate_trusted(cert: &Path) -> bool {
    if !cert.is_file() {
        return false;
    }
    match platform() {
        Ok(Platform::Macos) => Command::new("security")
            .args(["verify-cert", "-c"])
            .arg(cert)
            .args(["-p", "ssl", "-s", "ai.myc"])
            .output()
            .map(|output| output.status.success())
            .unwrap_or(false),
        Ok(Platform::Linux) => {
            let address = installed_listen().unwrap_or_else(default_listen);
            tls_verified(address, None).is_ok()
        }
        Err(_) => false,
    }
}

fn trust_certificate(cert: &Path) -> Result<(), String> {
    match platform()? {
        Platform::Macos => {
            let keychain = user_home()?.join("Library/Keychains/login.keychain-db");
            if !keychain.is_file() {
                return Err(format!("login keychain not found: {}", keychain.display()));
            }
            let output = Command::new("security")
                .args(["add-trusted-cert", "-r", "trustRoot", "-k"])
                .arg(&keychain)
                .arg(cert)
                .output()
                .map_err(|error| format!("run security add-trusted-cert: {error}"))?;
            if !output.status.success() {
                return Err(format!(
                    "security add-trusted-cert failed: {}",
                    String::from_utf8_lossy(&output.stderr).trim()
                ));
            }
            Ok(())
        }
        Platform::Linux => {
            run_privileged(
                "install",
                &[
                    "-m".to_owned(),
                    "0644".to_owned(),
                    cert.display().to_string(),
                    SYSTEM_CA_PATH.to_owned(),
                ],
            )?;
            run_privileged("update-ca-certificates", &[])
        }
    }
}

fn uninstall(args: &[String]) -> Result<Vec<String>, String> {
    let mut home = myceliumd::home_dir();
    let mut write = false;
    let mut dry_run = false;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--write" => write = true,
            "--dry-run" => dry_run = true,
            "--path" => {
                index += 1;
                home = expand_home(args.get(index).ok_or("--path requires a directory")?);
            }
            other => return Err(format!("unknown gateway uninstall argument `{other}`")),
        }
        index += 1;
    }
    if write == dry_run {
        return Err("gateway uninstall requires exactly one of --write or --dry-run".into());
    }
    let paths = service_paths()?;
    if dry_run {
        let mut lines = paths
            .iter()
            .map(|path| format!("would remove {}", path.display()))
            .collect::<Vec<_>>();
        if platform()? == Platform::Linux && Path::new(SYSTEM_CA_PATH).is_file() {
            lines.push(format!("would remove {SYSTEM_CA_PATH}"));
        }
        return Ok(lines);
    }
    match platform()? {
        Platform::Macos => {
            let domain = launch_domain()?;
            for label in [GATEWAY_LABEL, HTTPS_LABEL] {
                let _ = Command::new("launchctl")
                    .args(["bootout", &format!("{domain}/{label}")])
                    .output();
            }
            for path in &paths {
                if path.exists() {
                    fs::remove_file(path)
                        .map_err(|error| format!("remove {}: {error}", path.display()))?;
                }
            }
        }
        Platform::Linux => {
            let _ = run_privileged(
                "systemctl",
                &[
                    "disable".to_owned(),
                    "--now".to_owned(),
                    HTTPS_SOCKET_UNIT.to_owned(),
                    HTTPS_SERVICE_UNIT.to_owned(),
                    GATEWAY_UNIT.to_owned(),
                ],
            );
            for path in &paths {
                run_privileged("rm", &["-f".to_owned(), path.display().to_string()])?;
            }
            run_privileged("systemctl", &["daemon-reload".to_owned()])?;
        }
    }
    let mut lines = vec![
        format!(
            "removed {} for {}",
            match platform()? {
                Platform::Macos => "user launch agents",
                Platform::Linux => "systemd units",
            },
            home.display()
        ),
        "routes and certificates were retained".into(),
    ];
    if platform()? == Platform::Linux && Path::new(SYSTEM_CA_PATH).is_file() {
        run_privileged("rm", &["-f".to_owned(), SYSTEM_CA_PATH.to_owned()])?;
        run_privileged("update-ca-certificates", &[])?;
        lines.push(format!(
            "removed the system CA trust entry {SYSTEM_CA_PATH}"
        ));
    }
    if let Some(path) = system_daemon_path() {
        lines.push(format!(
            "system LaunchDaemon {} was not modified; remove it separately if it is no longer wanted",
            path.display()
        ));
    }
    Ok(lines)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temporary_dir(name: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "mycelium-gateway-{name}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&path).unwrap();
        path
    }

    #[test]
    fn default_routes_cover_capability_names() {
        let routes = default_routes(Path::new("/tmp/mycelium-home"));
        let hosts = routes["routes"]
            .as_array()
            .unwrap()
            .iter()
            .flat_map(|route| route["hosts"].as_array().unwrap())
            .filter_map(Value::as_str)
            .collect::<Vec<_>>();
        for expected in ["ai.myc", "mcp.myc", "home.myc", "webhook.myc"] {
            assert!(hosts.contains(&expected));
        }
    }

    #[test]
    fn the_ai_route_falls_back_to_the_public_edge() {
        let routes = default_routes(Path::new("/tmp/mycelium-home"));
        let ai = routes["routes"]
            .as_array()
            .unwrap()
            .iter()
            .find(|route| route["name"] == "ai")
            .expect("the ai route is what every client points at");
        let upstreams = ai["upstream"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(Value::as_str)
            .collect::<Vec<_>>();
        assert_eq!(
            upstreams,
            vec!["http://127.0.0.1:4000", "https://ai.fpl.dev"]
        );
        assert_eq!(ai["service_kind"], "ai");
    }

    #[test]
    fn fleet_usage_sums_fresh_hosts_and_drops_stale_ones() {
        use mycelium_peer_protocol::gateway_usage::{
            GatewayUsageMetrics, TokenCounts, GATEWAY_USAGE_MAX_AGE_SECONDS,
        };
        let peer = |hostname: &str, updated_at: u64, completion: u64| {
            let usage = GatewayUsageMetrics {
                updated_at,
                window_seconds: 60,
                totals: TokenCounts {
                    requests: 2,
                    metered_requests: 2,
                    prompt_tokens: 10,
                    completion_tokens: completion,
                    ..TokenCounts::default()
                },
                window: TokenCounts {
                    requests: 1,
                    metered_requests: 1,
                    completion_tokens: 60,
                    generation_millis: 60_000,
                    ..TokenCounts::default()
                },
            };
            json!({
                "hello": {"hostname": hostname, "node_id": hostname},
                "health": {"platform_metrics": usage.to_platform_metrics()}
            })
        };
        let now = 10_000;
        let peers = json!([
            peer("agora-one", now - 5, 30),
            peer("titan", now - 10, 10),
            peer("gone", now - GATEWAY_USAGE_MAX_AGE_SECONDS - 60, 999),
            json!({"hello": {"hostname": "no-gateway"}, "health": {"platform_metrics": {}}}),
        ]);
        let rendered = render_fleet_usage(&peers, now, false).join("\n");
        assert!(
            rendered.contains(
                "fleet ai usage (2 machines): 4 requests, 20 prompt tokens, 40 completion tokens"
            ),
            "{rendered}"
        );
        assert!(rendered.contains("agora-one requests=2 prompt=10 completion=30 tok/s=1.00"));
        assert!(!rendered.contains("gone"), "{rendered}");
        assert!(!rendered.contains("no-gateway"), "{rendered}");

        let collected: Value =
            serde_json::from_str(&render_fleet_usage(&peers, now, true)[0]).unwrap();
        assert_eq!(collected["hosts"], json!(2));
        assert_eq!(collected["totals"]["completion_tokens"], json!(40));
        assert_eq!(collected["rows"][0]["hostname"], json!("agora-one"));
    }

    #[test]
    fn usage_rendering_makes_unmetered_requests_visible() {
        use mycelium_peer_protocol::gateway_usage::{GatewayUsageSnapshot, TokenCounts};
        let snapshot = GatewayUsageSnapshot {
            schema_version: 1,
            generated_at: 100,
            window_seconds: 60,
            totals: TokenCounts {
                requests: 3,
                metered_requests: 2,
                prompt_tokens: 40,
                completion_tokens: 10,
                generation_millis: 2_000,
                ..TokenCounts::default()
            },
            window: TokenCounts {
                requests: 1,
                metered_requests: 1,
                completion_tokens: 60,
                generation_millis: 1_000,
                ..TokenCounts::default()
            },
            ..GatewayUsageSnapshot::default()
        };
        let rendered = render_usage(&snapshot).join("\n");
        assert!(
            rendered.contains("requests: 3 (metered 2, unmetered 1)"),
            "{rendered}"
        );
        assert!(
            rendered.contains("throughput: 1.00 tok/s now"),
            "{rendered}"
        );
        assert!(
            rendered.contains("60.00 tok/s while generating"),
            "{rendered}"
        );
        assert!(rendered.contains("unmetered requests"), "{rendered}");
    }

    #[test]
    fn home_route_has_no_invented_backend() {
        let routes = default_routes(Path::new("/tmp/mycelium-home"));
        let home = routes["routes"]
            .as_array()
            .unwrap()
            .iter()
            .find(|route| route["name"] == "home")
            .unwrap();
        assert!(home.get("upstream").is_none());
    }

    #[test]
    fn status_reports_a_system_daemon_conflict() {
        let rendered = render_status(&json!({
            "installed": true,
            "system_daemon": "/Library/LaunchDaemons/dev.fpl.mycelium-https.plist",
        }));
        assert!(rendered
            .iter()
            .any(|line| line.contains("system LaunchDaemon")));
    }

    #[test]
    fn legacy_certificate_pair_is_discovered() {
        let home = temporary_dir("legacy");
        let dir = home.join("gateway");
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("server.crt"), "cert").unwrap();
        fs::write(dir.join("server.key"), "key").unwrap();
        let paths = Paths::discover(&home);
        assert_eq!(paths.cert, dir.join("server.crt"));
        assert_eq!(paths.key, dir.join("server.key"));
        fs::remove_dir_all(home).unwrap();
    }

    #[test]
    fn certificate_generation_writes_a_chain_and_private_key() {
        let dir = temporary_dir("cert");
        let material = generate_certificate(&dir, &[]).unwrap();
        assert!(material.generated);
        assert!(material.cert.is_file());
        assert!(material.key.is_file());
        assert!(material.ca.as_ref().unwrap().is_file());
        let chain = fs::read_to_string(&material.cert).unwrap();
        assert_eq!(chain.matches("BEGIN CERTIFICATE").count(), 2);
        let key = fs::read_to_string(&material.key).unwrap();
        assert!(key.contains("PRIVATE KEY"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&material.key).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn certificate_names_cover_capability_hosts() {
        let names = certificate_names(&["tools.myc".to_owned()]);
        for expected in ["ai.myc", "mcp.myc", "home.myc", "webhook.myc", "tools.myc"] {
            assert!(names.contains(&expected.to_owned()));
        }
    }

    #[test]
    fn services_use_the_configured_loopback_and_socket_activation() {
        let home = temporary_dir("plist");
        let dir = home.join("gateway");
        fs::create_dir_all(&dir).unwrap();
        let paths = Paths::discover(&home);
        let material = CertificateMaterial {
            cert: dir.join("server.pem"),
            key: dir.join("server-key.pem"),
            ca: None,
            generated: false,
        };
        let listen: SocketAddr = "127.0.0.1:9443".parse().unwrap();
        let gateway = render_gateway_plist(
            &paths,
            Path::new("/tmp/mycelium-gateway"),
            &paths.routes,
            &material,
            listen,
        );
        let https = render_https_plist(&paths, Path::new("/tmp/mycelium-https-forwarder"), listen);
        assert!(gateway.contains("127.0.0.1:9443"));
        assert!(gateway.contains("--tls-cert"));
        assert!(https.contains("SockServiceName"));
        assert!(https.contains("<integer>443</integer>"));
        assert!(https.contains("127.0.0.1:9443"));
        fs::remove_dir_all(home).unwrap();
    }

    #[test]
    fn systemd_units_use_the_configured_listen() {
        let listen: SocketAddr = "127.0.0.1:10443".parse().unwrap();
        let material = CertificateMaterial {
            cert: PathBuf::from("/home/a/.mycelium/gateway/server.pem"),
            key: PathBuf::from("/home/a/.mycelium/gateway/server-key.pem"),
            ca: None,
            generated: false,
        };
        let gateway = render_gateway_unit(
            Path::new("/home/a/.mycelium/gateway/usage.json"),
            listen,
            Path::new("/home/a/.mycelium/bin/mycelium-gateway"),
            Path::new("/home/a/.mycelium/gateway/routes.json"),
            &material,
        )
        .unwrap();
        assert!(gateway.contains("--listen 127.0.0.1:10443"));
        assert!(gateway.contains("--usage \"/home/a/.mycelium/gateway/usage.json\""));
        assert!(gateway.contains("Restart=on-failure"));
        assert!(gateway.contains("mycelium-gateway"));
        let socket = render_https_socket_unit();
        assert!(socket.contains("ListenStream=127.0.0.1:443"));
        assert!(socket.contains("Service=mycelium-https.service"));
        let forwarder = render_https_service_unit(
            listen,
            Path::new("/home/a/.mycelium/bin/mycelium-https-forwarder"),
        )
        .unwrap();
        assert!(forwarder.contains("--target 127.0.0.1:10443"));
    }

    #[test]
    fn listen_parsing_rejects_unsafe_addresses() {
        let expected: SocketAddr = "127.0.0.1:10443".parse().unwrap();
        let text = if cfg!(target_os = "macos") {
            "<string>--listen</string><string>127.0.0.1:10443</string>"
        } else {
            "ExecStart=/x --listen 127.0.0.1:10443 --routes /r"
        };
        assert_eq!(parse_listen(text), Some(expected));
        assert!(listen_addr("0.0.0.0:8443").is_err());
        assert!(listen_addr("127.0.0.1:443").is_err());
        assert!(listen_addr("127.0.0.1:0").is_err());
    }
}
