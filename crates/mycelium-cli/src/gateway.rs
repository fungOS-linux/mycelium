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

const GATEWAY_LABEL: &str = "dev.fpl.mycelium-gateway";
const HTTPS_LABEL: &str = "dev.fpl.mycelium-https";
const GATEWAY_PORT: u16 = 8443;
const HTTPS_PORT: u16 = 443;
const GATEWAY_ADDR: &str = "127.0.0.1:8443";
const HTTPS_ADDR: &str = "127.0.0.1:443";

const USAGE: &str = "mycelium gateway status [--json] [--path MYCELIUM-HOME]\n\
mycelium gateway install [--write|--dry-run] [--trust-cert] [--routes PATH] [--cert PATH --key PATH] [--gateway-bin PATH] [--forwarder-bin PATH] [--path MYCELIUM-HOME]\n\
mycelium gateway uninstall [--write|--dry-run] [--path MYCELIUM-HOME]";

#[derive(Clone, Debug)]
pub struct Paths {
    pub home: PathBuf,
    pub dir: PathBuf,
    pub routes: PathBuf,
    pub cert: PathBuf,
    pub key: PathBuf,
    pub ca: PathBuf,
    pub gateway_bin: PathBuf,
    pub forwarder_bin: PathBuf,
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
            cert,
            key,
            ca: home.join("gateway/ca.pem"),
            gateway_bin: home.join("bin/mycelium-gateway"),
            forwarder_bin: home.join("bin/mycelium-https-forwarder"),
        }
    }
}

#[derive(Clone, Debug)]
struct InstallOptions {
    home: PathBuf,
    routes: Option<PathBuf>,
    cert: Option<PathBuf>,
    key: Option<PathBuf>,
    gateway_bin: Option<PathBuf>,
    forwarder_bin: Option<PathBuf>,
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
            GATEWAY_ADDR
        } else {
            "down"
        }
    ));
    lines.push(format!(
        "  https listener: {}",
        if value["https_listening"].as_bool().unwrap_or(false) {
            HTTPS_ADDR
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
    let gateway_plist = launch_agent_path(GATEWAY_LABEL);
    let https_plist = launch_agent_path(HTTPS_LABEL);
    let installed = gateway_plist.as_ref().is_ok_and(|path| path.is_file())
        && https_plist.as_ref().is_ok_and(|path| path.is_file());
    let gateway_listening = tcp_probe(GATEWAY_PORT);
    let https_listening = tcp_probe(HTTPS_PORT);
    let certificate_trusted = paths.cert.is_file() && certificate_trusted(&paths.cert);
    let health = if gateway_listening {
        probe(GATEWAY_PORT).await.ok()
    } else {
        None
    };
    let tls = if gateway_listening {
        Some(tls_chain_verified(&paths, GATEWAY_PORT))
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
        "gateway_agent": launchd_state(GATEWAY_LABEL),
        "https_agent": launchd_state(HTTPS_LABEL),
        "gateway_listening": gateway_listening,
        "https_listening": https_listening,
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
    if !cfg!(target_os = "macos") && !options.dry_run {
        return Err("local HTTPS gateway installation currently supports macOS LaunchAgents; Linux socket units are a follow-up".into());
    }
    if options.cert.is_some() != options.key.is_some() {
        return Err("--cert and --key must be provided together".into());
    }

    let paths = Paths::discover(&options.home);
    preflight()?;
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
    let material = prepare_certificate(&paths, &options, &mut actions)?;
    let routes = prepare_routes(&paths, &options, &mut actions)?;

    if options.dry_run {
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
            "would write {}/{}.plist",
            launch_agent_dir().display(),
            GATEWAY_LABEL
        ));
        actions.push(format!(
            "would write {}/{}.plist",
            launch_agent_dir().display(),
            HTTPS_LABEL
        ));
        if options.trust {
            actions.push(format!(
                "would trust {} for the login keychain",
                material.trust_anchor().display()
            ));
        }
        return Ok(actions);
    }

    create_private_dir(&paths.dir)?;
    let gateway_bin = install_binary(&gateway_source, &paths.gateway_bin)?;
    let forwarder_bin = install_binary(&forwarder_source, &paths.forwarder_bin)?;
    let gateway_plist = write_named_plist(
        GATEWAY_LABEL,
        &render_gateway_plist(&paths, &gateway_bin, &routes, &material),
    )?;
    let https_plist = write_named_plist(HTTPS_LABEL, &render_https_plist(&paths, &forwarder_bin))?;
    if options.trust {
        trust_certificate(material.trust_anchor())?;
        if !certificate_trusted(&material.cert) {
            return Err(format!(
                "certificate {} does not verify for ai.myc after trust installation",
                material.cert.display()
            ));
        }
    }

    bootstrap(GATEWAY_LABEL, &gateway_plist)?;
    bootstrap(HTTPS_LABEL, &https_plist)?;
    wait_for_listener(GATEWAY_PORT)?;
    let health = wait_for_https(HTTPS_PORT).await?;
    if health["status"].as_u64() != Some(200) {
        return Err(format!(
            "installed the gateway, but https://ai.myc/healthz returned HTTP {}",
            health["status"]
        ));
    }
    tls_chain_verified(&paths, HTTPS_PORT).map_err(|error| {
        format!("installed the gateway, but the :{HTTPS_PORT} TLS check failed: {error}")
    })?;

    let mut lines = vec![format!(
        "installed local HTTPS gateway for {}",
        options.home.display()
    )];
    lines.push(format!("  gateway: {}", gateway_bin.display()));
    lines.push(format!("  forwarder: {}", forwarder_bin.display()));
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

fn preflight() -> Result<(), String> {
    if let Some(path) = system_daemon_path() {
        return Err(format!(
            "{} also claims 127.0.0.1:{HTTPS_PORT} for the system launchd domain; remove it before installing the user agent: sudo launchctl bootout system/{HTTPS_LABEL} && sudo rm {}",
            path.display(),
            path.display()
        ));
    }
    ensure_port_available(GATEWAY_LABEL, GATEWAY_PORT)?;
    ensure_port_available(HTTPS_LABEL, HTTPS_PORT)
}

/// Refuse to start when a listener already owns the port and is not the
/// Mycelium job we are about to replace. A socket-activated job counts as ours
/// while launchd reports it as `waiting` or `running` and its plist is present.
fn ensure_port_available(label: &str, port: u16) -> Result<(), String> {
    if !tcp_probe(port) {
        return Ok(());
    }
    let plist_present = launch_agent_path(label).is_ok_and(|path| path.is_file());
    let state = launchd_state(label);
    let healthy = matches!(state["state"].as_str(), Some("running") | Some("waiting"));
    if plist_present && state["loaded"].as_bool() == Some(true) && healthy {
        return Ok(());
    }
    let owners = listener_pids(port);
    Err(format!(
        "cannot install {label}: 127.0.0.1:{port} is already in use by {}; stop that listener and retry",
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

fn listener_pids(port: u16) -> Vec<u32> {
    let Ok(output) = Command::new("lsof")
        .arg("-nP")
        .arg(format!("-iTCP:{port}"))
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

fn parse_install(args: &[String]) -> Result<InstallOptions, String> {
    let mut options = InstallOptions::new();
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--write" => options.write = true,
            "--dry-run" => options.dry_run = true,
            "--trust-cert" => options.trust = true,
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
    let material = generate_certificate(&paths.dir)?;
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

fn generate_certificate(dir: &Path) -> Result<CertificateMaterial, String> {
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
    let mut leaf_params =
        CertificateParams::new(vec!["*.myc".into(), "localhost".into(), "127.0.0.1".into()])
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
) -> String {
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\"><dict>\n<key>Label</key><string>{label}</string>\n<key>ProgramArguments</key><array><string>{gateway}</string><string>--listen</string><string>{listen}</string><string>--routes</string><string>{routes}</string><string>--reload-secs</string><string>1</string><string>--tls-cert</string><string>{cert}</string><string>--tls-key</string><string>{key}</string></array>\n<key>RunAtLoad</key><true/><key>KeepAlive</key><true/><key>ThrottleInterval</key><integer>10</integer>\n<key>StandardOutPath</key><string>{log}</string>\n<key>StandardErrorPath</key><string>{log}</string>\n</dict></plist>\n",
        label = xml(GATEWAY_LABEL),
        gateway = xml(&gateway_bin.display().to_string()),
        listen = GATEWAY_ADDR,
        routes = xml(&routes.display().to_string()),
        cert = xml(&material.cert.display().to_string()),
        key = xml(&material.key.display().to_string()),
        log = xml(&paths.dir.join("gateway.log").display().to_string()),
    )
}

fn render_https_plist(paths: &Paths, forwarder_bin: &Path) -> String {
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\"><dict>\n<key>Label</key><string>{label}</string>\n<key>ProgramArguments</key><array><string>{forwarder}</string><string>--target</string><string>{listen}</string></array>\n<key>RunAtLoad</key><true/><key>ThrottleInterval</key><integer>5</integer>\n<key>StandardErrorPath</key><string>{log}</string>\n<key>Sockets</key><dict><key>HTTPS</key><dict><key>SockNodeName</key><string>127.0.0.1</string><key>SockServiceName</key><integer>{port}</integer><key>SockFamily</key><string>IPv4</string><key>SockType</key><string>stream</string><key>SockProtocol</key><string>TCP</string></dict></dict>\n</dict></plist>\n",
        label = xml(HTTPS_LABEL),
        forwarder = xml(&forwarder_bin.display().to_string()),
        listen = GATEWAY_ADDR,
        log = xml(&paths.dir.join("https-forwarder.log").display().to_string()),
        port = HTTPS_PORT,
    )
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

fn wait_for_listener(port: u16) -> Result<(), String> {
    let address = SocketAddr::from(([127, 0, 0, 1], port));
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

fn tcp_probe(port: u16) -> bool {
    // Prefer lsof: a bare TCP connect to the socket-activated :443 would wake
    // the forwarder and log a failed TLS handshake on every status check.
    if !listener_pids(port).is_empty() {
        return true;
    }
    TcpStream::connect_timeout(
        &SocketAddr::from(([127, 0, 0, 1], port)),
        Duration::from_millis(300),
    )
    .is_ok()
}

async fn wait_for_https(port: u16) -> Result<Value, String> {
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        match probe(port).await {
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
    let output = Command::new("id")
        .arg("-u")
        .output()
        .map_err(|error| format!("determine user id: {error}"))?;
    if !output.status.success() {
        return Err("id -u failed".into());
    }
    Ok(format!(
        "gui/{}",
        String::from_utf8_lossy(&output.stdout).trim()
    ))
}

fn launchd_state(label: &str) -> Value {
    if !cfg!(target_os = "macos") {
        return json!({"supported": false, "loaded": false, "state": "unsupported"});
    }
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

fn launch_agent_dir() -> PathBuf {
    user_home()
        .map(|home| home.join("Library/LaunchAgents"))
        .unwrap_or_else(|_| PathBuf::from("Library/LaunchAgents"))
}

fn launch_agent_path(label: &str) -> Result<PathBuf, String> {
    if !cfg!(target_os = "macos") {
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
    json!({
        "mycelium_bin": mycelium.display().to_string(),
        "service_refresh_secs": 15,
        "routes": [
            {
                "name": "bifrost",
                "hosts": ["ai.myc", "api.myc"],
                "upstream": "http://127.0.0.1:4000",
                "service_kind": "ai",
                "priority": 10
            },
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
async fn probe(port: u16) -> Result<Value, String> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(3))
        .resolve("ai.myc", SocketAddr::from(([127, 0, 0, 1], port)))
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
fn tls_chain_verified(paths: &Paths, port: u16) -> Result<(), String> {
    let anchor = if paths.ca.is_file() {
        &paths.ca
    } else {
        &paths.cert
    };
    if !anchor.is_file() {
        return Err(format!("trust anchor missing: {}", anchor.display()));
    }
    let output = Command::new("openssl")
        .args([
            "s_client",
            "-connect",
            &format!("127.0.0.1:{port}"),
            "-servername",
            "ai.myc",
            "-CAfile",
        ])
        .arg(anchor)
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
    Err(format!(
        "127.0.0.1:{port} certificate check failed: {detail}"
    ))
}

fn system_daemon_path() -> Option<PathBuf> {
    let path = Path::new("/Library/LaunchDaemons").join(format!("{HTTPS_LABEL}.plist"));
    path.is_file().then_some(path)
}

fn certificate_trusted(cert: &Path) -> bool {
    if !cfg!(target_os = "macos") || !cert.is_file() {
        return false;
    }
    Command::new("security")
        .args(["verify-cert", "-c"])
        .arg(cert)
        .args(["-p", "ssl", "-s", "ai.myc"])
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
}

fn trust_certificate(cert: &Path) -> Result<(), String> {
    if !cfg!(target_os = "macos") {
        return Err("--trust-cert is supported only on macOS".into());
    }
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
    let paths = [
        launch_agent_path(GATEWAY_LABEL)?,
        launch_agent_path(HTTPS_LABEL)?,
    ];
    if dry_run {
        return Ok(paths
            .iter()
            .map(|path| format!("would remove {}", path.display()))
            .collect());
    }
    let domain = launch_domain()?;
    for label in [GATEWAY_LABEL, HTTPS_LABEL] {
        let _ = Command::new("launchctl")
            .args(["bootout", &format!("{domain}/{label}")])
            .output();
    }
    for path in paths {
        if path.exists() {
            fs::remove_file(&path)
                .map_err(|error| format!("remove {}: {error}", path.display()))?;
        }
    }
    let mut lines = vec![
        format!("removed user launch agents for {}", home.display()),
        "routes and certificates were retained".into(),
    ];
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
        let material = generate_certificate(&dir).unwrap();
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
    fn plists_use_loopback_and_socket_activation() {
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
        let gateway = render_gateway_plist(
            &paths,
            Path::new("/tmp/mycelium-gateway"),
            &paths.routes,
            &material,
        );
        let https = render_https_plist(&paths, Path::new("/tmp/mycelium-https-forwarder"));
        assert!(gateway.contains("127.0.0.1:8443"));
        assert!(gateway.contains("--tls-cert"));
        assert!(https.contains("SockServiceName"));
        assert!(https.contains("<integer>443</integer>"));
        assert!(https.contains("127.0.0.1:8443"));
        fs::remove_dir_all(home).unwrap();
    }
}
