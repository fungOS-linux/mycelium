use std::path::{Path, PathBuf};
use std::process::Command;

use myceliumd::client::ClientError;

pub struct Issue<'a> {
    pub name: &'a str,
    pub site: &'a str,
    pub address: &'a str,
    pub additional_addresses: &'a [String],
    pub target: &'a str,
    pub binary: &'a Path,
    pub peers: &'a [String],
    pub output: &'a Path,
}

pub fn init(path: &Path) -> Result<Vec<String>, ClientError> {
    if path.join("ca-key.pem").exists() || path.join("ca.pem").exists() {
        return Err(usage("enrollment CA already exists"));
    }
    std::fs::create_dir_all(path).map_err(ClientError::Io)?;
    openssl(&[
        "genpkey",
        "-algorithm",
        "ED25519",
        "-out",
        &display(path.join("ca-key.pem"))?,
    ])?;
    openssl(&[
        "req",
        "-x509",
        "-new",
        "-key",
        &display(path.join("ca-key.pem"))?,
        "-out",
        &display(path.join("ca.pem"))?,
        "-subj",
        "/CN=Mycelium Mesh CA",
        "-days",
        "3650",
    ])?;
    owner_only(&path.join("ca-key.pem"))?;
    Ok(vec![format!(
        "initialized enrollment CA at {}; back up ca-key.pem offline",
        path.display()
    )])
}

pub(crate) fn sign_csr(
    ca: &Path,
    csr_pem: &str,
    expected_name: &str,
    work_dir: &Path,
) -> Result<String, String> {
    validate_label("name", expected_name).map_err(|error| error.to_string())?;
    if !ca.join("ca-key.pem").is_file() || !ca.join("ca.pem").is_file() {
        return Err("enrollment CA is missing ca.pem or ca-key.pem".into());
    }
    if !csr_pem.starts_with("-----BEGIN CERTIFICATE REQUEST-----") {
        return Err("peer CSR is not PEM encoded".into());
    }
    let csr = work_dir.join("node.csr");
    let cert = work_dir.join("node.pem");
    let extensions = work_dir.join("node-extensions.cnf");
    std::fs::write(&csr, csr_pem).map_err(|error| format!("stage peer CSR: {error}"))?;
    std::fs::write(
        &extensions,
        format!("[mycelium_peer]\nextendedKeyUsage=serverAuth,clientAuth\n{}\n",
            subject_alt_name(&std::collections::BTreeSet::from([expected_name]))),
    )
    .map_err(|error| format!("stage peer certificate extensions: {error}"))?;
    openssl_string(&[
        "req",
        "-in",
        &display(&csr).map_err(|error| error.to_string())?,
        "-noout",
        "-verify",
    ])?;
    let subject = openssl_output(&[
        "req",
        "-in",
        &display(&csr).map_err(|error| error.to_string())?,
        "-noout",
        "-subject",
        "-nameopt",
        "RFC2253",
    ])?;
    if subject.trim() != format!("subject=CN={expected_name}") {
        return Err(format!(
            "peer CSR subject must be exactly CN={expected_name}; got {}",
            subject.trim()
        ));
    }
    openssl_string(&[
        "x509",
        "-req",
        "-in",
        &display(&csr).map_err(|error| error.to_string())?,
        "-CA",
        &display(ca.join("ca.pem")).map_err(|error| error.to_string())?,
        "-CAkey",
        &display(ca.join("ca-key.pem")).map_err(|error| error.to_string())?,
        "-CAcreateserial",
        "-extfile",
        &display(&extensions).map_err(|error| error.to_string())?,
        "-extensions",
        "mycelium_peer",
        "-out",
        &display(&cert).map_err(|error| error.to_string())?,
        "-days",
        "365",
    ])?;
    std::fs::read_to_string(cert).map_err(|error| format!("read signed peer certificate: {error}"))
}

pub fn issue(ca: &Path, request: Issue<'_>) -> Result<Vec<String>, ClientError> {
    validate_label("name", request.name)?;
    validate_label("site", request.site)?;
    validate_label("target", request.target)?;
    validate_address(request.address)?;
    for address in request.additional_addresses {
        validate_address(address)?;
    }
    if !ca.join("ca-key.pem").is_file() || !ca.join("ca.pem").is_file() {
        return Err(usage("enrollment CA is missing ca.pem or ca-key.pem"));
    }
    if !request.binary.is_file() {
        return Err(usage("enrollment binary does not exist"));
    }
    if request.output.exists() {
        return Err(usage("enrollment output already exists"));
    }
    std::fs::create_dir_all(request.output).map_err(ClientError::Io)?;
    let key = request.output.join("node-key.pem");
    let csr = request.output.join("node.csr");
    let cert = request.output.join("node.pem");
    let addresses = std::iter::once(request.address)
        .chain(request.additional_addresses.iter().map(String::as_str))
        .collect::<std::collections::BTreeSet<_>>();
    let san = subject_alt_name(&addresses);
    openssl(&["genpkey", "-algorithm", "ED25519", "-out", &display(&key)?])?;
    openssl(&[
        "req",
        "-new",
        "-key",
        &display(&key)?,
        "-out",
        &display(&csr)?,
        "-subj",
        &format!("/CN={}", request.name),
        "-addext",
        &san,
        "-addext",
        "extendedKeyUsage=serverAuth,clientAuth",
    ])?;
    openssl(&[
        "x509",
        "-req",
        "-in",
        &display(&csr)?,
        "-CA",
        &display(ca.join("ca.pem"))?,
        "-CAkey",
        &display(ca.join("ca-key.pem"))?,
        "-CAcreateserial",
        "-copy_extensions",
        "copy",
        "-out",
        &display(&cert)?,
        "-days",
        "365",
    ])?;
    std::fs::copy(ca.join("ca.pem"), request.output.join("ca.pem")).map_err(ClientError::Io)?;
    std::fs::copy(request.binary, request.output.join("mycelium")).map_err(ClientError::Io)?;
    owner_only(&key)?;
    executable(&request.output.join("mycelium"))?;
    let release_keys = std::env::var("MYCELIUM_RELEASE_KEYS").unwrap_or_default();
    let access_keys = std::env::var("MYCELIUM_ACCESS_KEYS").unwrap_or_default();
    let authority_keys = std::env::var("MYCELIUM_AUTHORITY_KEYS").unwrap_or_default();
    let peer_list = request.peers.join(",");
    std::fs::write(
        request.output.join("node.env"),
        format!(
            "MYCELIUM_SITE={}\nMYCELIUM_PEER_LISTEN=0.0.0.0:7443\nMYCELIUM_PEERS={}\nMYCELIUM_PEER_CA=pki/ca.pem\nMYCELIUM_PEER_CERT=pki/node.pem\nMYCELIUM_PEER_KEY=pki/node-key.pem\nMYCELIUM_AUTHORITY_KEYS={}\nMYCELIUM_RELEASE_KEYS={}\nMYCELIUM_ACCESS_KEYS={}\nMYCELIUM_UPDATE_CHANNEL=canary\n",
            request.site, peer_list, authority_keys, release_keys, access_keys
        ),
    )
    .map_err(ClientError::Io)?;
    std::fs::write(
        request.output.join("manifest.json"),
        serde_json::to_vec_pretty(&serde_json::json!({
            "name": request.name,
            "site": request.site,
            "address": request.address,
            "addresses": addresses,
            "target": request.target,
            "peers": request.peers,
        }))
        .map_err(|error| usage(&error.to_string()))?,
    )
    .map_err(ClientError::Io)?;
    std::fs::write(request.output.join("mycelium.service"), systemd_unit())
        .map_err(ClientError::Io)?;
    std::fs::write(
        request.output.join("dev.fpl.mycelium.plist"),
        launchd_plist(
            request.site,
            &peer_list,
            &authority_keys,
            &release_keys,
            &access_keys,
        ),
    )
    .map_err(ClientError::Io)?;
    let _ = std::fs::remove_file(csr);
    Ok(vec![format!(
        "issued {} ({}) enrollment bundle at {}",
        request.name,
        request.target,
        request.output.display()
    )])
}

pub fn install(bundle: &Path, home: &Path) -> Result<Vec<String>, ClientError> {
    let packaged = crate::packaged::current().map_err(|error| usage(&error))?;
    if packaged {
        crate::packaged::validate_new_peer(home, true).map_err(|error| usage(&error))?;
    }
    for name in [
        "mycelium",
        "ca.pem",
        "node.pem",
        "node-key.pem",
        "manifest.json",
    ] {
        if !bundle.join(name).is_file() {
            return Err(usage(&format!("enrollment bundle is missing {name}")));
        }
    }
    let manifest: serde_json::Value = serde_json::from_slice(
        &std::fs::read(bundle.join("manifest.json")).map_err(ClientError::Io)?,
    )
    .map_err(|error| usage(&format!("invalid enrollment manifest: {error}")))?;
    let site = manifest["site"]
        .as_str()
        .ok_or_else(|| usage("manifest is missing site"))?;
    validate_label("site", site)?;
    let peers = manifest["peers"]
        .as_array()
        .ok_or_else(|| usage("manifest is missing peers"))?
        .iter()
        .map(|value| {
            value
                .as_str()
                .ok_or_else(|| usage("manifest peer is not text"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    for peer in &peers {
        validate_peer(peer)?;
    }

    let bin = home.join("bin/mycelium");
    let pki = home.join("pki");
    if packaged {
        crate::packaged::private_home(home).map_err(|error| usage(&error))?;
        crate::packaged::ensure_binding(home).map_err(|error| usage(&error))?;
    } else {
        std::fs::create_dir_all(bin.parent().unwrap()).map_err(ClientError::Io)?;
        copy_mode(&bundle.join("mycelium"), &bin, 0o755)?;
    }
    std::fs::create_dir_all(&pki).map_err(ClientError::Io)?;
    copy_mode(&bundle.join("ca.pem"), &pki.join("ca.pem"), 0o644)?;
    copy_mode(&bundle.join("node.pem"), &pki.join("node.pem"), 0o644)?;
    copy_mode(
        &bundle.join("node-key.pem"),
        &pki.join("node-key.pem"),
        0o600,
    )?;

    let release_keys = std::env::var("MYCELIUM_RELEASE_KEYS").unwrap_or_default();
    let access_keys = std::env::var("MYCELIUM_ACCESS_KEYS").unwrap_or_default();
    let authority_keys = std::env::var("MYCELIUM_AUTHORITY_KEYS").unwrap_or_default();
    let peers = peers.join(",");
    std::fs::write(
        home.join("node.env"),
        resolved_env(
            home,
            site,
            &peers,
            &authority_keys,
            &release_keys,
            &access_keys,
        )?,
    )
    .map_err(ClientError::Io)?;
    if packaged { owner_only(&home.join("node.env"))?; }
    let service = if packaged {
        crate::packaged::service_path()
    } else if cfg!(target_os = "macos") {
        let path = user_home()?.join("Library/LaunchAgents/dev.fpl.mycelium.plist");
        std::fs::create_dir_all(path.parent().unwrap()).map_err(ClientError::Io)?;
        std::fs::write(
            &path,
            resolved_launchd(
                home,
                site,
                &peers,
                &authority_keys,
                &release_keys,
                &access_keys,
                None,
            )?,
        )
        .map_err(ClientError::Io)?;
        path
    } else if cfg!(target_os = "linux") {
        let path = user_home()?.join(".config/systemd/user/mycelium.service");
        std::fs::create_dir_all(path.parent().unwrap()).map_err(ClientError::Io)?;
        std::fs::write(&path, resolved_systemd(home)?).map_err(ClientError::Io)?;
        path
    } else {
        return Err(usage("enrollment install supports Darwin and Linux"));
    };
    Ok(vec![
        format!("installed enrolled peer under {}", home.display()),
        format!("{} {}; service was not started", if packaged { "retained package-owned" } else { "wrote" }, service.display()),
    ])
}

pub(crate) fn install_peer_material(
    home: &Path,
    key: &Path,
    certificate_pem: &str,
    ca_pem: &str,
    site: &str,
    peers: &[String],
    system_service: bool,
    iroh_server_name: Option<&str>,
) -> Result<Vec<String>, String> {
    let packaged = crate::packaged::current()?;
    if packaged {
        crate::packaged::validate(home, system_service)?;
        crate::packaged::private_home(home)?;
        crate::packaged::ensure_binding(home)?;
    }
    validate_label("site", site).map_err(|error| error.to_string())?;
    if let Some(name) = iroh_server_name {
        validate_label("Iroh server name", name).map_err(|error| error.to_string())?;
    }
    for peer in peers {
        validate_peer(peer).map_err(|error| error.to_string())?;
    }
    let bin = home.join("bin/mycelium");
    let pki = home.join("pki");
    std::fs::create_dir_all(&pki).map_err(|error| format!("create {}: {error}", pki.display()))?;
    if !packaged {
        std::fs::create_dir_all(bin.parent().expect("bin has a parent"))
            .map_err(|error| format!("create binary directory: {error}"))?;
        copy_mode(
            &std::env::current_exe().map_err(|error| format!("locate current binary: {error}"))?,
            &bin,
            0o755,
        ).map_err(|error| error.to_string())?;
    }
    copy_mode(key, &pki.join("node-key.pem"), 0o600).map_err(|error| error.to_string())?;
    std::fs::write(pki.join("node.pem"), certificate_pem)
        .map_err(|error| format!("install node certificate: {error}"))?;
    std::fs::write(pki.join("ca.pem"), ca_pem)
        .map_err(|error| format!("install mesh CA: {error}"))?;
    let release_keys = std::env::var("MYCELIUM_RELEASE_KEYS").unwrap_or_default();
    let access_keys = std::env::var("MYCELIUM_ACCESS_KEYS").unwrap_or_default();
    let authority_keys = std::env::var("MYCELIUM_AUTHORITY_KEYS").unwrap_or_default();
    let peers = peers.join(",");
    std::fs::write(
        home.join("node.env"),
        format!("{}{}", resolved_env(
            home,
            site,
            &peers,
            &authority_keys,
            &release_keys,
            &access_keys,
        )
        .map_err(|error| error.to_string())?, iroh_server_name
            .map(|name| format!("MYCELIUM_IROH_SERVER_NAME={name}\n")).unwrap_or_default()),
    )
    .map_err(|error| format!("write node environment: {error}"))?;
    if packaged { owner_only(&home.join("node.env")).map_err(|error| error.to_string())?; }
    let service = write_peer_service(
        home,
        site,
        &peers,
        &authority_keys,
        &release_keys,
        &access_keys,
        iroh_server_name,
        system_service,
    )?;
    start_peer_service(&service, home, system_service)?;
    Ok(vec![
        format!("installed peer identity under {}", home.display()),
        format!("started peer service from {}", service.display()),
    ])
}

pub(crate) fn repair_peer_service(
    home: &Path,
    site_override: Option<&str>,
    system_service: bool,
) -> Result<Vec<String>, String> {
    let packaged = crate::packaged::current()?;
    if packaged {
        crate::packaged::validate(home, system_service)?;
        crate::packaged::private_home(home)?;
        crate::packaged::ensure_binding(home)?;
    }
    for required in ["node.env", "pki/ca.pem", "pki/node.pem", "pki/node-key.pem"] {
        if !home.join(required).is_file() {
            return Err(format!(
                "cannot repair peer service: {} is missing",
                home.join(required).display()
            ));
        }
    }
    let managed_binary = home.join("bin/mycelium");
    let current_binary = std::env::current_exe()
        .map_err(|error| format!("locate current Mycelium binary: {error}"))?;
    if !packaged && current_binary != managed_binary {
        std::fs::create_dir_all(
            managed_binary
                .parent()
                .expect("managed binary has a parent"),
        )
        .map_err(|error| format!("create managed binary directory: {error}"))?;
        copy_mode(&current_binary, &managed_binary, 0o755).map_err(|error| error.to_string())?;
    }
    let mut environment = std::fs::read_to_string(home.join("node.env"))
        .map_err(|error| format!("read node environment: {error}"))?;
    if let Some(site) = site_override {
        validate_label("site", site).map_err(|error| error.to_string())?;
        environment = replace_environment_value(&environment, "MYCELIUM_SITE", site)?;
        std::fs::write(home.join("node.env"), &environment)
            .map_err(|error| format!("update node site: {error}"))?;
    }
    let setting = |name: &str| -> Result<&str, String> {
        environment
            .lines()
            .find_map(|line| line.strip_prefix(&format!("{name}=")))
            .ok_or_else(|| format!("node environment is missing {name}"))
    };
    let site = setting("MYCELIUM_SITE")?;
    let peers = setting("MYCELIUM_PEERS")?;
    let release_keys = setting("MYCELIUM_RELEASE_KEYS").unwrap_or("");
    let access_keys = setting("MYCELIUM_ACCESS_KEYS").unwrap_or("");
    let authority_keys = setting("MYCELIUM_AUTHORITY_KEYS").unwrap_or("");
    // node.env is the canonical store (systemd reads it via
    // EnvironmentFile); launchd cannot, so repair must carry the Iroh
    // server name into the plist explicitly or macOS sync stays off.
    let iroh_server_name = setting("MYCELIUM_IROH_SERVER_NAME").ok();
    validate_label("site", site).map_err(|error| error.to_string())?;
    for peer in peers.split(',').filter(|peer| !peer.is_empty()) {
        validate_peer(peer).map_err(|error| error.to_string())?;
    }
    let service = write_peer_service(
        home,
        site,
        peers,
        authority_keys,
        release_keys,
        access_keys,
        iroh_server_name,
        system_service,
    )?;
    start_peer_service(&service, home, system_service)?;
    Ok(vec![format!(
        "repaired and verified peer service from {}",
        service.display()
    )])
}

fn replace_environment_value(source: &str, name: &str, value: &str) -> Result<String, String> {
    let prefix = format!("{name}=");
    let mut replaced = false;
    let mut lines = source
        .lines()
        .map(|line| {
            if line.starts_with(&prefix) {
                replaced = true;
                format!("{prefix}{value}")
            } else {
                line.to_owned()
            }
        })
        .collect::<Vec<_>>();
    if !replaced {
        return Err(format!("node environment is missing {name}"));
    }
    lines.push(String::new());
    Ok(lines.join("\n"))
}

fn write_peer_service(
    home: &Path,
    site: &str,
    peers: &str,
    authority_keys: &str,
    release_keys: &str,
    access_keys: &str,
    iroh_server_name: Option<&str>,
    system_service: bool,
) -> Result<PathBuf, String> {
    if crate::packaged::current()? {
        crate::packaged::validate(home, system_service)?;
        return Ok(crate::packaged::service_path());
    }
    if system_service {
        if !cfg!(target_os = "linux") {
            return Err("system peer service is supported only on Linux".into());
        }
        let output = Command::new("id")
            .arg("-u")
            .output()
            .map_err(|error| format!("determine user id: {error}"))?;
        if !output.status.success() || String::from_utf8_lossy(&output.stdout).trim() != "0" {
            return Err("--system-service requires root".into());
        }
        let path = PathBuf::from("/etc/systemd/system/mycelium.service");
        std::fs::write(
            &path,
            resolved_systemd(home).map_err(|error| error.to_string())?,
        )
        .map_err(|error| format!("write systemd system unit: {error}"))?;
        return Ok(path);
    }
    if cfg!(target_os = "macos") {
        let path = user_home()
            .map_err(|error| error.to_string())?
            .join("Library/LaunchAgents/dev.fpl.mycelium.plist");
        std::fs::create_dir_all(path.parent().expect("plist has a parent"))
            .map_err(|error| format!("create launch agent directory: {error}"))?;
        std::fs::write(
            &path,
            resolved_launchd(home, site, peers, authority_keys, release_keys, access_keys, iroh_server_name)
                .map_err(|error| error.to_string())?,
        )
        .map_err(|error| format!("write launch agent: {error}"))?;
        Ok(path)
    } else if cfg!(target_os = "linux") {
        let path = user_home()
            .map_err(|error| error.to_string())?
            .join(".config/systemd/user/mycelium.service");
        std::fs::create_dir_all(path.parent().expect("unit has a parent"))
            .map_err(|error| format!("create systemd directory: {error}"))?;
        std::fs::write(
            &path,
            resolved_systemd(home).map_err(|error| error.to_string())?,
        )
        .map_err(|error| format!("write systemd unit: {error}"))?;
        Ok(path)
    } else {
        Err("peer enrollment supports Darwin and Linux".into())
    }
}

fn start_peer_service(service: &Path, home: &Path, system_service: bool) -> Result<(), String> {
    // A CLI-autostarted daemon has no enrolled environment and otherwise wins
    // the Unix socket race against the managed service.
    let _ = Command::new(
        std::env::current_exe().map_err(|error| format!("locate current binary: {error}"))?,
    )
    .args(["daemon", "stop"])
    .env("MYCELIUM_NO_AUTOSTART", "1")
    .env("MYCELIUM_HOME", home)
    .status();
    std::thread::sleep(std::time::Duration::from_millis(300));
    if cfg!(target_os = "macos") {
        let output = Command::new("id")
            .arg("-u")
            .output()
            .map_err(|error| format!("determine user id: {error}"))?;
        if !output.status.success() {
            return Err("id -u failed while starting peer service".into());
        }
        let domain = format!("gui/{}", String::from_utf8_lossy(&output.stdout).trim());
        let _ = Command::new("launchctl")
            .args(["bootout", &format!("{domain}/dev.fpl.mycelium")])
            .status();
        let status = Command::new("launchctl")
            .args(["bootstrap", &domain])
            .arg(service)
            .status()
            .map_err(|error| format!("start launch agent: {error}"))?;
        if !status.success() {
            return Err(format!("launchctl bootstrap exited with {status}"));
        }
    } else {
        for args in systemd_start_commands(system_service) {
            let status = Command::new("systemctl")
                .args(*args)
                .status()
                .map_err(|error| format!("run systemctl: {error}"))?;
            if !status.success() {
                return Err(format!("systemctl {} exited with {status}", args.join(" ")));
            }
        }
    }
    // A peer with several unreachable seeds can spend more than ten seconds
    // establishing its first mesh round before the local readiness probes are
    // both observable. Keep the check bounded, but do not report a healthy
    // launchd/systemd service as failed merely because its WAN peers are slow.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    let socket = home.join("myceliumd.sock");
    loop {
        let socket_ready = socket.exists();
        let listener_ready = std::net::TcpStream::connect("127.0.0.1:7443").is_ok();
        if socket_ready && listener_ready {
            return Ok(());
        }
        if std::time::Instant::now() >= deadline {
            return Err(format!(
                "managed peer service did not create {} and listen on 127.0.0.1:7443 within 30 seconds; inspect {}",
                socket.display(),
                home.join("daemon.log").display()
            ));
        }
        std::thread::sleep(std::time::Duration::from_millis(200));
    }
}

fn systemd_start_commands(system_service: bool) -> &'static [&'static [&'static str]] {
    if system_service {
        &[&["daemon-reload"], &["enable", "--now", "mycelium.service"]]
    } else {
        &[
            &["--user", "daemon-reload"],
            &["--user", "enable", "--now", "mycelium.service"],
        ]
    }
}

fn resolved_env(
    home: &Path,
    site: &str,
    peers: &str,
    authority_keys: &str,
    release_keys: &str,
    access_keys: &str,
) -> Result<String, ClientError> {
    let home = display(home)?;
    Ok(format!("MYCELIUM_HOME={home}\nMYCELIUM_SITE={site}\nMYCELIUM_PEER_LISTEN=0.0.0.0:7443\nMYCELIUM_PEERS={peers}\nMYCELIUM_PEER_CA={home}/pki/ca.pem\nMYCELIUM_PEER_CERT={home}/pki/node.pem\nMYCELIUM_PEER_KEY={home}/pki/node-key.pem\nMYCELIUM_AUTHORITY_KEYS={authority_keys}\nMYCELIUM_RELEASE_KEYS={release_keys}\nMYCELIUM_ACCESS_KEYS={access_keys}\nMYCELIUM_UPDATE_CHANNEL=canary\n"))
}

fn resolved_systemd(home: &Path) -> Result<String, ClientError> {
    let home = display(home)?;
    Ok(format!("[Unit]\nDescription=Mycelium peer\nAfter=network-online.target\nWants=network-online.target\n\n[Service]\nExecStart={home}/bin/mycelium _serve\nEnvironmentFile={home}/node.env\nRestart=always\nRestartSec=5\nNoNewPrivileges=true\nPrivateTmp=true\n\n[Install]\nWantedBy=default.target\n"))
}

fn resolved_launchd(
    home: &Path,
    site: &str,
    peers: &str,
    authority_keys: &str,
    release_keys: &str,
    access_keys: &str,
    iroh_server_name: Option<&str>,
) -> Result<String, ClientError> {
    let home = xml(&display(home)?);
    let plist = format!("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\"><dict>\n<key>Label</key><string>dev.fpl.mycelium</string>\n<key>ProgramArguments</key><array><string>{home}/bin/mycelium</string><string>_serve</string></array>\n<key>EnvironmentVariables</key><dict>\n<key>MYCELIUM_HOME</key><string>{home}</string>\n<key>MYCELIUM_SITE</key><string>{}</string>\n<key>MYCELIUM_PEER_LISTEN</key><string>0.0.0.0:7443</string>\n<key>MYCELIUM_PEERS</key><string>{}</string>\n<key>MYCELIUM_PEER_CA</key><string>{home}/pki/ca.pem</string>\n<key>MYCELIUM_PEER_CERT</key><string>{home}/pki/node.pem</string>\n<key>MYCELIUM_PEER_KEY</key><string>{home}/pki/node-key.pem</string>\n<key>MYCELIUM_AUTHORITY_KEYS</key><string>{}</string>\n<key>MYCELIUM_RELEASE_KEYS</key><string>{}</string>\n<key>MYCELIUM_ACCESS_KEYS</key><string>{}</string>\n<key>MYCELIUM_UPDATE_CHANNEL</key><string>canary</string>\n</dict><key>RunAtLoad</key><true/><key>KeepAlive</key><true/>\n<key>StandardOutPath</key><string>{home}/daemon.log</string>\n<key>StandardErrorPath</key><string>{home}/daemon.log</string>\n</dict></plist>\n", xml(site), xml(peers), xml(authority_keys), xml(release_keys), xml(access_keys));
    // launchd has no EnvironmentFile equivalent: every variable the daemon
    // needs must be embedded in the plist. Omitting MYCELIUM_IROH_SERVER_NAME
    // here left macOS daemons unable to start Iroh sync at all.
    Ok(match iroh_server_name {
        Some(name) => plist.replacen(
            "<key>MYCELIUM_UPDATE_CHANNEL</key>",
            &format!("<key>MYCELIUM_IROH_SERVER_NAME</key><string>{}</string>\n<key>MYCELIUM_UPDATE_CHANNEL</key>", xml(name)),
            1,
        ),
        None => plist,
    })
}

fn validate_peer(peer: &str) -> Result<(), ClientError> {
    if peer.is_empty()
        || peer.len() > 320
        || peer.bytes().any(|b| b.is_ascii_whitespace() || b == b',')
    {
        return Err(usage("peer address contains unsafe characters"));
    }
    Ok(())
}

fn copy_mode(from: &Path, to: &Path, mode: u32) -> Result<(), ClientError> {
    use std::os::unix::fs::PermissionsExt;
    let staged = to.with_extension(format!("install-{}", std::process::id()));
    if staged.exists() {
        std::fs::remove_file(&staged).map_err(ClientError::Io)?;
    }
    std::fs::copy(from, &staged).map_err(ClientError::Io)?;
    std::fs::set_permissions(&staged, std::fs::Permissions::from_mode(mode))
        .map_err(ClientError::Io)?;
    std::fs::rename(staged, to).map_err(ClientError::Io)
}

fn user_home() -> Result<PathBuf, ClientError> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or_else(|| usage("HOME is not set"))
}

fn xml(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

fn systemd_unit() -> &'static str {
    "[Unit]\nDescription=Mycelium peer\nAfter=network-online.target\nWants=network-online.target\n\n[Service]\nExecStart=%h/.mycelium/bin/mycelium _serve\nEnvironment=MYCELIUM_HOME=%h/.mycelium\nEnvironmentFile=%h/.mycelium/node.env\nRestart=always\nRestartSec=5\nNoNewPrivileges=true\nPrivateTmp=true\n\n[Install]\nWantedBy=default.target\n"
}

fn launchd_plist(
    site: &str,
    peers: &str,
    authority_keys: &str,
    release_keys: &str,
    access_keys: &str,
) -> String {
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\"><dict>\n<key>Label</key><string>dev.fpl.mycelium</string>\n<key>ProgramArguments</key><array><string>MYCELIUM_HOME/bin/mycelium</string><string>_serve</string></array>\n<key>EnvironmentVariables</key><dict>\n<key>MYCELIUM_HOME</key><string>MYCELIUM_HOME</string>\n<key>MYCELIUM_SITE</key><string>{site}</string>\n<key>MYCELIUM_PEER_LISTEN</key><string>0.0.0.0:7443</string>\n<key>MYCELIUM_PEERS</key><string>{peers}</string>\n<key>MYCELIUM_PEER_CA</key><string>MYCELIUM_HOME/pki/ca.pem</string>\n<key>MYCELIUM_PEER_CERT</key><string>MYCELIUM_HOME/pki/node.pem</string>\n<key>MYCELIUM_PEER_KEY</key><string>MYCELIUM_HOME/pki/node-key.pem</string>\n<key>MYCELIUM_AUTHORITY_KEYS</key><string>{authority_keys}</string>\n<key>MYCELIUM_RELEASE_KEYS</key><string>{release_keys}</string>\n<key>MYCELIUM_ACCESS_KEYS</key><string>{access_keys}</string>\n<key>MYCELIUM_UPDATE_CHANNEL</key><string>canary</string>\n</dict><key>RunAtLoad</key><true/><key>KeepAlive</key><true/>\n<key>StandardOutPath</key><string>MYCELIUM_HOME/daemon.log</string>\n<key>StandardErrorPath</key><string>MYCELIUM_HOME/daemon.log</string>\n</dict></plist>\n"
    )
}

fn openssl(args: &[&str]) -> Result<(), ClientError> {
    let output = Command::new("openssl")
        .args(args)
        .output()
        .map_err(ClientError::Io)?;
    if output.status.success() {
        Ok(())
    } else {
        Err(usage(&format!(
            "openssl failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )))
    }
}

fn openssl_string(args: &[&str]) -> Result<(), String> {
    openssl_output(args).map(|_| ())
}

fn openssl_output(args: &[&str]) -> Result<String, String> {
    let output = Command::new("openssl")
        .args(args)
        .output()
        .map_err(|error| format!("run openssl: {error}"))?;
    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    } else {
        Err(format!(
            "openssl failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ))
    }
}

fn validate_label(name: &str, value: &str) -> Result<(), ClientError> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._+-".contains(&byte))
    {
        return Err(usage(&format!("{name} contains unsafe characters")));
    }
    Ok(())
}

fn validate_address(value: &str) -> Result<(), ClientError> {
    if value.is_empty()
        || value.len() > 253
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b':'))
    {
        return Err(usage("address is not a safe IP address or DNS name"));
    }
    Ok(())
}

fn subject_alt_name(addresses: &std::collections::BTreeSet<&str>) -> String {
    format!(
        "subjectAltName={}",
        addresses
            .iter()
            .map(|address| {
                if address.parse::<std::net::IpAddr>().is_ok() {
                    format!("IP:{address}")
                } else {
                    format!("DNS:{address}")
                }
            })
            .collect::<Vec<_>>()
            .join(",")
    )
}

fn display(path: impl AsRef<Path>) -> Result<String, ClientError> {
    path.as_ref()
        .to_str()
        .map(str::to_owned)
        .ok_or_else(|| usage("enrollment paths must be UTF-8"))
}

fn owner_only(path: &Path) -> Result<(), ClientError> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).map_err(ClientError::Io)
}

fn executable(path: &Path) -> Result<(), ClientError> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).map_err(ClientError::Io)
}

fn usage(message: &str) -> ClientError {
    ClientError::Protocol(message.into())
}

pub fn default_ca() -> PathBuf {
    myceliumd::home_dir().join("authority")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn enrollment_names_and_addresses_are_shell_independent() {
        assert!(validate_label("name", "home-pi").is_ok());
        assert!(validate_label("name", "x;reboot").is_err());
        assert!(validate_address("home-pi.tail.example").is_ok());
        assert!(validate_address("x $(reboot)").is_err());
    }

    #[test]
    fn enrollment_certificate_covers_public_private_and_dns_addresses() {
        let addresses = std::collections::BTreeSet::from([
            "10.118.0.11",
            "134.209.208.195",
            "fpl-beachhead-1.internal",
        ]);
        assert_eq!(
            subject_alt_name(&addresses),
            "subjectAltName=IP:10.118.0.11,IP:134.209.208.195,DNS:fpl-beachhead-1.internal"
        );
    }

    #[test]
    fn install_copy_atomically_replaces_existing_file() {
        let root =
            std::env::temp_dir().join(format!("mycelium-enroll-copy-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let source = root.join("source");
        let destination = root.join("destination");
        std::fs::write(&source, b"new").unwrap();
        std::fs::write(&destination, b"old").unwrap();
        copy_mode(&source, &destination, 0o600).unwrap();
        assert_eq!(std::fs::read(&destination).unwrap(), b"new");
        assert_eq!(
            std::fs::metadata(&destination)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn system_service_uses_the_system_manager() {
        assert_eq!(
            systemd_start_commands(true),
            &[&["daemon-reload"][..], &["enable", "--now", "mycelium.service"]]
        );
        assert_eq!(systemd_start_commands(false)[0], &["--user", "daemon-reload"]);
    }
}
