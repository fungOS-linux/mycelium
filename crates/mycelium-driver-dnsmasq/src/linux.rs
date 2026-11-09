//! User-owned Linux companion activation. Namespace routing is deliberately
//! separate: installing a listener never changes the host's default resolver.
use super::linux_namespace::command;
use super::*;
const UNIT: &str = "mycelium-dns.service";

fn argument(path: &Path) -> Result<String, String> {
    let text = path.to_str().ok_or("non-UTF-8 service path")?;
    if !path.is_absolute() || text.chars().any(char::is_control) {
        return Err("service paths must be absolute and contain no control characters".into());
    }
    Ok(format!(
        "\"{}\"",
        text.replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('%', "%%")
    ))
}
fn unit(executable: &Path, config: &Path) -> Result<String, String> {
    // Only the legacy standalone adapter binary lacks the `dns resolver`
    // subcommand; every other name is the CLI, including renamed builds.
    let prefix = if executable.file_name().and_then(|s| s.to_str()) == Some("mycelium-dns-resolver")
    {
        ""
    } else {
        " dns resolver"
    };
    Ok(format!("{MARKER}[Unit]\nDescription=Mycelium local DNS companion\n[Service]\nExecStart={}{} run --config {} --write\nRestart=on-failure\nRestartSec=15\n[Install]\nWantedBy=default.target\n", argument(executable)?, prefix, argument(config)?))
}
fn control(args: &[&str]) -> Result<(), String> {
    let output = Command::new("systemctl")
        .arg("--user")
        .args(args)
        .output()
        .map_err(|e| e.to_string())?;
    if !output.status.success() {
        return Err(format!(
            "systemctl {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    Ok(())
}
pub(super) async fn apply(settings: &Settings) -> Result<Value, String> {
    if settings.resolver.mode == ResolverMode::LanServing {
        return Err("LAN activation requires verified firewall policy; plan only".into());
    }
    let path = home()?.join(".config/systemd/user").join(UNIT);
    if fs::symlink_metadata(&path).is_ok_and(|m| m.file_type().is_symlink()) {
        return Err("refusing symlink service unit".into());
    }
    let old = match fs::read(&path) {
        Ok(bytes) if bytes.starts_with(MARKER.as_bytes()) => Some(bytes),
        Ok(_) => return Err("service unit owned by another administrator; unchanged".into()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => return Err(e.to_string()),
    };
    if settings.resolver.mode == ResolverMode::Off {
        if old.is_some() {
            control(&["disable", "--now", UNIT])?;
            fs::remove_file(&path).map_err(|e| e.to_string())?;
            control(&["daemon-reload"])?;
        }
        return Ok(json!({"mode":"off","namespace_removal_required":true}));
    }
    let records = observe(settings).await?;
    let first = records
        .first()
        .ok_or("no fresh reachable records; refusing empty activation")?;
    let directory = state_dir()?;
    let candidate = directory.join("candidate.conf");
    atomic_write(&candidate, settings.render(records.clone())?.as_bytes())?;
    syntax(settings, &candidate)?;
    let active = Command::new("systemctl")
        .args(["--user", "is-active", "--quiet", UNIT])
        .status()
        .map_err(|e| e.to_string())?
        .success();
    if active && old.is_none() {
        return Err("active service has no owned unit; unchanged".into());
    }
    if !active {
        for listener in &settings.resolver.listen {
            std::net::UdpSocket::bind(listener)
                .map_err(|e| format!("listener unavailable: {e}"))?;
            std::net::TcpListener::bind(listener)
                .map_err(|e| format!("TCP listener unavailable: {e}"))?;
        }
    }
    let stored = directory.join("active-settings.json");
    let old_settings = fs::read(&stored).ok();
    if active {
        control(&["stop", UNIT])?;
    }
    let result = async {
        atomic_write(
            &stored,
            &serde_json::to_vec(settings).map_err(|e| e.to_string())?,
        )?;
        atomic_write(
            &path,
            unit(
                &std::env::current_exe().map_err(|e| e.to_string())?,
                &stored,
            )?
            .as_bytes(),
        )?;
        control(&["daemon-reload"])?;
        control(&["enable", "--now", UNIT])?;
        // The first observation can consume two ten-second CLI deadlines
        // before dnsmasq even starts; five seconds guaranteed a false failure.
        for _ in 0..60 {
            tokio::time::sleep(Duration::from_millis(500)).await;
            if verify(settings, first).is_ok() {
                return Ok(());
            }
        }
        Err("DNS postcondition failed".to_string())
    }
    .await;
    if let Err(error) = result {
        let mut rollback = Vec::new();
        if let Err(e) = control(&["disable", "--now", UNIT]) {
            rollback.push(e);
        }
        if let Some(bytes) = old {
            atomic_write(&path, &bytes)?;
            if let Some(bytes) = old_settings {
                atomic_write(&stored, &bytes)?;
            }
        } else if path.exists() {
            fs::remove_file(&path).map_err(|e| e.to_string())?;
        }
        control(&["daemon-reload"])?;
        if active {
            control(&["enable", "--now", UNIT])?;
        }
        return Err(format!(
            "{error}; restored previous unit; rollback errors: {}",
            rollback.join("; ")
        ));
    }
    Ok(
        json!({"mode":settings.resolver.mode,"records":records.len(),"verified_record":first,"namespace_install_required":true,"default_dns_changed":false,"persistence":"systemd-user; login or existing linger required"}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn unit_quotes_paths_and_systemd_specifiers() {
        let rendered = unit(
            Path::new("/home/a %u/bin/mycelium"),
            Path::new("/home/a/dns.json"),
        )
        .unwrap();
        assert!(rendered.contains("\"/home/a %%u/bin/mycelium\" dns resolver run"));
        assert!(rendered.starts_with(MARKER));
        assert!(!rendered.contains("User="));
        // A renamed CLI build still needs the `dns resolver` subcommand.
        let renamed = unit(
            Path::new("/home/a/bin/mycelium-master"),
            Path::new("/home/a/dns.json"),
        )
        .unwrap();
        assert!(renamed.contains("/home/a/bin/mycelium-master\" dns resolver run"));
        let legacy = unit(
            Path::new("/home/a/bin/mycelium-dns-resolver"),
            Path::new("/home/a/dns.json"),
        )
        .unwrap();
        assert!(legacy.contains("/home/a/bin/mycelium-dns-resolver\" run"));
    }
    #[test]
    fn stub_takes_port_53_and_moves_the_forwarder() {
        let mut settings = crate::tests::settings();
        settings.resolver.doh = Some(mycelium_dns_policy::resolver::DohUpstream {
            endpoint: "https://dns.example/dns-query".into(),
            listen: "127.0.0.1:5336".parse().unwrap(),
            timeout_seconds: 5,
            max_inflight: 8,
        });
        let root = stub_settings(&settings).unwrap();
        assert_eq!(root.resolver.listen[0].to_string(), "127.0.0.1:53");
        assert_eq!(
            root.resolver.doh.as_ref().unwrap().listen.to_string(),
            "127.0.0.1:5357"
        );
    }

    #[test]
    fn stub_unit_runs_the_resolver_with_both_homes() {
        let unit = stub_unit(
            Path::new("/home/a/.mycelium/bin/mycelium"),
            Path::new("/var/lib/mycelium-dns/.mycelium/dns/settings.json"),
            Path::new("/home/a/.mycelium"),
        )
        .unwrap();
        assert!(unit.contains("dns resolver run"));
        assert!(unit.contains("Environment=HOME=\"/var/lib/mycelium-dns\""));
        assert!(unit.contains("Environment=MYCELIUM_HOME=\"/home/a/.mycelium\""));
        assert!(unit.contains("WantedBy=multi-user.target"));
        assert!(unit.starts_with(MARKER));
    }

    #[test]
    fn reject_nonabsolute_and_injected_paths() {
        assert!(unit(Path::new("mycelium"), Path::new("/config")).is_err());
        assert!(unit(Path::new("/bin/mycelium\nRestart=no"), Path::new("/config")).is_err());
    }
}

// ---------------------------------------------------------------------------
// Stub backend
//
// Hosts without systemd-resolved 258+ (Debian 12 ships systemd 252 and no
// resolved at all) have no per-suffix routing. The only place a suffix can be
// routed there is the system resolver itself, so this backend runs the same
// resolver as a root service on `127.0.0.1:53` and points `resolv.conf` at it.
// Non-`.myc` names then take the configured DoH hop, which is the point.
const STUB_UNIT: &str = "mycelium-dnsd.service";
const STUB_UNIT_PATH: &str = "/etc/systemd/system/mycelium-dnsd.service";
const STUB_HOME: &str = "/var/lib/mycelium-dns";
const RESOLV: &str = "/etc/resolv.conf";
const RESOLV_BACKUP: &str = "/etc/resolv.conf.mycelium-backup";

/// System-scoped control. `control` above drives the user manager, and root
/// has no user bus, so the stub must not reuse it.
fn system_control(args: &[&str]) -> Result<(), String> {
    let output = Command::new("systemctl")
        .arg("--system")
        .args(args)
        .output()
        .map_err(|e| e.to_string())?;
    if !output.status.success() {
        return Err(format!(
            "systemctl --system {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(())
}

fn stub_settings(settings: &Settings) -> Result<Settings, String> {
    let mut root = settings.clone();
    root.resolver.listen = vec!["127.0.0.1:53".parse().expect("static listener")];
    if let Some(doh) = root.resolver.doh.as_mut() {
        // The daemon and any user agent must not fight over one port.
        doh.listen = "127.0.0.1:5357".parse().expect("static listener");
    }
    root.validate()?;
    Ok(root)
}

fn stub_unit(binary: &Path, config: &Path, mesh: &Path) -> Result<String, String> {
    Ok(format!(
        "{MARKER}[Unit]\nDescription=Mycelium system DNS stub\n[Service]\nExecStart={} dns resolver run --config {} --write\nEnvironment=HOME={}\nEnvironment=MYCELIUM_HOME={}\nRestart=on-failure\nRestartSec=5\n[Install]\nWantedBy=multi-user.target\n",
        argument(binary)?,
        argument(config)?,
        argument(Path::new(STUB_HOME))?,
        argument(mesh)?,
    ))
}

fn mesh_home(settings: &Settings) -> Result<std::path::PathBuf, String> {
    settings
        .mycelium
        .ancestors()
        .find(|path| path.file_name().and_then(|name| name.to_str()) == Some(".mycelium"))
        .map(Path::to_path_buf)
        .ok_or_else(|| "resolver binary must live under a Mycelium home".into())
}

pub(super) async fn remove_stub(settings: &Settings) -> Result<Value, String> {
    install_stub(settings, true).await
}

pub(super) async fn install_stub(settings: &Settings, remove: bool) -> Result<Value, String> {
    if command("/usr/bin/id", &["-u"])?.trim() != "0" {
        return Err("system DNS stub requires root".into());
    }
    let unit = Path::new(STUB_UNIT_PATH);
    if remove {
        let _ = system_control(&["disable", "--now", STUB_UNIT]);
        if unit.exists() {
            fs::remove_file(unit).map_err(|e| e.to_string())?;
        }
        system_control(&["daemon-reload"])?;
        let backup = Path::new(RESOLV_BACKUP);
        if backup.exists() {
            fs::rename(backup, RESOLV).map_err(|e| e.to_string())?;
        }
        return Ok(json!({"backend": "stub", "installed": false, "resolv_conf_restored": true}));
    }
    let home = Path::new(STUB_HOME);
    let state = home.join(".mycelium/dns");
    fs::create_dir_all(&state).map_err(|e| e.to_string())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(home, fs::Permissions::from_mode(0o700)).map_err(|e| e.to_string())?;
        fs::set_permissions(&state, fs::Permissions::from_mode(0o700))
            .map_err(|e| e.to_string())?;
    }
    let config = state.join("settings.json");
    atomic_write(
        &config,
        &serde_json::to_vec_pretty(&stub_settings(settings)?).map_err(|e| e.to_string())?,
    )?;
    atomic_write(
        unit,
        stub_unit(&settings.mycelium, &config, &mesh_home(settings)?)?.as_bytes(),
    )?;
    system_control(&["daemon-reload"])?;
    system_control(&["enable", "--now", STUB_UNIT])?;
    // Keep the previous resolver reachable if this host ever has to roll back.
    let backup = Path::new(RESOLV_BACKUP);
    if !backup.exists() {
        fs::copy(RESOLV, backup).map_err(|e| e.to_string())?;
    }
    atomic_write(
        Path::new(RESOLV),
        b"# Managed by Mycelium DNS resolver\nnameserver 127.0.0.1\n",
    )?;
    let records = observe(settings).await?;
    let first = records
        .first()
        .ok_or("no fresh record for OS qualification")?;
    let expected: std::collections::BTreeSet<String> = records
        .iter()
        .filter(|record| record.name == first.name)
        .map(|record| record.address.to_string())
        .collect();
    let mut answered = false;
    for _ in 0..40 {
        let answer = Command::new("/usr/bin/timeout")
            .args(["15", "/usr/bin/getent", "ahosts", &first.name])
            .env("LC_ALL", "C")
            .output()
            .ok()
            .filter(|output| output.status.success())
            .map(|output| String::from_utf8_lossy(&output.stdout).into_owned())
            .unwrap_or_default();
        if answer.lines().any(|line| {
            line.split_whitespace()
                .next()
                .is_some_and(|address| expected.contains(address))
        }) {
            answered = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    if !answered {
        return Err("system stub did not answer the observed record".into());
    }
    Ok(json!({
        "backend": "stub",
        "installed": true,
        "listen": "127.0.0.1:53",
        "resolv_conf": RESOLV,
        "resolv_conf_backup": RESOLV_BACKUP,
        "verified_record": first,
    }))
}
