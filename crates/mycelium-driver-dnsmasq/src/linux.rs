//! User-owned Linux companion activation. Namespace routing is deliberately
//! separate: installing a listener never changes the host's default resolver.
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
    let prefix = if executable.file_name().and_then(|s| s.to_str()) == Some("mycelium") {
        " dns resolver"
    } else {
        ""
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
        for _ in 0..10 {
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
    }
    #[test]
    fn reject_nonabsolute_and_injected_paths() {
        assert!(unit(Path::new("mycelium"), Path::new("/config")).is_err());
        assert!(unit(Path::new("/bin/mycelium\nRestart=no"), Path::new("/config")).is_err());
    }
}
