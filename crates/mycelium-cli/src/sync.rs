//! Explicit rendezvous import/export for already-enrolled peers.
//!
//! Every write is followed by a live reload of the running daemon: the
//! optional Iroh transport is rebuilt in place, so enabling, joining, or
//! changing the relay policy never needs a manual stop/start cycle. A
//! daemon that is not running picks the change up when it starts.

#[cfg(feature = "iroh-sync")]
use myceliumd::client::{Client, ClientError};
#[cfg(feature = "iroh-sync")]
use myceliumd::protocol::Request;

#[cfg(feature = "iroh-sync")]
fn write_private(path: &std::path::Path, bytes: &[u8]) -> Result<(), String> {
    use std::io::Write;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .map_err(|error| error.to_string())?;
    file.write_all(bytes).map_err(|error| error.to_string())?;
    file.sync_all().map_err(|error| error.to_string())?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .map_err(|error| error.to_string())
}

#[cfg(feature = "iroh-sync")]
fn save_config(home: &std::path::Path, config: &myceliumd::peer::SyncConfig) -> Result<(), String> {
    config.validate()?;
    let temporary = home.join("iroh-sync.json.tmp");
    let bytes = serde_json::to_vec_pretty(config).map_err(|e| e.to_string())?;
    write_private(&temporary, &bytes)?;
    std::fs::rename(temporary, home.join("iroh-sync.json")).map_err(|e| e.to_string())
}

/// Ask the running daemon to re-read `iroh-sync.json`. The mesh, the peer
/// identity, and the signed observation log are untouched.
#[cfg(feature = "iroh-sync")]
async fn reload_daemon() -> Result<String, String> {
    match Client::try_connect().await {
        Ok(mut client) => match client.call(&Request::SyncReload).await {
            Ok(value) => Ok(render_reload(&value)),
            Err(ClientError::Rpc { message, .. }) => {
                Err(format!("the running daemon rejected the reload: {message}"))
            }
            Err(error) => Err(error.to_string()),
        },
        Err(ClientError::Connect(_)) => {
            Ok("daemon is not running; the change applies when it starts".into())
        }
        Err(error) => Err(error.to_string()),
    }
}

/// Same as [`reload_daemon`], but a missing daemon is an error: the operator
/// asked for an explicit reload.
#[cfg(feature = "iroh-sync")]
async fn reload_daemon_required() -> Result<String, String> {
    match Client::try_connect().await {
        Ok(mut client) => match client.call(&Request::SyncReload).await {
            Ok(value) => Ok(render_reload(&value)),
            Err(ClientError::Rpc { message, .. }) => {
                Err(format!("the running daemon rejected the reload: {message}"))
            }
            Err(error) => Err(error.to_string()),
        },
        Err(ClientError::Connect(_)) => {
            Err("myceliumd is not running; start it and retry the reload".into())
        }
        Err(error) => Err(error.to_string()),
    }
}

#[cfg(feature = "iroh-sync")]
fn render_reload(value: &serde_json::Value) -> String {
    format!("daemon reloaded Iroh sync: {}", render_state(value))
}

#[cfg(feature = "iroh-sync")]
fn render_state(value: &serde_json::Value) -> String {
    let running = value
        .get("running")
        .and_then(|value| value.as_bool())
        .unwrap_or(false);
    let seeds = value
        .get("seeds")
        .and_then(|value| value.as_u64())
        .unwrap_or(0);
    let relays = value
        .get("public_relays")
        .and_then(|value| value.as_bool())
        .unwrap_or(false);
    let name = value
        .get("server_name")
        .and_then(|value| value.as_str())
        .unwrap_or("none");
    format!(
        "{}, {seeds} seed(s), public relays {}, server name {name}",
        if running { "running" } else { "idle" },
        if relays { "enabled" } else { "disabled" },
    )
}

#[cfg(feature = "iroh-sync")]
pub async fn run(args: &[String]) -> Result<Vec<String>, String> {
    use myceliumd::peer::{SyncConfig, SyncRendezvous};
    use std::io::Read;
    let home = myceliumd::home_dir();
    let read = |path: &std::path::Path| -> Result<Vec<u8>, String> {
        let mut bytes = Vec::new();
        std::fs::File::open(path)
            .map_err(|e| e.to_string())?
            .take(65537)
            .read_to_end(&mut bytes)
            .map_err(|e| e.to_string())?;
        if bytes.len() > 65536 {
            return Err("sync document exceeds 64 KiB".into());
        }
        Ok(bytes)
    };
    let at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| e.to_string())?
        .as_secs();
    let load_config = |path: &std::path::Path| -> Result<SyncConfig, String> {
        if path.exists() {
            let config: SyncConfig = serde_json::from_slice(&read(path)?)
                .map_err(|e| format!("existing iroh-sync.json is invalid: {e}"))?;
            config
                .validate()
                .map_err(|e| format!("existing iroh-sync.json is invalid: {e}"))?;
            Ok(config)
        } else {
            Ok(SyncConfig::default())
        }
    };
    match args.first().map(String::as_str) {
        Some("relays") if args.len() == 3 && args[2] == "--write"
            && matches!(args[1].as_str(), "enable" | "disable") => {
            let path = home.join("iroh-sync.json");
            let mut config = load_config(&path)?;
            config.public_relays = args[1] == "enable";
            save_config(&home, &config)?;
            let mut lines = vec![format!(
                "public relays {}; peer authentication is unchanged",
                args[1]
            )];
            lines.push(reload_daemon().await?);
            Ok(lines)
        }
        Some("export") if args.len() == 1 || args == ["export", "--qr"] => {
            let rendezvous: SyncRendezvous =
                serde_json::from_slice(&read(&home.join("iroh-rendezvous.json"))?)
                    .map_err(|e| e.to_string())?;
            rendezvous.validate(Some(at))?;
            let json = serde_json::to_string(&rendezvous).map_err(|e| e.to_string())?;
            if args.len() == 2 {
                let qr = qrcode::QrCode::new(json.as_bytes()).map_err(|e| e.to_string())?;
                Ok(vec![
                    qr.render::<qrcode::render::unicode::Dense1x2>().build(),
                    json,
                ])
            } else {
                Ok(vec![json])
            }
        }
        Some("enable") => {
            let mut write = false;
            let mut server_name: Option<String> = None;
            let mut index = 1;
            while index < args.len() {
                match args[index].as_str() {
                    "--write" => {
                        write = true;
                        index += 1;
                    }
                    "--server-name" => {
                        let value = args
                            .get(index + 1)
                            .ok_or("--server-name needs a certificate SAN")?;
                        server_name = Some(value.clone());
                        index += 2;
                    }
                    other => return Err(format!("unknown sync option `{other}`")),
                }
            }
            if !write {
                return Err("enabling Iroh sync requires --write".into());
            }
            std::fs::create_dir_all(&home).map_err(|e| e.to_string())?;
            let path = home.join("iroh-sync.json");
            // An existing peer configuration is preserved: enabling sync is
            // not a reason to drop bootstrap seeds.
            let mut config = load_config(&path)?;
            if let Some(name) = server_name {
                config.server_name = Some(name);
            } else if config.server_name.is_none() {
                config.server_name = std::env::var("MYCELIUM_IROH_SERVER_NAME")
                    .ok()
                    .filter(|value| !value.trim().is_empty());
            }
            save_config(&home, &config)?;
            let mut lines = vec![format!(
                "Iroh sync enabled ({} seed(s), public relays {})",
                config.seeds.len(),
                if config.public_relays { "enabled" } else { "disabled" }
            )];
            if config.server_name.is_none() {
                lines.push(
                    "no server name configured: pass --server-name or set MYCELIUM_IROH_SERVER_NAME to a certificate SAN so peers can verify this peer"
                        .into(),
                );
            }
            lines.push(reload_daemon().await?);
            Ok(lines)
        }
        Some("join") if args.len() == 3 && args[2] == "--write" => {
            let seed: SyncRendezvous =
                serde_json::from_slice(&read(std::path::Path::new(&args[1]))?)
                    .map_err(|e| e.to_string())?;
            seed.validate(Some(at))?;
            let path = home.join("iroh-sync.json");
            let mut config = load_config(&path)?;
            config
                .seeds
                .retain(|s| s.endpoint.endpoint_id != seed.endpoint.endpoint_id);
            let relays = !seed.endpoint.relay_urls.is_empty();
            config.seeds.push(seed);
            save_config(&home, &config)?;
            let mut lines = vec!["sync seed saved; enrollment and trust are unchanged".into()];
            if relays && !config.public_relays {
                lines.push(
                    "this seed carries relay hints: run `mycelium sync relays enable --write` to use them"
                        .into(),
                );
            }
            lines.push(reload_daemon().await?);
            Ok(lines)
        }
        Some("reload") if args.len() == 1 => Ok(vec![reload_daemon_required().await?]),
        Some("status") if args.len() == 1 => {
            match Client::try_connect().await {
                Ok(mut client) => {
                    let value = client
                        .call(&Request::SyncStatus)
                        .await
                        .map_err(|error| error.to_string())?;
                    let mut lines = vec![format!("Iroh sync: {}", render_state(&value))];
                    if let Some(error) = value.get("error").and_then(|value| value.as_str()) {
                        lines.push(format!("last error: {error}"));
                    }
                    Ok(lines)
                }
                Err(ClientError::Connect(_)) => {
                    let path = home.join("iroh-sync.json");
                    if !path.exists() {
                        return Ok(vec![
                            "Iroh sync is not configured (no iroh-sync.json); daemon is not running"
                                .into(),
                        ]);
                    }
                    let config = load_config(&path)?;
                    Ok(vec![format!(
                        "Iroh sync configured on disk ({} seed(s), public relays {}); daemon is not running",
                        config.seeds.len(),
                        if config.public_relays { "enabled" } else { "disabled" }
                    )])
                }
                Err(error) => Err(error.to_string()),
            }
        }
        _ => Err(
            "usage: mycelium sync enable --write [--server-name SAN] | export [--qr] | join <rendezvous.json> --write | relays enable|disable --write | reload | status"
                .into(),
        ),
    }
}

#[cfg(not(feature = "iroh-sync"))]
pub async fn run(_: &[String]) -> Result<Vec<String>, String> {
    Err("this binary lacks Iroh sync; install with --features iroh-sync".into())
}

#[cfg(all(test, feature = "iroh-sync"))]
mod tests {
    use super::*;

    #[test]
    fn relay_policy_roundtrip_preserves_bootstrap_seeds() {
        let home = std::env::temp_dir().join(format!(
            "mycelium-sync-policy-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&home).unwrap();
        let mut config: myceliumd::peer::SyncConfig = serde_json::from_value(serde_json::json!({
            "public_relays": false,
            "seeds": [{"server_name": "peer.test", "endpoint": {
                "id": "mycelium-sync", "endpoint_id": "a".repeat(64),
                "alpns": ["mycelium/sync/1"], "direct_addresses": ["127.0.0.1:7444"],
                "relay_urls": [], "observed_at": 100, "expires_at": 130
            }}]
        }))
        .unwrap();
        let original_seeds = serde_json::to_value(&config.seeds).unwrap();
        for enabled in [true, false] {
            config.public_relays = enabled;
            save_config(&home, &config).unwrap();
            let saved: myceliumd::peer::SyncConfig =
                serde_json::from_slice(&std::fs::read(home.join("iroh-sync.json")).unwrap())
                    .unwrap();
            assert_eq!(saved.public_relays, enabled);
            assert_eq!(serde_json::to_value(saved.seeds).unwrap(), original_seeds);
        }
        config.seeds.push(config.seeds[0].clone());
        assert!(save_config(&home, &config).is_err());
        let retained: myceliumd::peer::SyncConfig =
            serde_json::from_slice(&std::fs::read(home.join("iroh-sync.json")).unwrap()).unwrap();
        assert_eq!(retained.seeds.len(), 1);
        // The peer transport configuration is private to the daemon home.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(home.join("iroh-sync.json"))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        std::fs::remove_file(home.join("iroh-sync.json")).unwrap();
        std::fs::remove_dir(home).unwrap();
    }

    #[test]
    fn default_config_prefers_direct_paths() {
        let config = myceliumd::peer::SyncConfig::default();
        assert!(config.direct_first);
        assert!(!config.public_relays);
        assert!(config.seeds.is_empty());
        assert!(config.server_name.is_none());
    }
}
