//! Explicit rendezvous import/export for already-enrolled peers.
#[cfg(feature = "iroh-sync")]
fn save_config(home: &std::path::Path, config: &myceliumd::peer::SyncConfig) -> Result<(), String> {
    config.validate()?;
    let temporary = home.join("iroh-sync.json.tmp");
    std::fs::write(&temporary, serde_json::to_vec_pretty(config).map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())?;
    std::fs::rename(temporary, home.join("iroh-sync.json")).map_err(|e| e.to_string())
}

#[cfg(feature = "iroh-sync")]
pub fn run(args: &[String]) -> Result<Vec<String>, String> {
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
    match args.first().map(String::as_str) {
        Some("relays") if args.len() == 3 && args[2] == "--write"
            && matches!(args[1].as_str(), "enable" | "disable") => {
            let path = home.join("iroh-sync.json");
            let mut config: SyncConfig = serde_json::from_slice(&read(&path)?)
                .map_err(|e| e.to_string())?;
            config.public_relays = args[1] == "enable";
            save_config(&home, &config)?;
            Ok(vec![format!("public relays {}; restart the managed daemon (peer authentication is unchanged)", args[1])])
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
        Some("enable") if args.len() == 2 && args[1] == "--write" => {
            std::fs::create_dir_all(&home).map_err(|e| e.to_string())?;
            let path = home.join("iroh-sync.json");
            if path.exists() {
                // Enabling twice is a no-op, not an error: report the
                // existing configuration instead of failing with EEXIST.
                let config: SyncConfig =
                    serde_json::from_slice(&read(&path)?).map_err(|e| e.to_string())?;
                config.validate()?;
                return Ok(vec![format!(
                    "Iroh already enabled (public relays {}, {} sync seed(s)); no changes written. If the daemon's rendezvous is stale, restart myceliumd and check MYCELIUM_IROH_SERVER_NAME in its environment",
                    if config.public_relays { "on" } else { "off" },
                    config.seeds.len()
                )]);
            }
            use std::io::Write;
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)
                .map_err(|e| e.to_string())?;
            file.write_all(b"{\"public_relays\":false,\"seeds\":[]}\n")
                .map_err(|e| e.to_string())?;
            file.sync_all().map_err(|e| e.to_string())?;
            Ok(vec!["Iroh enabled; set MYCELIUM_IROH_SERVER_NAME to your certificate SAN and restart myceliumd".into()])
        }
        Some("join") if args.len() == 3 && args[2] == "--write" => {
            let seed: SyncRendezvous =
                serde_json::from_slice(&read(std::path::Path::new(&args[1]))?)
                    .map_err(|e| e.to_string())?;
            seed.validate(Some(at))?;
            let path = home.join("iroh-sync.json");
            let mut config: SyncConfig =
                serde_json::from_slice(&read(&path)?).map_err(|e| e.to_string())?;
            config
                .seeds
                .retain(|s| s.endpoint.endpoint_id != seed.endpoint.endpoint_id);
            config.seeds.push(seed);
            save_config(&home, &config)?;
            Ok(vec!["sync seed saved; restart myceliumd to connect (enrollment and trust are unchanged)".into()])
        }
        _ => Err(
            "usage: mycelium sync enable --write | export [--qr] | join <rendezvous.json> --write | relays enable|disable --write"
                .into(),
        ),
    }
}

#[cfg(not(feature = "iroh-sync"))]
pub fn run(_: &[String]) -> Result<Vec<String>, String> {
    Err("this binary lacks Iroh sync; install with --features iroh-sync".into())
}

#[cfg(all(test, feature = "iroh-sync"))]
mod tests {
    use super::*;

    #[test]
    fn relay_policy_roundtrip_preserves_bootstrap_seeds() {
        let home = std::env::temp_dir().join(format!("mycelium-sync-policy-{}-{}", std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
        std::fs::create_dir(&home).unwrap();
        let mut config: myceliumd::peer::SyncConfig = serde_json::from_value(serde_json::json!({
            "public_relays": false,
            "seeds": [{"server_name": "peer.test", "endpoint": {
                "id": "mycelium-sync", "endpoint_id": "a".repeat(64),
                "alpns": ["mycelium/sync/1"], "direct_addresses": ["127.0.0.1:7444"],
                "relay_urls": [], "observed_at": 100, "expires_at": 130
            }}]
        })).unwrap();
        let original_seeds = serde_json::to_value(&config.seeds).unwrap();
        for enabled in [true, false] {
            config.public_relays = enabled;
            save_config(&home, &config).unwrap();
            let saved: myceliumd::peer::SyncConfig = serde_json::from_slice(
                &std::fs::read(home.join("iroh-sync.json")).unwrap()).unwrap();
            assert_eq!(saved.public_relays, enabled);
            assert_eq!(serde_json::to_value(saved.seeds).unwrap(), original_seeds);
        }
        config.seeds.push(config.seeds[0].clone());
        assert!(save_config(&home, &config).is_err());
        let retained: myceliumd::peer::SyncConfig = serde_json::from_slice(
            &std::fs::read(home.join("iroh-sync.json")).unwrap()).unwrap();
        assert_eq!(retained.seeds.len(), 1);
        std::fs::remove_file(home.join("iroh-sync.json")).unwrap();
        std::fs::remove_dir(home).unwrap();
    }
}
