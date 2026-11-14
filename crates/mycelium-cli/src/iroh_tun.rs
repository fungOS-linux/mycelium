//! `mycelium iroh-tun`: what the tunnel is doing, and the one file that enables
//! it.
//!
//! Status comes from the daemon, never from this process. The daemon owns the
//! child, the key and the published observation; a second opinion computed here
//! would be a second source of truth, and the whole point of moving registration
//! into the daemon was to have exactly one.

use myceliumd::client::ClientError;
use myceliumd::iroh_tun::{self, Config, Paths};
use myceliumd::protocol::Request;
use serde_json::Value;

pub async fn run(args: &[String]) -> Result<Vec<String>, String> {
    match args.first().map(String::as_str).unwrap_or("status") {
        "status" => status(&args[1..]).await,
        "config" => config(&args[1..]).await,
        "address" => address(&args[1..]).await,
        other => Err(format!(
            "unknown iroh-tun action `{other}`; try `status`, `config` or `address`"
        )),
    }
}

/// The overlay address this node owns, derived from its identity.
///
/// The installer needs it before any interface exists (it is what the tunnel
/// assigns), so it must come from identity alone and not from the kernel.
async fn address(args: &[String]) -> Result<Vec<String>, String> {
    let json = args.iter().any(|argument| argument == "--json");
    if let Some(other) = args.iter().find(|argument| argument.as_str() != "--json") {
        return Err(format!("unknown iroh-tun address argument `{other}`"));
    }
    let mut client = crate::connect().await.map_err(access)?;
    let value = client.call(&Request::IrohTunStatus).await.map_err(access)?;
    let node = value["node"].as_str().unwrap_or_default();
    let address = mycelium_dns_policy::addresses::overlay_address(node)
        .ok_or("the daemon did not report a node identity")?;
    if json {
        return Ok(vec![
            serde_json::json!({"address": format!("{address}/128"), "node": node}).to_string(),
        ]);
    }
    Ok(vec![format!("{address}/128")])
}

async fn status(args: &[String]) -> Result<Vec<String>, String> {
    let json = args.iter().any(|argument| argument == "--json");
    if let Some(other) = args.iter().find(|argument| argument.as_str() != "--json") {
        return Err(format!("unknown iroh-tun status argument `{other}`"));
    }
    let mut client = crate::connect().await.map_err(access)?;
    let value = client.call(&Request::IrohTunStatus).await.map_err(access)?;
    if json {
        return Ok(vec![value.to_string()]);
    }
    Ok(render(&value))
}

fn render(value: &Value) -> Vec<String> {
    let flag = |key: &str| value[key].as_bool().unwrap_or(false);
    let text = |key: &str| value[key].as_str().unwrap_or("-").to_owned();
    let mut lines = Vec::new();
    if let Some(error) = value["config_error"].as_str() {
        lines.push(format!("iroh-tun: config error: {error}"));
    }
    if !flag("enabled") {
        lines.push(format!("iroh-tun: not configured ({})", text("config")));
        lines.push(
            "  enable it with: mycelium iroh-tun config --tun utun220 --overlay <cidr> --write"
                .into(),
        );
        return lines;
    }
    lines.push(format!(
        "iroh-tun: {} on {} mtu {}",
        if flag("running") {
            "running"
        } else {
            "not running"
        },
        text("tun"),
        value["mtu"].as_u64().unwrap_or(0)
    ));
    lines.push(format!(
        "  identity  {} ({})",
        value["endpoint_id"]
            .as_str()
            .map(short_id)
            .unwrap_or_else(|| "no key yet".into()),
        if flag("publishing") {
            "publishing iroh-tun"
        } else {
            "not publishing"
        }
    ));
    let overlay = value["overlay"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect::<Vec<_>>()
        .join(", ");
    lines.push(format!(
        "  overlay   {}",
        if overlay.is_empty() {
            "none: this node reaches the overlay but nothing can reach it".into()
        } else {
            overlay
        }
    ));
    lines.push(format!(
        "  routes    {} learned, {} refresh failure(s), status {}s old",
        value["routes"].as_array().map(Vec::len).unwrap_or(0),
        value["refresh_failures"].as_u64().unwrap_or(0),
        value["status_age_secs"]
            .as_u64()
            .map(|age| age.to_string())
            .unwrap_or_else(|| "never".into())
    ));
    if flag("external") {
        lines.push("  owner     external privileged service (root)".into());
    }
    if let Some(pid) = value["pid"].as_u64() {
        lines.push(format!(
            "  process   pid {pid}, {} restart(s)",
            value["restarts"]
        ));
    }
    if let Some(error) = value["last_error"].as_str() {
        lines.push(format!("  error     {error}"));
    }
    lines.push(format!("  log       {}", text("log")));
    lines
}

/// The first eight characters identify an endpoint in conversation; the full id
/// is one `--json` away.
fn short_id(id: &str) -> String {
    id.chars().take(8).collect::<String>() + "…"
}

async fn config(args: &[String]) -> Result<Vec<String>, String> {
    let mut config = read_config()?;
    let mut write = false;
    let mut overlay: Option<Vec<String>> = None;
    let mut index = 0;
    while index < args.len() {
        let argument = args[index].as_str();
        match argument {
            "--write" => write = true,
            "--enabled" => {
                let value = value_of(args, &mut index, argument)?;
                config.enabled = value
                    .parse::<bool>()
                    .map_err(|_| "--enabled takes true or false".to_owned())?;
            }
            "--tun" => config.tun = Some(value_of(args, &mut index, argument)?),
            "--mtu" => {
                config.mtu = value_of(args, &mut index, argument)?
                    .parse()
                    .map_err(|_| "--mtu takes a number".to_owned())?;
            }
            "--refresh-secs" => {
                config.refresh_secs = value_of(args, &mut index, argument)?
                    .parse()
                    .map_err(|_| "--refresh-secs takes a number".to_owned())?;
            }
            "--listen" => config.listen = Some(value_of(args, &mut index, argument)?),
            "--status" => config.status = Some(value_of(args, &mut index, argument)?.into()),
            "--external" => {
                config.external = value_of(args, &mut index, argument)?
                    .parse::<bool>()
                    .map_err(|_| "--external takes true or false".to_owned())?;
            }
            "--binary" => config.binary = Some(value_of(args, &mut index, argument)?.into()),
            "--mycelium-binary" => {
                config.mycelium_binary = Some(value_of(args, &mut index, argument)?.into())
            }
            "--overlay" => {
                overlay
                    .get_or_insert_with(Vec::new)
                    .push(value_of(args, &mut index, argument)?);
            }
            other => return Err(format!("unknown iroh-tun config argument `{other}`")),
        }
        index += 1;
    }
    if let Some(overlay) = overlay {
        config.overlay = overlay;
    }
    let config = config.validate()?;
    let path = Paths::under(&myceliumd::home_dir()).config;
    let rendered = serde_json::to_string_pretty(&config).map_err(|error| error.to_string())?;
    if !write {
        return Ok(vec![
            format!("{}", path.display()),
            rendered,
            "(plan only; add --write to install it)".into(),
        ]);
    }
    write_config(&path, &rendered)?;
    Ok(vec![
        format!("wrote {}", path.display()),
        rendered,
        format!(
            "myceliumd picks this up within {}s; `mycelium iroh-tun status` follows the tunnel",
            iroh_tun::tick_interval().as_secs()
        ),
    ])
}

fn value_of(args: &[String], index: &mut usize, flag: &str) -> Result<String, String> {
    *index += 1;
    args.get(*index)
        .cloned()
        .ok_or_else(|| format!("{flag} needs a value"))
}

fn read_config() -> Result<Config, String> {
    let path = Paths::under(&myceliumd::home_dir()).config;
    match std::fs::read(&path) {
        Ok(bytes) => {
            serde_json::from_slice(&bytes).map_err(|error| format!("{}: {error}", path.display()))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Config::default()),
        Err(error) => Err(format!("read {}: {error}", path.display())),
    }
}

/// Atomic, because a half-written config is an operator intent the daemon would
/// have to guess at.
fn write_config(path: &std::path::Path, rendered: &str) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|error| format!("create {}: {error}", parent.display()))?;
    }
    let temporary = path.with_extension("json.tmp");
    std::fs::write(&temporary, format!("{rendered}\n"))
        .map_err(|error| format!("write {}: {error}", temporary.display()))?;
    std::fs::rename(&temporary, path)
        .map_err(|error| format!("install {}: {error}", path.display()))
}

fn access(error: ClientError) -> String {
    error.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_disabled_tunnel_says_how_to_enable_it() {
        let value = serde_json::json!({
            "enabled": false,
            "config": "/home/x/.mycelium/iroh-tun.json"
        });
        let lines = render(&value);
        assert!(lines[0].contains("not configured"));
        assert!(lines[1].contains("--write"));
    }

    #[test]
    fn a_running_tunnel_shows_identity_and_what_it_claims() {
        let value = serde_json::json!({
            "enabled": true,
            "running": true,
            "publishing": true,
            "tun": "utun220",
            "mtu": 1280,
            "endpoint_id": "295ca41d4e6e4b0f8d5b1c2f9a7e3d6c8b4a2f1e0d9c7b6a5f4e3d2c1b0a9f8e",
            "overlay": ["10.42.0.0/24"],
            "routes": [{"prefix": "10.9.0.0/24", "peer": "aa"}],
            "refresh_failures": 0,
            "status_age_secs": 3,
            "pid": 42,
            "restarts": 1,
            "log": "/home/x/.mycelium/iroh-tun.log"
        });
        let lines = render(&value).join("\n");
        assert!(lines.contains("running on utun220 mtu 1280"), "{lines}");
        assert!(lines.contains("295ca41d…"), "{lines}");
        assert!(lines.contains("publishing iroh-tun"), "{lines}");
        assert!(lines.contains("10.42.0.0/24"), "{lines}");
        assert!(lines.contains("1 learned"), "{lines}");
    }

    #[test]
    fn an_empty_overlay_is_reported_as_a_one_way_overlay() {
        let value = serde_json::json!({
            "enabled": true,
            "running": true,
            "publishing": true,
            "tun": "utun220",
            "mtu": 1280,
            "endpoint_id": "295ca41d4e6e4b0f8d5b1c2f9a7e3d6c8b4a2f1e0d9c7b6a5f4e3d2c1b0a9f8e",
            "overlay": [],
            "routes": [],
            "status_age_secs": 1,
            "log": "/tmp/log"
        });
        assert!(render(&value).join("\n").contains("nothing can reach it"));
    }
}
