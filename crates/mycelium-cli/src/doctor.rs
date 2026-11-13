//! Read-only health checks with an explicit repair path.
//!
//! Doctor deliberately reports local facts rather than starting the daemon or
//! changing the host. `--fix` is the only mutating mode and delegates to the
//! frontdoor lifecycle module.
use myceliumd::{client::Client, protocol::Request};
use serde_json::{json, Value};
use std::io::Write;
use std::net::ToSocketAddrs;
use std::path::Path;
use std::process::Command;
use std::time::Duration;

pub async fn run(args: &[String]) -> Result<Vec<String>, String> {
    let mut home = myceliumd::home_dir();
    let mut json_output = false;
    let mut fix = false;
    let mut trust = false;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--json" => json_output = true,
            "--fix" => fix = true,
            "--trust-cert" => trust = true,
            "--path" => {
                index += 1;
                home = expand_home(
                    args.get(index)
                        .ok_or("--path requires a Mycelium home directory")?,
                );
            }
            other => return Err(format!("unknown doctor argument `{other}`")),
        }
        index += 1;
    }
    if trust && !fix {
        return Err("--trust-cert requires --fix".into());
    }

    let mut checks = Vec::new();
    let mut fix_lines = Vec::new();
    let mut catalog: Option<Value> = None;
    if fix {
        match crate::frontdoor::install_default(&home, trust).await {
            Ok(lines) => fix_lines.extend(lines),
            Err(error) => add(&mut checks, "frontdoor fix", "fail", error),
        }
    }
    let mut client = match Client::try_connect().await {
        Ok(mut client) => match daemon_call(&mut client, &Request::Hello).await {
            Ok(hello) => {
                add(
                    &mut checks,
                    "daemon",
                    "ok",
                    format!(
                        "v{} pid {} socket {}",
                        hello["version"].as_str().unwrap_or("?"),
                        hello["pid"],
                        hello["socket"].as_str().unwrap_or("?")
                    ),
                );
                Some(client)
            }
            Err(error) => {
                add(
                    &mut checks,
                    "daemon",
                    "fail",
                    format!("hello failed: {error}"),
                );
                None
            }
        },
        Err(error) => {
            add(
                &mut checks,
                "daemon",
                "fail",
                format!("not running: {error}"),
            );
            None
        }
    };

    if let Some(client) = client.as_mut() {
        match daemon_call(client, &Request::Services).await {
            Ok(services) => {
                let (fresh, total) = service_count(&services);
                let status = if fresh == 0 { "warn" } else { "ok" };
                add(
                    &mut checks,
                    "services",
                    status,
                    format!("{fresh} fresh endpoint observation(s), {total} total"),
                );
                catalog = Some(services);
            }
            Err(error) => add(
                &mut checks,
                "services",
                "warn",
                format!("catalog unavailable: {error}"),
            ),
        }
    }

    if let Some(client) = client.as_mut() {
        match daemon_call(client, &Request::IrohTunStatus).await {
            Ok(mut status) => {
                if fix {
                    match restart_tunnel(client, &status).await {
                        Ok(Some((line, refreshed))) => {
                            fix_lines.push(line);
                            status = refreshed;
                        }
                        Ok(None) => {}
                        Err(error) => add(&mut checks, "iroh-tun fix", "fail", error),
                    }
                }
                iroh_tun_checks(&mut checks, &status, catalog.as_ref());
            }
            Err(error) => add(
                &mut checks,
                "iroh-tun",
                "warn",
                format!("status unavailable: {error}"),
            ),
        }
    }

    if let Some(client) = client.as_mut() {
        update_check(&mut checks, client).await;
    }

    for host in ["ai.myc", "mcp.myc"] {
        match (host, 443u16).to_socket_addrs() {
            Ok(addresses) => {
                let addresses = addresses.collect::<Vec<_>>();
                if addresses.iter().any(|address| address.ip().is_loopback()) {
                    add(
                        &mut checks,
                        host,
                        "ok",
                        format!(
                            "resolves to {}",
                            addresses
                                .iter()
                                .map(ToString::to_string)
                                .collect::<Vec<_>>()
                                .join(", ")
                        ),
                    );
                } else {
                    add(
                        &mut checks,
                        host,
                        "fail",
                        format!("does not resolve to loopback: {addresses:?}"),
                    );
                }
            }
            Err(error) => add(
                &mut checks,
                host,
                "fail",
                format!("DNS lookup failed: {error}"),
            ),
        }
    }

    let snapshot = crate::frontdoor::snapshot(&home).await;
    frontdoor_checks(&mut checks, &snapshot, &home);
    signature_checks(&mut checks);

    let failed = checks
        .iter()
        .filter(|check| check["status"] == "fail")
        .count();
    let warnings = checks
        .iter()
        .filter(|check| check["status"] == "warn")
        .count();
    let ok = failed == 0;
    let report = if json_output {
        vec![json!({
            "ok": ok,
            "checks": checks,
            "frontdoor": snapshot,
            "fix": fix_lines,
        })
        .to_string()]
    } else {
        let mut lines = fix_lines;
        for check in &checks {
            lines.push(format!(
                "  {:<4} {}: {}",
                check["status"].as_str().unwrap_or("?"),
                check["name"].as_str().unwrap_or("?"),
                check["detail"].as_str().unwrap_or("")
            ));
        }
        lines.push(format!(
            "doctor: {} ok, {} warning(s), {} failed",
            checks.len().saturating_sub(warnings + failed),
            warnings,
            failed
        ));
        if !ok {
            lines.push("remediation: mycelium frontdoor install --write --trust-cert".into());
        }
        lines
    };
    // `main` prints `Ok` lines and exits zero. Doctor owns its exit status so
    // scripts can gate on it, which is why the report is printed here.
    for line in &report {
        println!("{line}");
    }
    let _ = std::io::stdout().flush();
    if !ok {
        std::process::exit(1);
    }
    Ok(Vec::new())
}

fn frontdoor_checks(checks: &mut Vec<Value>, snapshot: &Value, home: &Path) {
    if crate::frontdoor::supported_platform().is_err() {
        add(
            checks,
            "local frontdoor",
            "warn",
            "frontdoor lifecycle supports macOS and Linux only".into(),
        );
        return;
    }
    let installed = snapshot["installed"].as_bool().unwrap_or(false);
    add(
        checks,
        "frontdoor install",
        if installed { "ok" } else { "fail" },
        if installed {
            format!("agents and configuration present under {}", home.display())
        } else {
            "run `mycelium frontdoor install --write --trust-cert`".into()
        },
    );
    for (name, key) in [
        ("frontdoor agent", "frontdoor_agent"),
        ("ingress https agent", "ingress_https_agent"),
        ("ingress http agent", "ingress_http_agent"),
    ] {
        let loaded = snapshot[key]["loaded"].as_bool().unwrap_or(false);
        add(
            checks,
            name,
            if loaded { "ok" } else { "fail" },
            snapshot[key]["state"]
                .as_str()
                .unwrap_or("not loaded")
                .to_owned(),
        );
    }
    for (name, key, address_key) in [
        ("frontdoor listener", "frontdoor_listening", "listen"),
        (
            "ingress https listener",
            "ingress_https_listening",
            "https_listen",
        ),
        (
            "ingress http listener",
            "ingress_http_listening",
            "http_listen",
        ),
    ] {
        let listening = snapshot[key].as_bool().unwrap_or(false);
        add(
            checks,
            name,
            if listening { "ok" } else { "fail" },
            format!(
                "{} {}",
                snapshot[address_key].as_str().unwrap_or("unknown"),
                if listening { "listening" } else { "down" }
            ),
        );
    }
    let cert_trusted = snapshot["certificate_trusted"].as_bool().unwrap_or(false);
    add(
        checks,
        "certificate trust",
        if cert_trusted { "ok" } else { "warn" },
        format!(
            "{} ({})",
            snapshot["certificate"].as_str().unwrap_or("missing"),
            if cert_trusted {
                "verified for ai.myc"
            } else {
                "browser will warn; run `mycelium frontdoor install --write --trust-cert`"
            }
        ),
    );
    add(
        checks,
        "routes",
        if snapshot["routes_valid"].as_bool().unwrap_or(false) {
            "ok"
        } else {
            "fail"
        },
        snapshot["routes"].as_str().unwrap_or("missing").to_owned(),
    );
    if let Some(path) = snapshot["system_daemon"].as_str() {
        add(
            checks,
            "system daemon",
            "fail",
            format!(
                "{path} also claims 127.0.0.1:443 and must be removed before the user agent can own the socket"
            ),
        );
    }
    match snapshot["health"].as_object() {
        Some(health) => {
            let status = health.get("status").and_then(Value::as_u64).unwrap_or(0);
            add(
                checks,
                "frontdoor health",
                if status == 200 { "ok" } else { "fail" },
                format!(
                    "HTTP {status} {}",
                    health.get("body").map(Value::to_string).unwrap_or_default()
                ),
            );
            // A listener that serves without a grant is tolerable only while it
            // is loopback-only, because only this machine can reach it. It is
            // the difference between "reachable" and "safely reachable", so it
            // is reported rather than buried in the health body.
            let auth_required = health
                .get("body")
                .and_then(|body| match body {
                    Value::String(text) => serde_json::from_str::<Value>(text).ok(),
                    other => Some(other.clone()),
                })
                .and_then(|body| body.get("auth_required").and_then(Value::as_bool));
            if auth_required == Some(false) {
                add(
                    checks,
                    "frontdoor auth",
                    "warn",
                    "auth_required is false: anything that can reach the listener is served without a grant; this is only safe while the listener is loopback-only".into(),
                );
            }
        }
        None => add(
            checks,
            "frontdoor health",
            "fail",
            "no response on 127.0.0.1:8443".into(),
        ),
    }
    let tls_verified = snapshot["tls_verified"].as_bool().unwrap_or(false);
    add(
        checks,
        "tls verification",
        if tls_verified { "ok" } else { "fail" },
        if tls_verified {
            "certificate chain and ai.myc identity verified against the local trust anchor".into()
        } else if let Some(error) = snapshot["tls_error"].as_str() {
            format!("TLS probe failed: {error}")
        } else {
            "frontdoor is not listening on 127.0.0.1:8443".into()
        },
    );
}

/// The two questions the design says doctor must answer without `ifconfig`:
/// is the kind published, and does the tunnel have a route?
///
/// `ifconfig` only proves a device exists. A device with no peers looks exactly
/// like a healthy one from the outside, which is how the overlay stayed
/// undiscoverable while appearing to run.
fn iroh_tun_checks(checks: &mut Vec<Value>, status: &Value, catalog: Option<&Value>) {
    if let Some(error) = status["config_error"].as_str() {
        add(checks, "iroh-tun config", "fail", error.to_owned());
        return;
    }
    if !status["enabled"].as_bool().unwrap_or(false) {
        add(
            checks,
            "iroh-tun",
            "warn",
            format!(
                "not configured ({}); enable with `mycelium iroh-tun config --tun IFACE --overlay CIDR --write`",
                status["config"].as_str().unwrap_or("iroh-tun.json")
            ),
        );
        return;
    }
    let node = status["node"].as_str().unwrap_or_default();
    let now = now_secs();
    let published = catalog
        .and_then(|catalog| catalog["observations"].as_array())
        .is_some_and(|observations| {
            observations.iter().any(|observation| {
                observation["value"]["kind"].as_str() == Some("iroh-tun")
                    && observation["value"]["attributes"]["node_id"].as_str() == Some(node)
                    && observation["expires_at"].as_u64().unwrap_or(0) > now
            })
        });
    let running = status["running"].as_bool().unwrap_or(false);
    let publishing = status["publishing"].as_bool().unwrap_or(false);
    let routes = status["routes"].as_array().map_or(0, Vec::len);
    let prefixes = status["overlay"].as_array().map_or(0, Vec::len);
    let tun = status["tun"].as_str().unwrap_or("tun");
    add(
        checks,
        "iroh-tun publish",
        if published { "ok" } else { "fail" },
        if published {
            format!("{node} publishes kind iroh-tun for {prefixes} prefix(es)")
        } else if publishing {
            "the tunnel is up; the daemon publishes it on its next renewal".into()
        } else {
            "the catalog has no fresh iroh-tun observation for this node".into()
        },
    );
    let (status_word, detail) = if running && publishing {
        (
            if routes > 0 { "ok" } else { "warn" },
            format!(
                "{tun} up, {routes} peer prefix(es) learned, status {}s old",
                status["status_age_secs"]
            ),
        )
    } else if running {
        (
            "fail",
            format!(
                "{tun} is alive but not reporting: {} (log: {})",
                first_line(status, &["last_error", "last_exit"]),
                status["log"].as_str().unwrap_or("?")
            ),
        )
    } else {
        (
            "fail",
            format!(
                "not running: {} (log: {})",
                first_line(status, &["last_exit", "last_error"]),
                status["log"].as_str().unwrap_or("?")
            ),
        )
    };
    add(checks, "iroh-tun tunnel", status_word, detail);
    if routes == 0 && running && publishing {
        // Not a failure: the first node in a fleet has no peers to learn from
        // and has to run before a second node can exist.
        add(
            checks,
            "iroh-tun peers",
            "warn",
            "no peers yet; expected for the first node on an overlay".into(),
        );
    }
}

fn first_line(status: &Value, keys: &[&str]) -> String {
    keys.iter()
        .find_map(|key| status[*key].as_str())
        .unwrap_or("no status document")
        .to_owned()
}

/// `--fix` repairs only what needs no invention: a tunnel that is configured and
/// not working gets bounced. It never writes configuration or picks an interface.
///
/// It waits for the result. A repair command that prints "fixed" next to a
/// failing check is worse than no repair at all, because it teaches the operator
/// to ignore both lines.
async fn restart_tunnel(
    client: &mut Client,
    status: &Value,
) -> Result<Option<(String, Value)>, String> {
    if !status["enabled"].as_bool().unwrap_or(false) {
        return Ok(None);
    }
    if status["running"].as_bool().unwrap_or(false)
        && status["publishing"].as_bool().unwrap_or(false)
    {
        return Ok(None);
    }
    daemon_call(client, &Request::IrohTunRestart { write: true })
        .await
        .map_err(|error| error.to_string())?;
    // The supervisor ticks on its own cadence; give it one full tick plus the
    // child's first status write before deciding the bounce worked.
    let deadline = std::time::Instant::now() + Duration::from_secs(12);
    let mut latest = daemon_call(client, &Request::IrohTunStatus)
        .await
        .map_err(|error| error.to_string())?;
    while std::time::Instant::now() < deadline {
        if latest["publishing"].as_bool().unwrap_or(false) {
            return Ok(Some((
                "iroh-tun: bounced the tunnel; it is publishing".into(),
                latest,
            )));
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
        latest = daemon_call(client, &Request::IrohTunStatus)
            .await
            .map_err(|error| error.to_string())?;
    }
    let reason = first_line(&latest, &["last_error", "last_exit"]);
    Ok(Some((
        format!("iroh-tun: bounced the tunnel, still not publishing: {reason}"),
        latest,
    )))
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn add(checks: &mut Vec<Value>, name: &str, status: &'static str, detail: String) {
    checks.push(json!({"name": name, "status": status, "detail": detail}));
}

/// Compare the running binary and recorded update state with the newest signed
/// release the daemon knows for this channel and target.
async fn update_check(checks: &mut Vec<Value>, client: &mut Client) {
    let channel = myceliumd::updates::channel();
    let targets = mycelium_peer_protocol::local_compatible_targets();
    let value = match daemon_call(client, &Request::ReleaseList).await {
        Ok(value) => value,
        Err(error) => {
            add(
                checks,
                "mycelium version",
                "warn",
                format!("release catalog unavailable: {error}"),
            );
            return;
        }
    };
    let releases = myceliumd::updates::parse_releases(&value);
    let Some(latest) = myceliumd::updates::select_release(&releases, &channel, &targets) else {
        add(
            checks,
            "mycelium version",
            "warn",
            format!(
                "no {channel} release for compatible targets {}",
                targets.join(", ")
            ),
        );
        return;
    };
    if let Err(error) = latest.verify() {
        add(
            checks,
            "mycelium version",
            "fail",
            format!(
                "latest {channel} release {} has an invalid signature: {error}",
                latest.version
            ),
        );
        return;
    }

    let running = myceliumd::updates::running_release(&releases);
    let (installed, source, digest_matches) =
        (running.version, running.source, running.digest_matches);
    let policy = myceliumd::read_update_policy();
    let (status, detail) = if !digest_matches {
        match installed.as_deref() {
            Some(version) => (
                "warn",
                format!(
                    "update state records {version} ({source}), but the running binary is a local build; {}",
                    if policy.enabled {
                        format!(
                            "automatic updates on channel {} will install the newest signed {} release",
                            policy.channel, latest.version
                        )
                    } else {
                        "automatic updates are disabled; run `mycelium update apply --write` to adopt a signed release"
                            .to_owned()
                    }
                ),
            ),
            None => (
                "warn",
                format!(
                    "installed release is unrecorded (local build?); latest {channel} is {} for {} (run `mycelium update apply --write` to adopt it)",
                    latest.version, latest.target
                ),
            ),
        }
    } else {
        match myceliumd::updates::version_verdict(installed.as_deref(), &latest.version) {
            myceliumd::updates::VersionVerdict::Current => (
                "ok",
                format!(
                    "installed {} is the latest {channel} release for {}",
                    latest.version, latest.target
                ),
            ),
            myceliumd::updates::VersionVerdict::UpdateAvailable => (
                "warn",
                format!(
                    "update available: installed {} is older than {} on {channel}; run `mycelium update apply --write`",
                    installed.as_deref().unwrap_or("unrecorded"),
                    latest.version
                ),
            ),
            myceliumd::updates::VersionVerdict::Ahead => (
                "ok",
                format!(
                    "installed {} is ahead of the latest {channel} release {}",
                    installed.as_deref().unwrap_or("unknown"),
                    latest.version
                ),
            ),
            myceliumd::updates::VersionVerdict::Unknown => (
                "warn",
                format!(
                    "recorded release {} could not be compared with latest {channel} {}",
                    installed.as_deref().unwrap_or("unknown"),
                    latest.version
                ),
            ),
        }
    };
    add(checks, "mycelium version", status, detail);
}

fn signature_checks(checks: &mut Vec<Value>) {
    if !cfg!(target_os = "macos") {
        return;
    }
    let Ok(executable) = std::env::current_exe() else {
        return;
    };
    let signed = Command::new("codesign")
        .args(["--verify", "--strict", "--verbose=2"])
        .arg(&executable)
        .output();
    let signed = signed.as_ref().is_ok_and(|output| output.status.success());
    add(
        checks,
        "binary signature",
        if signed { "ok" } else { "warn" },
        if signed {
            "codesign verified".into()
        } else {
            "codesign verification failed; local builds are expected to be unsigned".into()
        },
    );
    let notarized = Command::new("spctl")
        .args(["--assess", "--type", "execute", "--verbose"])
        .arg(&executable)
        .output();
    let notarized = notarized
        .as_ref()
        .is_ok_and(|output| output.status.success());
    add(
        checks,
        "binary notarization",
        if notarized { "ok" } else { "warn" },
        if notarized {
            "Gatekeeper accepted the binary".into()
        } else {
            "Gatekeeper rejected the binary; release builds should be signed and notarized".into()
        },
    );
}

/// Doctor must report a wedged daemon, not hang behind it.
async fn daemon_call(
    client: &mut Client,
    request: &Request,
) -> Result<Value, myceliumd::client::ClientError> {
    tokio::time::timeout(Duration::from_secs(5), client.call(request))
        .await
        .map_err(|_| myceliumd::client::ClientError::Protocol("daemon call timed out".into()))?
}

fn service_count(value: &Value) -> (usize, usize) {
    let now = now_secs();
    let observations = value
        .get("observations")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default();
    let fresh = observations
        .iter()
        .filter(|observation| observation["expires_at"].as_u64().unwrap_or(0) > now)
        .count();
    (fresh, observations.len())
}

fn expand_home(value: &str) -> std::path::PathBuf {
    value
        .strip_prefix("~/")
        .map(|suffix| {
            std::env::var_os("HOME")
                .map(std::path::PathBuf::from)
                .unwrap_or_default()
                .join(suffix)
        })
        .unwrap_or_else(|| std::path::PathBuf::from(value))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts_only_fresh_observations() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let value = json!({"observations": [
            {"expires_at": now + 60},
            {"expires_at": now.saturating_sub(60)},
        ]});
        assert_eq!(service_count(&value), (1, 2));
    }
}
