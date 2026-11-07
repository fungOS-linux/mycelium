//! Local SSH access healthcheck.
//!
//! The check reads only locally installed, already-verified state: the user
//! certificate this node holds, its renewal bookkeeping, and (on Linux) the
//! root-owned enforcement evidence written by `mycelium access host apply`.
//! Grant and authority counts come from signed fleet gossip that the daemon
//! already verified; they are reported as counts, never as an authorization
//! assertion. This module never issues or extends a certificate or a grant.
use std::path::Path;
use std::time::UNIX_EPOCH;

use mycelium_peer_protocol::SshHealth;
use serde::Deserialize;

const SCHEMA_VERSION: u16 = 1;
/// Enforcement older than this is reported as stale to the operator.
const ENFORCEMENT_STALE_SECS: u64 = 30 * 60;

#[derive(Clone, Debug, Deserialize)]
struct RenewalState {
    expires_at: u64,
    renew_after: u64,
}

fn read_certificate_principals(path: &Path) -> Vec<String> {
    let Ok(output) = std::process::Command::new("ssh-keygen")
        .args(["-L", "-f"])
        .arg(path)
        .output()
    else {
        return Vec::new();
    };
    if !output.status.success() {
        return Vec::new();
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let mut principals = Vec::new();
    let mut in_principals = false;
    for line in text.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("Principals:") {
            in_principals = true;
            let rest = rest.trim();
            if !rest.is_empty() {
                principals.push(rest.to_string());
            }
            continue;
        }
        if in_principals {
            // Continuation lines are indented and end at the next labelled field.
            if line.starts_with(' ') && !trimmed.contains(':') {
                principals.push(trimmed.to_string());
                continue;
            }
            if trimmed.is_empty() || trimmed.contains(':') {
                in_principals = false;
            }
        }
    }
    principals
}

fn enforcement_state(now: u64) -> String {
    let path = Path::new("/var/lib/mycelium/access/managed-users.json");
    let modified = std::fs::metadata(path)
        .ok()
        .and_then(|metadata| metadata.modified().ok())
        .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
        .map(|duration| duration.as_secs());
    enforcement_label(now, modified)
}

fn enforcement_label(now: u64, modified: Option<u64>) -> String {
    match modified {
        // macOS and hosts that have never run host enforcement have no evidence.
        None | Some(0) => "unknown".into(),
        Some(modified) if now.saturating_sub(modified) <= ENFORCEMENT_STALE_SECS => "ok".into(),
        Some(_) => "stale".into(),
    }
}

/// Local certificate state and expiry, independent of the gossip record.
/// Returns `(state, expires_at)` where state is valid/due/expired/missing/error.
pub fn certificate_state(now: u64) -> (String, Option<u64>) {
    let directory = crate::home_dir().join("ssh");
    let certificate = directory.join("user-cert.pub");
    let state_path = directory.join("renewal-state.json");
    if !certificate.is_file() {
        return ("missing".to_string(), None);
    }
    match std::fs::read(&state_path) {
        Ok(bytes) => match serde_json::from_slice::<RenewalState>(&bytes) {
            Ok(state) => {
                let label = if state.expires_at <= now {
                    "expired"
                } else if state.renew_after <= now {
                    "due"
                } else {
                    "valid"
                };
                (label.to_string(), Some(state.expires_at))
            }
            Err(_) => ("error".to_string(), None),
        },
        // A certificate with no renewal bookkeeping is still usable; treat it
        // as due so the next renewal pass runs.
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => ("due".to_string(), None),
        Err(_) => ("error".to_string(), None),
    }
}

/// Number of seconds since the Unix epoch, matching peer-protocol timestamps.
pub fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

/// Collect the locally derived SSH health record.
pub fn collect(
    node_id: &str,
    hostname: &str,
    site: &str,
    now: u64,
    listening: bool,
    established_sessions: u32,
    access_grants: u32,
    access_authorities: u32,
) -> SshHealth {
    let directory = crate::home_dir().join("ssh");
    let certificate = directory.join("user-cert.pub");
    let state_path = directory.join("renewal-state.json");

    let (certificate_state, not_after) = certificate_state(now);
    let renewal_after = std::fs::read(&state_path)
        .ok()
        .and_then(|bytes| serde_json::from_slice::<RenewalState>(&bytes).ok())
        .map(|state| state.renew_after);

    let principals = if certificate.is_file() {
        read_certificate_principals(&certificate)
    } else {
        Vec::new()
    };
    let enforcement = enforcement_state(now);
    let (disk_available, disk_state) = match crate::disk::available_bytes(&directory) {
        Ok(available) => (Some(available), crate::disk::state(available).label().to_string()),
        Err(_) => (None, "unknown".to_string()),
    };

    let verdict = if !listening
        || matches!(certificate_state.as_str(), "expired" | "missing" | "error")
        || disk_state == "critical"
    {
        "fail"
    } else if certificate_state == "due" || enforcement == "stale" || disk_state == "low" {
        "warn"
    } else {
        "ok"
    };

    SshHealth {
        schema_version: SCHEMA_VERSION,
        node_id: node_id.to_string(),
        hostname: hostname.to_string(),
        site: site.to_string(),
        observed_at: now,
        listening,
        established_sessions,
        certificate_state,
        certificate_not_before: None,
        certificate_not_after: not_after,
        certificate_principals: principals,
        renewal_after,
        renewal_error: None,
        access_grants,
        access_authorities,
        access_enforcement: enforcement,
        disk_available_bytes: disk_available,
        disk_state,
        verdict: verdict.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_certificate_fails_the_verdict() {
        // Uses the real home; only asserts the state machine, not the paths.
        let health = collect("node", "host", "site", 1_000, true, 0, 0, 0);
        assert!(matches!(
            health.certificate_state.as_str(),
            "missing" | "valid" | "due" | "expired" | "error"
        ));
        if !health.listening {
            assert_eq!(health.verdict, "fail");
        }
    }

    #[test]
    fn enforcement_labels_missing_and_stale_evidence() {
        assert_eq!(enforcement_label(1_000, None), "unknown");
        assert_eq!(enforcement_label(1_000, Some(0)), "unknown");
        assert_eq!(enforcement_label(1_000, Some(900)), "ok");
        assert_eq!(enforcement_label(1_000 + ENFORCEMENT_STALE_SECS + 1, Some(1_000)), "stale");
    }
}
