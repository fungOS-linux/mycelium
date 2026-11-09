//! Fixed root bootstrap supervising a signed, gossiped worker. The bootstrap
//! is not replaced during activation: it can recover a failed worker after a
//! crash/reboot. Activation and rollback belong to the shared software engine.
use crate::host_access::{install, protected, Policy};
use mycelium_peer_protocol::{sha256_hex, AuthorityRecord, PackageManifest};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::Read,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

const PACKAGE: &str = "mycelium-host-access";
type Error = Box<dyn std::error::Error + Send + Sync>;

/// Subscribe only to artifact caching. Privileged activation remains controlled
/// by the separate root-owned policy, never this user-daemon placement hint.
pub(crate) fn placement_hint(args: &[String]) -> Result<PathBuf, String> {
    let update_path = Path::new(option(args, "--updates")?);
    protected(update_path)?;
    let config: Updates =
        serde_json::from_slice(&fs::read(update_path).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;
    let current = myceliumd::software_policy_path();
    let mut policy = if current.exists() {
        myceliumd::software::read_policy(&current).map_err(|e| e.to_string())?
    } else {
        myceliumd::software::SoftwarePolicy {
            schema_version: 1,
            defaults: Default::default(),
            rules: vec![],
        }
    };
    policy.rules.retain(|r| r.name != "root-host-access-cache");
    policy.rules.push(myceliumd::software::PlacementRule {
        name: "root-host-access-cache".into(),
        selector: Default::default(),
        packages: vec![myceliumd::software::DesiredPackage {
            name: PACKAGE.into(),
            channel: config.channel,
            updates: Some(myceliumd::software::UpdatePolicy::Manual),
            requires: BTreeMap::new(),
        }],
    });
    policy.validate()?;
    let destination = PathBuf::from("/etc/mycelium/host-access-software-hint.json");
    install(
        &destination,
        &serde_json::to_vec(&policy).map_err(|e| e.to_string())?,
        0o644,
    )?;
    Ok(destination)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Updates {
    channel: String,
    minimum_age_secs: u64,
    rollout_window_secs: u64,
    retry_backoff_secs: u64,
}
#[derive(Default, Deserialize, Serialize)]
struct State {
    seen: BTreeMap<String, u64>,
    attempts: BTreeMap<String, u64>,
}

fn option<'a>(args: &'a [String], key: &str) -> Result<&'a str, String> {
    args.windows(2)
        .find(|a| a[0] == key)
        .map(|a| a[1].as_str())
        .ok_or_else(|| format!("missing {key}"))
}

fn stage_artifact(manifest: &PackageManifest, artifacts: &Path) -> Result<(), Error> {
    if manifest.artifact_size == 0 || manifest.artifact_size > 128 * 1024 * 1024 {
        return Err("host helper artifact exceeds bounded size".into());
    }
    let destination = artifacts.join(&manifest.artifact_digest);
    if destination.exists() {
        protected(&destination)?;
        if sha256_hex(&fs::read(&destination)?) == manifest.artifact_digest {
            return Ok(());
        }
        return Err("root artifact cache digest mismatch".into());
    }
    // An untrusted peer-owned cache may supply bytes, never authority. Read a
    // bounded stream (including symlink/device cases), then hash before storing.
    let source = myceliumd::artifacts_dir().join(&manifest.artifact_digest);
    let mut bytes = Vec::new();
    fs::File::open(source)?
        .take(manifest.artifact_size + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 != manifest.artifact_size
        || sha256_hex(&bytes) != manifest.artifact_digest
    {
        return Err("peer artifact does not match root-verified manifest".into());
    }
    install(&destination, &bytes, 0o600)?;
    Ok(())
}

fn probe(executable: &Path, policy: &Path, apply: bool) -> Result<(), Error> {
    let canonical = fs::canonicalize(executable)?;
    protected(&canonical)?;
    let mut child = Command::new(&canonical)
        .args([
            "access",
            "host",
            if apply { "apply" } else { "plan" },
            "--policy",
            policy.to_str().ok_or("non-UTF8 policy")?,
        ])
        .args(if apply { vec!["--write"] } else { vec![] })
        .env("MYCELIUM_NO_AUTOSTART", "1")
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()?;
    let stdout = child.stdout.take().ok_or("missing worker stdout")?;
    let reader = std::thread::spawn(move || {
        let mut bytes = Vec::new();
        let result = stdout.take(65537).read_to_end(&mut bytes);
        (result, bytes)
    });
    let deadline = Instant::now() + Duration::from_secs(30);
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err("host worker exceeded 30-second deadline".into());
        }
        std::thread::sleep(Duration::from_millis(25));
    };
    let (result, bytes) = reader.join().map_err(|_| "worker output reader panicked")?;
    result?;
    if !status.success() || bytes.len() > 65536 {
        return Err("host worker failed or exceeded bounded output".into());
    }
    if !apply {
        let value: Value = serde_json::from_slice(&bytes)?;
        if !value["accounts"].is_object()
            || !value["ssh_principals"].is_object()
            || !value["managed_users"].is_array()
        {
            return Err("worker lacks identity-bound host reconciliation health contract".into());
        }
    }
    Ok(())
}

struct Worker {
    current: PathBuf,
    policy: PathBuf,
}
impl myceliumd::software_service::Lifecycle for Worker {
    fn preflight(&self, executable: &Path) -> Result<(), Error> {
        protected(&fs::canonicalize(executable)?)?;
        protected(&self.policy)?;
        Ok(())
    }
    fn stop(&self) -> Result<(), Error> {
        Ok(())
    } // bounded oneshot, no persistent daemon to stop
    fn start(&self) -> Result<(), Error> {
        Ok(())
    }
    fn verify(&self, digest: &str) -> Result<(), Error> {
        let executable = fs::canonicalize(&self.current)?;
        protected(&executable)?;
        if sha256_hex(&fs::read(&executable)?) != digest {
            return Err("root worker digest mismatch".into());
        }
        probe(&executable, &self.policy, false)
    }
}

pub fn run(
    args: &[String],
    access: &Value,
    authority: &Value,
    packages: &Value,
) -> Result<Vec<String>, String> {
    let policy_path = Path::new(option(args, "--policy")?);
    if args.iter().any(|a| a == "--dry-run") {
        return crate::host_access::run(
            &[
                "plan".into(),
                "--policy".into(),
                policy_path.display().to_string(),
            ],
            access,
            authority,
        );
    }
    if !args.iter().any(|a| a == "--write") {
        return Err("supervision requires --write".into());
    }
    // Always enforce cached grant expiry first, even when packages or the
    // carrier are unavailable. The fixed bootstrap is a recovery implementation.
    let mut messages = crate::host_access::run(
        &[
            "apply".into(),
            "--policy".into(),
            policy_path.display().to_string(),
            "--write".into(),
        ],
        access,
        authority,
    )?;
    if packages.is_null() {
        messages
            .push("package updates unavailable; fixed bootstrap enforced retained access".into());
        return Ok(messages);
    }
    let result = (|| -> Result<(), Error> {
        let config_path = Path::new(option(args, "--updates")?);
        protected(config_path)?;
        let config: Updates = serde_json::from_slice(&fs::read(config_path)?)?;
        if config.channel.is_empty()
            || !config
                .channel
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
            || config.minimum_age_secs > 30 * 86400
            || config.rollout_window_secs > 30 * 86400
            || config.retry_backoff_secs > 30 * 86400
        {
            return Err("invalid bounded host rollout policy".into());
        }
        protected(policy_path)?;
        let trust: Policy = serde_json::from_slice(&fs::read(policy_path)?)?;
        let records: Vec<AuthorityRecord> = serde_json::from_value(authority.clone())?;
        let empty = BTreeSet::new();
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let resolver = myceliumd::authority::AuthorityResolver::new(
            &trust.authority_roots,
            &empty,
            &trust.legacy_release_keys,
            &records,
            now,
        );
        let manifests: Vec<PackageManifest> = serde_json::from_value(packages.clone())?;
        let authorized: Vec<_> = manifests
            .into_iter()
            .filter(|p| {
                p.name == PACKAGE
                    && p.channel == config.channel
                    && p.artifact_digest.len() == 64
                    && p.artifact_digest.bytes().all(|b| b.is_ascii_hexdigit())
                    && semver::Version::parse(&p.version).is_ok()
                    && p.verify().is_ok()
                    && resolver.package(p).authorized
            })
            .collect();
        let targets = mycelium_peer_protocol::local_compatible_targets();
        let base = Path::new("/var/lib/mycelium/access");
        protected(base)?;
        let lock_path = base.join("supervisor.lock");
        if lock_path.exists() {
            protected(&lock_path)?;
        }
        let lock = fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(lock_path)?;
        lock.try_lock()?;
        let artifacts = base.join("artifacts");
        let software = base.join("software");
        fs::create_dir_all(&artifacts)?;
        fs::create_dir_all(&software)?;
        protected(&artifacts)?;
        protected(&software)?;
        let worker = Worker {
            current: software.join(PACKAGE).join("current").join(PACKAGE),
            policy: policy_path.to_owned(),
        };
        myceliumd::software::recover_in(PACKAGE, &software, &worker)?;
        if !worker.current.exists() {
            let bootstrap = std::env::current_exe()?;
            protected(&bootstrap)?;
            let digest = sha256_hex(&fs::read(&bootstrap)?);
            let baseline = authorized
                .iter()
                .find(|p| p.artifact_digest == digest && targets.contains(&p.target))
                .ok_or(
                    "root helper needs signed baseline matching the installed bootstrap bytes",
                )?;
            install(&artifacts.join(&digest), &fs::read(&bootstrap)?, 0o600)?;
            myceliumd::software::activate_in(baseline, &artifacts, &software, None)?;
        }
        let state_path = base.join("rollout-state.json");
        let mut state: State = if state_path.exists() {
            protected(&state_path)?;
            serde_json::from_slice(&fs::read(&state_path)?)?
        } else {
            State::default()
        };
        let candidate =
            myceliumd::software::select(&authorized, PACKAGE, &config.channel, &targets)
                .ok_or("no authorized compatible host helper manifest")?;
        let first_seen = *state
            .seen
            .entry(candidate.artifact_digest.clone())
            .or_insert(now);
        let current_digest = sha256_hex(&fs::read(fs::canonicalize(&worker.current)?)?);
        let current = authorized
            .iter()
            .find(|p| p.artifact_digest == current_digest)
            .ok_or("active worker has no currently authorized manifest")?;
        if candidate.artifact_digest != current_digest {
            // The worker manifest was matched by digest, so this release is
            // verified rather than merely recorded.
            let running = myceliumd::updates::RunningRelease {
                version: Some(current.version.clone()),
                source: "binary digest",
                digest: Some(current_digest.clone()),
                digest_matches: true,
            };
            let _ = crate::automatic_upgrade_allowed(&running, &candidate.version)?;
            let due = first_seen
                .saturating_add(config.minimum_age_secs)
                .saturating_add(crate::node_rollout_offset(config.rollout_window_secs));
            let retry = state
                .attempts
                .get(&candidate.artifact_digest)
                .copied()
                .unwrap_or(0)
                .saturating_add(config.retry_backoff_secs);
            if now >= due && now >= retry {
                stage_artifact(candidate, &artifacts)?;
                state
                    .attempts
                    .insert(candidate.artifact_digest.clone(), now);
                install(&state_path, &serde_json::to_vec(&state)?, 0o600)?;
                myceliumd::software::activate_in(candidate, &artifacts, &software, Some(&worker))?;
                messages.push(format!(
                    "activated root-verified gossiped worker {} {}",
                    PACKAGE, candidate.version
                ));
            } else {
                messages.push(format!(
                    "worker {} awaiting root rollout age/backoff",
                    candidate.version
                ));
            }
        }
        install(&state_path, &serde_json::to_vec(&state)?, 0o600)?;
        probe(&worker.current, policy_path, true)?;
        messages.push(
            "signed worker applied host policy; fixed bootstrap retained for recovery".into(),
        );
        Ok(())
    })();
    result.map_err(|e| format!("bootstrap enforced access; worker rollout failed: {e}"))?;
    Ok(messages)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn supervision_never_mutates_without_write() {
        let args = vec![
            "supervise".into(),
            "--policy".into(),
            "/nonexistent-root-policy".into(),
            "--updates".into(),
            "/nonexistent-update-policy".into(),
        ];
        assert_eq!(
            run(&args, &Value::Null, &Value::Null, &Value::Null).unwrap_err(),
            "supervision requires --write"
        );
    }
    #[test]
    fn unbounded_artifact_rejected_before_cache_io() {
        let key = ed25519_dalek::SigningKey::from_bytes(&[7; 32]);
        let mut manifest = PackageManifest::sign(
            &key,
            PACKAGE.into(),
            "1.0.0".into(),
            "stable".into(),
            "test".into(),
            b"fixture",
        )
        .unwrap();
        manifest.artifact_size = 129 * 1024 * 1024;
        assert!(
            stage_artifact(&manifest, Path::new("/nonexistent-root-artifacts"))
                .unwrap_err()
                .to_string()
                .contains("bounded size")
        );
    }
}
