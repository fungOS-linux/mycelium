use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use mycelium_peer_protocol::{SshRenewalRequest, SshRenewalResponse};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RenewalBinding {
    pub node_id: String,
    pub unix_users: Vec<String>,
    pub roles: Vec<String>,
    pub credential_ttl: u64,
    #[serde(default)]
    pub revoked: bool,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
struct RenewalBindings {
    bindings: Vec<RenewalBinding>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct RenewalState {
    expires_at: u64,
    renew_after: u64,
}

pub fn bindings_path() -> PathBuf {
    crate::home_dir().join("ssh/renewal-bindings.json")
}

pub fn authorize(binding: RenewalBinding) -> Result<(), String> {
    if binding.node_id.len() != 64 || !binding.node_id.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err("renewal node ID must be a 32-byte hexadecimal peer identity".into());
    }
    if binding.unix_users.is_empty() || binding.roles.is_empty() {
        return Err("renewal authorization needs at least one Unix user and role".into());
    }
    if binding
        .unix_users
        .iter()
        .chain(&binding.roles)
        .any(|value| !safe_atom(value))
    {
        return Err("renewal Unix users and roles must be safe account-name atoms".into());
    }
    if binding.credential_ttl == 0 || binding.credential_ttl > 30 * 24 * 60 * 60 {
        return Err("renewal credential TTL must be between 1 second and 30 days".into());
    }
    let path = bindings_path();
    let mut store = load_bindings(&path)?;
    store
        .bindings
        .retain(|entry| entry.node_id != binding.node_id);
    store.bindings.push(binding);
    store
        .bindings
        .sort_by(|left, right| left.node_id.cmp(&right.node_id));
    atomic_write(
        &path,
        &serde_json::to_vec_pretty(&store).map_err(|e| e.to_string())?,
    )
}

pub fn issue(request: &SshRenewalRequest, now: u64) -> Option<SshRenewalResponse> {
    let ca = crate::home_dir().join("ssh/user_ca");
    if !ca.is_file() {
        return None;
    }
    Some(
        issue_inner(request, now, &ca).unwrap_or_else(|error| SshRenewalResponse {
            request_id: request.request_id.clone(),
            certificate: None,
            expires_at: None,
            error: Some(error),
        }),
    )
}

fn issue_inner(
    request: &SshRenewalRequest,
    now: u64,
    ca: &Path,
) -> Result<SshRenewalResponse, String> {
    request
        .verify()
        .map_err(|error| format!("invalid peer proof: {error}"))?;
    if request.requested_at.abs_diff(now) > 300 {
        return Err("renewal request clock is outside the five-minute acceptance window".into());
    }
    if request.public_key.len() > 16 * 1024 || !request.public_key.starts_with("ssh-") {
        return Err("renewal request contains an invalid SSH public key".into());
    }
    let store = load_bindings(&bindings_path())?;
    let binding = store
        .bindings
        .iter()
        .find(|entry| entry.node_id == request.node_id && !entry.revoked)
        .ok_or("peer has no active SSH renewal authorization")?;
    let certificate = sign_certificate(request, binding, ca)?;
    Ok(SshRenewalResponse {
        request_id: request.request_id.clone(),
        certificate: Some(certificate),
        expires_at: Some(now.saturating_add(binding.credential_ttl)),
        error: None,
    })
}

fn sign_certificate(
    request: &SshRenewalRequest,
    binding: &RenewalBinding,
    ca: &Path,
) -> Result<String, String> {
    let root = crate::home_dir().join("ssh/renewal-staging");
    fs::create_dir_all(&root).map_err(|error| format!("create renewal staging: {error}"))?;
    let stem = root.join(&request.request_id);
    let public = stem.with_extension("pub");
    fs::write(&public, &request.public_key).map_err(|error| format!("stage SSH key: {error}"))?;
    let principals = binding
        .roles
        .iter()
        .map(|role| format!("mycelium-role-{role}"))
        .collect::<Vec<_>>()
        .join(",");
    let validity = format!("+0s:+{}s", binding.credential_ttl);
    let identity = format!("mycelium:renew:{}", request.node_id);
    let serial = crate::peer::now().wrapping_mul(1_000_003);
    let output = Command::new("ssh-keygen")
        .args(["-q", "-s"])
        .arg(ca)
        .args([
            "-I",
            &identity,
            "-n",
            &principals,
            "-V",
            &validity,
            "-z",
            &serial.to_string(),
        ])
        .arg(&public)
        .output()
        .map_err(|error| format!("run ssh-keygen: {error}"))?;
    let certificate = PathBuf::from(format!("{}-cert.pub", stem.display()));
    let result = if output.status.success() {
        fs::read_to_string(&certificate)
            .map_err(|error| format!("read renewed certificate: {error}"))
    } else {
        Err(format!(
            "ssh-keygen failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ))
    };
    let _ = fs::remove_file(public);
    let _ = fs::remove_file(certificate);
    result
}

pub fn renewal_request(
    key: &ed25519_dalek::SigningKey,
    now: u64,
) -> Result<Option<SshRenewalRequest>, String> {
    let home = crate::home_dir();
    let public_key = home.join("ssh/public-key.pub");
    let fallback = dirs_public_key();
    let public_key = if public_key.is_file() {
        public_key
    } else {
        fallback
    };
    let certificate = home.join("ssh/user-cert.pub");
    if !public_key.is_file() || !certificate.is_file() || !renewal_due(now)? {
        return Ok(None);
    }
    let material =
        fs::read_to_string(public_key).map_err(|error| format!("read SSH public key: {error}"))?;
    let request_id = format!(
        "{}-{now}",
        &mycelium_peer_protocol::encode_hex(key.verifying_key().as_bytes())[..16]
    );
    SshRenewalRequest::sign(request_id, now, material, key).map(Some)
}

pub fn install(response: &SshRenewalResponse, now: u64) -> Result<(), String> {
    if let Some(error) = &response.error {
        return Err(error.clone());
    }
    let certificate = response
        .certificate
        .as_deref()
        .ok_or("renewal response has no certificate")?;
    let expires_at = response
        .expires_at
        .ok_or("renewal response has no expiry")?;
    if expires_at <= now
        || !certificate.starts_with("ssh-")
        || !certificate.contains("-cert-v01@openssh.com")
    {
        return Err("renewal response contains an invalid certificate".into());
    }
    let directory = crate::home_dir().join("ssh");
    fs::create_dir_all(&directory).map_err(|error| format!("create SSH state: {error}"))?;
    let installed = directory.join("user-cert.pub");
    // A unique staging path prevents two concurrent renewals (for example two
    // connected issuers answering the same request) from racing on the same
    // file and turning a successful install into a spurious ENOENT rename.
    static STAGING_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let sequence = STAGING_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let staged = directory.join(format!(
        "user-cert.renewal-staging-{}-{sequence}.pub",
        std::process::id()
    ));
    fs::write(&staged, certificate)
        .map_err(|error| format!("stage renewed certificate: {error}"))?;
    let validation = validate_replacement(&installed, &staged);
    if let Err(error) = validation {
        let _ = fs::remove_file(&staged);
        return Err(error);
    }
    if let Err(error) = fs::rename(&staged, &installed) {
        let _ = fs::remove_file(&staged);
        // Another writer may have installed an equivalent certificate first.
        let already_installed = fs::read(&installed)
            .ok()
            .is_some_and(|bytes| bytes == certificate.as_bytes());
        if !already_installed {
            return Err(format!("install renewed certificate: {error}"));
        }
    }
    let lifetime = expires_at.saturating_sub(now);
    let state = RenewalState {
        expires_at,
        renew_after: now.saturating_add(lifetime.saturating_mul(2) / 3),
    };
    atomic_write(
        &directory.join("renewal-state.json"),
        &serde_json::to_vec_pretty(&state).map_err(|error| error.to_string())?,
    )
}

fn validate_replacement(installed: &Path, staged: &Path) -> Result<(), String> {
    // A first-time install has nothing to compare against; the certificate is
    // still validated for shape and expiry by `install`. A renewal must not
    // change the issuing CA or public key binding of an existing certificate.
    if !installed.is_file() {
        return Ok(());
    }
    let inspect = |path: &Path| -> Result<String, String> {
        let output = Command::new("ssh-keygen")
            .args(["-L", "-f"])
            .arg(path)
            .output()
            .map_err(|error| format!("inspect SSH certificate: {error}"))?;
        if !output.status.success() {
            return Err(format!(
                "invalid renewed SSH certificate: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            ));
        }
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    };
    let old = inspect(installed)?;
    let new = inspect(staged)?;
    for label in ["Signing CA:", "Public key:"] {
        let field = |text: &str| {
            text.lines()
                .find(|line| line.trim_start().starts_with(label))
                .map(|line| line.trim().to_owned())
        };
        if field(&old).is_none() || field(&old) != field(&new) {
            return Err(format!(
                "renewed SSH certificate changed its {label} binding"
            ));
        }
    }
    Ok(())
}

fn renewal_due(now: u64) -> Result<bool, String> {
    let path = crate::home_dir().join("ssh/renewal-state.json");
    match fs::read(&path) {
        Ok(bytes) => {
            let state: RenewalState = serde_json::from_slice(&bytes)
                .map_err(|error| format!("read {}: {error}", path.display()))?;
            Ok(now >= state.renew_after)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(true),
        Err(error) => Err(format!("read {}: {error}", path.display())),
    }
}

fn dirs_public_key() -> PathBuf {
    std::env::var("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("."))
        .join(".ssh/id_ed25519.pub")
}

fn load_bindings(path: &Path) -> Result<RenewalBindings, String> {
    match fs::read(path) {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .map_err(|error| format!("read {}: {error}", path.display())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            Ok(RenewalBindings::default())
        }
        Err(error) => Err(format!("read {}: {error}", path.display())),
    }
}

fn atomic_write(path: &Path, bytes: &[u8]) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| format!("create {}: {error}", parent.display()))?;
    }
    let temporary = path.with_extension("tmp");
    fs::write(&temporary, bytes)
        .map_err(|error| format!("write {}: {error}", temporary.display()))?;
    fs::rename(&temporary, path).map_err(|error| format!("install {}: {error}", path.display()))
}

fn safe_atom(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renewal_request_proof_detects_tampering() {
        let key = ed25519_dalek::SigningKey::from_bytes(&[9; 32]);
        let mut request =
            SshRenewalRequest::sign("request-1".into(), 42, "ssh-ed25519 AAAA".into(), &key)
                .unwrap();
        assert!(request.verify().is_ok());
        request.requested_at += 1;
        assert!(request.verify().is_err());
    }
}
