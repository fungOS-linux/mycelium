use std::fs;
use std::path::{Path, PathBuf};

use mycelium_peer_protocol::{AccessStatement, SshRenewalRequest, SshRenewalResponse};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug)]
struct RenewalBinding {
    principal: String,
    roles: Vec<String>,
    credential_ttl: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct RenewalState {
    expires_at: u64,
    renew_after: u64,
}

pub fn issue(
    request: &SshRenewalRequest,
    now: u64,
    access: &crate::peer::AccessStateView,
) -> Option<SshRenewalResponse> {
    let ca = crate::home_dir().join("ssh/user_ca");
    if !ca.is_file() {
        return None;
    }
    Some(
        issue_inner(request, now, &ca, access).unwrap_or_else(|error| SshRenewalResponse {
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
    access: &crate::peer::AccessStateView,
) -> Result<SshRenewalResponse, String> {
    request
        .verify()
        .map_err(|error| format!("invalid peer proof: {error}"))?;
    if request.requested_at.abs_diff(now) > 300 {
        return Err("renewal request clock is outside the five-minute acceptance window".into());
    }
    if !safe_atom(&request.request_id) {
        return Err("invalid renewal request ID".into());
    }
    if request.public_key.len() > 16 * 1024 || request.public_key.trim().contains(['\n', '\r']) {
        return Err("renewal request contains an invalid SSH public key".into());
    }
    let (binding, serial) = grant_authorization(request, access, now)?;
    let certificate = sign_certificate(request, &binding, serial, now, ca)?;
    let expires_at = ssh_key::Certificate::from_openssh(&certificate)
        .map_err(|e| e.to_string())?
        .valid_before();
    Ok(SshRenewalResponse {
        request_id: request.request_id.clone(),
        certificate: Some(certificate),
        // Use the actual certificate validity, not the time before ssh-keygen
        // started. These clocks can differ on a busy authority.
        expires_at: Some(expires_at),
        error: None,
    })
}

/// Existing signed access scopes carry the renewal lease; roles, users and
/// keys remain single-source grant fields rather than a second ACL database.
pub fn scope(node_id: &str, ttl: u64) -> Result<String, String> {
    if node_id.len() != 64
        || !node_id.bytes().all(|b| b.is_ascii_hexdigit())
        || !(1..=30 * 86400).contains(&ttl)
    {
        return Err(
            "renewal scope requires a peer ID and a 1-second..30-day credential TTL".into(),
        );
    }
    Ok(format!(
        "ssh-renewal:{}:{ttl}",
        node_id.to_ascii_lowercase()
    ))
}

fn key_material(public: &str) -> Result<ssh_key::public::KeyData, String> {
    ssh_key::PublicKey::from_openssh(public.trim())
        .map(|key| key.key_data().clone())
        .map_err(|e| format!("invalid SSH key: {e}"))
}

fn grant_authorization(
    request: &SshRenewalRequest,
    access: &crate::peer::AccessStateView,
    now: u64,
) -> Result<(RenewalBinding, u64), String> {
    let material = key_material(&request.public_key)?;
    let prefix = format!("ssh-renewal:{}:", request.node_id);
    let mut eligible = Vec::new();
    let mut identities = std::collections::BTreeSet::new();
    for entry in &access.grants {
        entry
            .record
            .verify()
            .map_err(|e| format!("invalid access signature: {e}"))?;
        let AccessStatement::Grant {
            principal,
            roles,
            unix_users,
            ssh_public_keys,
            scopes,
            serial,
            not_before,
            not_after,
            ..
        } = &entry.record.statement
        else {
            continue;
        };
        if now < *not_before || now >= *not_after || roles.is_empty() || unix_users.is_empty() {
            continue;
        }
        if access.revocations.iter().any(|r| r.verify().is_ok() && matches!(&r.statement,AccessStatement::Revoke{revoked_at,..} if *revoked_at <= now) && r.statement.revokes(&entry.record.statement)) {continue;}
        if !ssh_public_keys
            .iter()
            .any(|key| key_material(key).is_ok_and(|key| key == material))
        {
            continue;
        }
        let ttl = scopes
            .iter()
            .filter_map(|scope| scope.strip_prefix(&prefix)?.parse::<u64>().ok())
            .filter(|ttl| (1..=30 * 86400).contains(ttl))
            .max();
        let Some(ttl) = ttl else {
            continue;
        };
        if roles
            .iter()
            .chain(unix_users)
            .any(|v| !safe_atom(v) || v == "root")
        {
            return Err("renewal grant contains an unsafe account or role".into());
        }
        identities.insert(principal);
        eligible.push((
            *not_before,
            *not_after,
            *serial,
            RenewalBinding {
                principal: principal.clone(),
                roles: roles.clone(),
                credential_ttl: ttl.min(not_after.saturating_sub(now)),
            },
        ));
    }
    if identities.len() > 1 {
        return Err("SSH key has ambiguous renewal principals; revoke conflicting grants".into());
    }
    eligible.sort_by_key(|(before, after, serial, _)| (*before, *after, *serial));
    eligible
        .pop()
        .map(|(_, _, serial, binding)| (binding, serial))
        .ok_or_else(|| "no active signed grant authorizes this peer and SSH key to renew".into())
}

fn sign_certificate(
    request: &SshRenewalRequest,
    binding: &RenewalBinding,
    serial: u64,
    now: u64,
    ca: &Path,
) -> Result<String, String> {
    let ca = ssh_key::PrivateKey::from_openssh(fs::read(ca).map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())?;
    let nonce = mycelium_peer_protocol::decode_hex(&request.signature)?;
    let mut builder = ssh_key::certificate::Builder::new(
        nonce,
        key_material(&request.public_key)?,
        now.saturating_sub(30),
        now.saturating_add(binding.credential_ttl),
    )
    .map_err(|e| e.to_string())?;
    builder.serial(serial).map_err(|e| e.to_string())?;
    builder
        .cert_type(ssh_key::certificate::CertType::User)
        .map_err(|e| e.to_string())?;
    builder
        .key_id(format!("mycelium:renew:{}", request.node_id))
        .map_err(|e| e.to_string())?;
    for role in &binding.roles {
        builder
            .valid_principal(format!("mycelium-role-{role}"))
            .map_err(|e| e.to_string())?;
        builder
            .valid_principal(mycelium_peer_protocol::ssh_role_principal(
                &binding.principal,
                role,
            ))
            .map_err(|e| e.to_string())?;
    }
    for extension in [
        "permit-X11-forwarding",
        "permit-agent-forwarding",
        "permit-port-forwarding",
        "permit-pty",
        "permit-user-rc",
    ] {
        builder
            .extension(extension, "")
            .map_err(|e| e.to_string())?;
    }
    builder
        .sign(&ca)
        .map_err(|e| e.to_string())?
        .to_openssh()
        .map_err(|e| e.to_string())
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
    if let Some(request) = pending(key, now)? {
        if request.public_key == material {
            return Ok(Some(request));
        }
    }
    let request_id = format!(
        "{}-{now}",
        &mycelium_peer_protocol::encode_hex(key.verifying_key().as_bytes())[..16]
    );
    let request = SshRenewalRequest::sign(request_id, now, material, key)?;
    atomic_write(
        &home.join("ssh/renewal-pending.json"),
        &serde_json::to_vec(&request).map_err(|e| e.to_string())?,
    )?;
    Ok(Some(request))
}

/// The request this node is still waiting on, if any.
///
/// A response is installed only when it answers this request, so a late
/// response to a superseded request cannot replace a newer certificate. The
/// window matches the issuer's five-minute acceptance window: past it the
/// request can no longer be answered and must be re-signed.
pub fn pending(
    key: &ed25519_dalek::SigningKey,
    now: u64,
) -> Result<Option<SshRenewalRequest>, String> {
    let path = crate::home_dir().join("ssh/renewal-pending.json");
    let Ok(bytes) = fs::read(&path) else {
        return Ok(None);
    };
    let request: SshRenewalRequest =
        serde_json::from_slice(&bytes).map_err(|e| format!("invalid pending renewal: {e}"))?;
    let node_id = mycelium_peer_protocol::encode_hex(key.verifying_key().as_bytes());
    if now < request.requested_at || now - request.requested_at >= 240 || request.node_id != node_id
    {
        return Ok(None);
    }
    request.verify()?;
    Ok(Some(request))
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
    let staged = directory.join("user-cert.renewal-staging.pub");
    fs::write(&staged, certificate)
        .map_err(|error| format!("stage renewed certificate: {error}"))?;
    let validation = validate_replacement(&installed, &staged, now, expires_at);
    if let Err(error) = validation {
        let _ = fs::remove_file(&staged);
        return Err(error);
    }
    fs::rename(&staged, &installed)
        .map_err(|error| format!("install renewed certificate: {error}"))?;
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

fn validate_replacement(
    installed: &Path,
    staged: &Path,
    now: u64,
    expires_at: u64,
) -> Result<(), String> {
    let old = ssh_key::Certificate::from_openssh(
        &fs::read_to_string(installed).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    old.verify_signature()
        .map_err(|e| format!("invalid existing CA pin: {e}"))?;
    let new =
        ssh_key::Certificate::from_openssh(&fs::read_to_string(staged).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;
    new.validate_at(
        now,
        [&old.signature_key().fingerprint(ssh_key::HashAlg::Sha256)],
    )
    .map_err(|e| format!("invalid renewed certificate signature/validity: {e}"))?;
    if new.public_key() != old.public_key()
        || new.cert_type() != ssh_key::certificate::CertType::User
        || new.valid_before() != expires_at
        || !new.critical_options().is_empty()
        || new.valid_principals().is_empty()
    {
        return Err("renewed certificate changed key/type, has unsupported options, empty principals or inconsistent expiry".into());
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
    fn fixture() -> (SshRenewalRequest, crate::peer::AccessStateView) {
        let peer = ed25519_dalek::SigningKey::from_bytes(&[9; 32]);
        let subject = ssh_key::PrivateKey::new(
            ssh_key::private::Ed25519Keypair::from_seed(&[11; 32]).into(),
            "test",
        )
        .unwrap();
        let request = SshRenewalRequest::sign(
            "request-1".into(),
            100,
            subject.public_key().to_openssh().unwrap(),
            &peer,
        )
        .unwrap();
        let grant = mycelium_peer_protocol::AccessRecord::sign(
            &ed25519_dalek::SigningKey::from_bytes(&[7; 32]),
            AccessStatement::Grant {
                grant_id: "test".into(),
                principal: "james".into(),
                serial: 42,
                roles: vec!["home-operator".into()],
                scopes: vec![scope(&request.node_id, 3600).unwrap()],
                unix_users: vec!["mames".into()],
                ssh_public_keys: vec![request.public_key.clone()],
                oidc_audiences: vec![],
                oidc_ssh_key_exchange: false,
                not_before: 50,
                not_after: 200,
            },
        )
        .unwrap();
        (
            request,
            crate::peer::AccessStateView {
                grants: vec![crate::peer::AccessGrantView {
                    record: grant,
                    active: false,
                    revoked_by: vec![],
                }],
                revocations: vec![],
            },
        )
    }
    #[test]
    fn signed_grant_binds_peer_key_roles_and_expiry() {
        let (request, state) = fixture();
        let (binding, serial) = grant_authorization(&request, &state, 100).unwrap();
        assert_eq!(binding.roles, vec!["home-operator"]);
        assert_eq!(binding.credential_ttl, 100);
        assert_eq!(serial, 42);
        assert!(grant_authorization(&request, &state, 200).is_err());
        let mut wrong = request.clone();
        wrong.node_id = "a".repeat(64);
        assert!(grant_authorization(&wrong, &state, 100).is_err());
        let mut wrong = request;
        wrong.public_key = ssh_key::PrivateKey::new(
            ssh_key::private::Ed25519Keypair::from_seed(&[12; 32]).into(),
            "test",
        )
        .unwrap()
        .public_key()
        .to_openssh()
        .unwrap();
        assert!(grant_authorization(&wrong, &state, 100).is_err());
    }
    #[test]
    fn revoked_grant_cannot_renew_even_if_flag_is_active() {
        let (request, mut state) = fixture();
        state.grants[0].active = true;
        state.revocations.push(
            mycelium_peer_protocol::AccessRecord::sign(
                &ed25519_dalek::SigningKey::from_bytes(&[7; 32]),
                AccessStatement::Revoke {
                    revocation_id: "rev".into(),
                    grant_id: Some("test".into()),
                    principal: None,
                    serial: None,
                    revoked_at: 105,
                    reason: "test".into(),
                },
            )
            .unwrap(),
        );
        assert!(grant_authorization(&request, &state, 100).is_ok());
        assert!(grant_authorization(&request, &state, 105).is_err());
    }
    #[test]
    fn missing_scope_or_tampering_denies_renewal() {
        let (request, mut state) = fixture();
        if let AccessStatement::Grant { scopes, .. } = &mut state.grants[0].record.statement {
            scopes.clear();
        }
        assert!(grant_authorization(&request, &state, 100).is_err());
        state.grants[0].record = mycelium_peer_protocol::AccessRecord::sign(
            &ed25519_dalek::SigningKey::from_bytes(&[7; 32]),
            state.grants[0].record.statement.clone(),
        )
        .unwrap();
        assert!(grant_authorization(&request, &state, 100).is_err());
    }
    #[test]
    fn native_certificate_is_ca_verified_serial_bound_and_grant_clamped() {
        let (request, state) = fixture();
        let directory = crate::test_dir("renewal-test");
        let ca = ssh_key::PrivateKey::new(
            ssh_key::private::Ed25519Keypair::from_seed(&[17; 32]).into(),
            "test CA",
        )
        .unwrap();
        let ca_path = directory.join("ca");
        fs::write(
            &ca_path,
            ca.to_openssh(ssh_key::LineEnding::LF).unwrap().as_bytes(),
        )
        .unwrap();
        let response = issue_inner(&request, 100, &ca_path, &state).unwrap();
        let certificate =
            ssh_key::Certificate::from_openssh(response.certificate.as_ref().unwrap()).unwrap();
        certificate
            .validate_at(
                100,
                [&ca.public_key().fingerprint(ssh_key::HashAlg::Sha256)],
            )
            .unwrap();
        assert_eq!(certificate.serial(), 42);
        assert_eq!(certificate.valid_before(), 200);
        assert_eq!(response.expires_at, Some(200));
        let old_path = directory.join("expired-cert");
        let new_path = directory.join("new-cert");
        let (binding, serial) = grant_authorization(&request, &state, 50).unwrap();
        let short = RenewalBinding {
            principal: binding.principal,
            roles: binding.roles,
            credential_ttl: 1,
        };
        fs::write(
            &old_path,
            sign_certificate(&request, &short, serial, 50, &ca_path).unwrap(),
        )
        .unwrap();
        fs::write(&new_path, response.certificate.unwrap()).unwrap();
        validate_replacement(&old_path, &new_path, 100, 200).unwrap(); // An expired login certificate may renew.
        assert!(validate_replacement(&old_path, &new_path, 100, 201).is_err());
        let wrong_ca = ssh_key::PrivateKey::new(
            ssh_key::private::Ed25519Keypair::from_seed(&[18; 32]).into(),
            "wrong CA",
        )
        .unwrap();
        fs::write(
            &ca_path,
            wrong_ca
                .to_openssh(ssh_key::LineEnding::LF)
                .unwrap()
                .as_bytes(),
        )
        .unwrap();
        fs::write(
            &new_path,
            issue_inner(&request, 100, &ca_path, &state)
                .unwrap()
                .certificate
                .unwrap(),
        )
        .unwrap();
        assert!(validate_replacement(&old_path, &new_path, 100, 200).is_err());
        fs::remove_dir_all(directory).unwrap();
    }
}
