//! Linux host enforcement. Gossip is an untrusted carrier: privileged decisions
//! are recomputed from signatures, root-owned trust configuration and local time.
//! No peer identity or daemon-provided `active` flag conveys grant authority.
use mycelium_peer_protocol::{AccessRecord, AccessStatement, AuthorityRecord};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::Path,
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Policy {
    version: u32,
    pub(crate) authority_roots: BTreeSet<String>,
    #[serde(default)]
    legacy_access_keys: BTreeSet<String>,
    #[serde(default)]
    pub(crate) legacy_release_keys: BTreeSet<String>,
    accepted_roles: BTreeSet<String>,
    #[serde(default)]
    sudo_roles: BTreeSet<String>,
    ca_public: String,
    /// PAM account checks only; authentication stacks/passwords remain intact.
    #[serde(default)]
    pam_services: BTreeSet<String>,
}

#[derive(Debug, Serialize)]
struct Plan {
    accounts: BTreeMap<String, BTreeSet<String>>,
    ssh_principals: BTreeMap<String, BTreeSet<String>>,
    sudo_users: BTreeSet<String>,
    managed_users: BTreeSet<String>,
    sudoers: String,
    pam_access: String,
}

fn atom(s: &str) -> Result<(), String> {
    if s.is_empty()
        || s.len() > 64
        || !s.as_bytes()[0].is_ascii_lowercase()
        || !s
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"_-".contains(&b))
        || s == "root"
    {
        return Err(format!("unsafe managed account/role `{s}`"));
    }
    Ok(())
}

fn validate(policy: &Policy) -> Result<(), String> {
    if policy.version != 1
        || policy.accepted_roles.is_empty()
        || (policy.authority_roots.is_empty() && policy.legacy_access_keys.is_empty())
        || !policy.sudo_roles.is_subset(&policy.accepted_roles)
    {
        return Err("host policy requires version 1, trusted issuers, accepted roles and sudo roles contained in accepted roles".into());
    }
    for value in policy.accepted_roles.iter().chain(&policy.sudo_roles) {
        atom(value)?;
    }
    if !Path::new(&policy.ca_public).is_absolute() {
        return Err("SSH CA public path must be absolute".into());
    }
    for key in policy
        .authority_roots
        .iter()
        .chain(&policy.legacy_access_keys)
        .chain(&policy.legacy_release_keys)
    {
        if key.len() != 64 || !key.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err("invalid public authority key".into());
        }
    }
    for service in &policy.pam_services {
        if !matches!(service.as_str(), "sshd" | "sudo") {
            return Err("PAM account enforcement supports sshd and sudo only".into());
        }
    }
    Ok(())
}

fn derive(
    policy: &Policy,
    access: &Value,
    authority: &Value,
    previous: BTreeSet<String>,
    now: u64,
) -> Result<(Plan, Value), String> {
    validate(policy)?;
    let authority_records: Vec<AuthorityRecord> = authority
        .as_array()
        .ok_or("authority snapshot must be an array")?
        .iter()
        .map(|v| {
            serde_json::from_value(v.clone()).map_err(|e| format!("decode authority record: {e}"))
        })
        .collect::<Result<_, _>>()?;
    let empty = BTreeSet::new();
    let resolver = myceliumd::authority::AuthorityResolver::new(
        &policy.authority_roots,
        &policy.legacy_access_keys,
        &empty,
        &authority_records,
        now,
    );
    let mut records = Vec::new();
    let mut retained_grants = Vec::new();
    let mut retained_revocations = Vec::new();
    for (field, wrapped) in [("grants", true), ("revocations", false)] {
        for value in access[field]
            .as_array()
            .ok_or("missing access snapshot records")?
        {
            let record: AccessRecord = serde_json::from_value(if wrapped {
                value["record"].clone()
            } else {
                value.clone()
            })
            .map_err(|e| format!("decode access record: {e}"))?;
            let authorized = resolver.access(&record.signer).authorized;
            if let Err(error) = record.verify() {
                if authorized {
                    return Err(format!("invalid trusted access signature: {error}"));
                }
                continue;
            }
            if wrapped {
                retained_grants.push(serde_json::json!({"record":record}));
            } else {
                retained_revocations.push(serde_json::json!(record));
            }
            if !authorized {
                continue;
            }
            records.push(record);
        }
    }
    if records.is_empty() && previous.is_empty() {
        return Err("no verified access evidence; refusing host changes".into());
    }
    let mut accounts = BTreeMap::<String, BTreeSet<String>>::new();
    let mut sudo_expiries = BTreeMap::<String, u64>::new();
    let mut ssh_principals = BTreeMap::<String, BTreeSet<String>>::new();
    let mut verified = Vec::new();
    let revocations: Vec<_> = records.iter().filter(|r| matches!(&r.statement, AccessStatement::Revoke {revoked_at, ..} if *revoked_at <= now)).collect();
    for record in &records {
        let AccessStatement::Grant {
            principal,
            roles,
            unix_users,
            not_before,
            not_after,
            ..
        } = &record.statement
        else {
            continue;
        };
        let active = *not_before <= now
            && now < *not_after
            && !revocations
                .iter()
                .any(|r| r.statement.revokes(&record.statement));
        let revoked_by: Vec<_> = revocations
            .iter()
            .filter(|r| r.statement.revokes(&record.statement))
            .collect();
        verified.push(
            serde_json::json!({"active": active, "record": record, "revoked_by": revoked_by}),
        );
        if !active {
            continue;
        }
        let roles: BTreeSet<_> = roles
            .iter()
            .filter(|r| policy.accepted_roles.contains(*r))
            .cloned()
            .collect();
        if roles.is_empty() {
            continue;
        }
        for user in unix_users {
            atom(user)?;
            accounts
                .entry(user.clone())
                .or_default()
                .extend(roles.clone());
            ssh_principals.entry(user.clone()).or_default().extend(
                roles
                    .iter()
                    .map(|role| mycelium_peer_protocol::ssh_role_principal(principal, role)),
            );
            if !roles.is_disjoint(&policy.sudo_roles) {
                let expiry = (*not_after).min(now.saturating_add(300));
                sudo_expiries
                    .entry(user.clone())
                    .and_modify(|at| *at = (*at).max(expiry))
                    .or_insert(expiry);
            }
        }
    }
    for user in &previous {
        atom(user)?;
    }
    let mut managed_users = previous;
    managed_users.extend(accounts.keys().cloned());
    let sudo_users: BTreeSet<_> = accounts
        .iter()
        .filter(|(_, roles)| !roles.is_disjoint(&policy.sudo_roles))
        .map(|(u, _)| u.clone())
        .collect();
    let mut sudoers =
        "# Managed by Mycelium from verified active grants; do not edit.\n".to_owned();
    for user in &sudo_users {
        let expiry = time::OffsetDateTime::from_unix_timestamp(
            i64::try_from(sudo_expiries[user]).map_err(|_| "sudo lease timestamp overflow")?,
        )
        .map_err(|e| e.to_string())?
        .format(time::macros::format_description!(
            "[year][month][day][hour][minute][second]Z"
        ))
        .map_err(|e| e.to_string())?;
        // Reuse the bounded-sudo lease design without a second policy loop.
        sudoers.push_str(&format!(
            "{user} ALL=(ALL:ALL) NOTAFTER={expiry} NOPASSWD: ALL\n"
        ));
    }
    let mut pam_access =
        "# Managed account authorization only; unmanaged accounts unchanged.\n".to_owned();
    for user in accounts.keys() {
        pam_access.push_str(&format!("+ : {user} : ALL\n"));
    }
    for user in &managed_users {
        pam_access.push_str(&format!("- : {user} : ALL\n"));
    }
    pam_access.push_str("+ : ALL : ALL\n");
    let sanitized = serde_json::json!({"grants": verified, "revocations": revocations,
        "_retained": {"grants": retained_grants, "revocations": retained_revocations}});
    Ok((
        Plan {
            accounts,
            ssh_principals,
            sudo_users,
            managed_users,
            sudoers,
            pam_access,
        },
        sanitized,
    ))
}

/// Reject user-owned binaries, policies and writable/symlinked path ancestors.
#[cfg(unix)]
pub(crate) fn protected(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt;
    if !path.is_absolute() {
        return Err("privileged paths must be absolute".into());
    }
    for ancestor in path.ancestors() {
        let meta = fs::symlink_metadata(ancestor)
            .map_err(|e| format!("inspect {}: {e}", ancestor.display()))?;
        if meta.file_type().is_symlink() || meta.uid() != 0 || meta.mode() & 0o022 != 0 {
            return Err(format!(
                "privileged path must be root-owned, non-writable and not symlinked: {}",
                ancestor.display()
            ));
        }
    }
    Ok(())
}

fn command(program: &str, args: &[&str]) -> Result<(), String> {
    let output = Command::new(program)
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .args(args)
        .output()
        .map_err(|e| e.to_string())?;
    if !output.status.success() {
        return Err(format!(
            "{program}: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    Ok(())
}

#[cfg(unix)]
pub(crate) fn install(path: &Path, bytes: &[u8], mode: u32) -> Result<(), String> {
    use std::io::Write;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    protected(path.parent().ok_or("missing destination parent")?)?;
    if path.exists() {
        protected(path)?;
    }
    let staged = path.with_extension(format!("mycelium-staging-{}", std::process::id()));
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&staged)
        .map_err(|e| e.to_string())?;
    let result = (|| {
        file.write_all(bytes).map_err(|e| e.to_string())?;
        file.sync_all().map_err(|e| e.to_string())?;
        fs::set_permissions(&staged, fs::Permissions::from_mode(mode))
            .map_err(|e| e.to_string())?;
        fs::rename(&staged, path).map_err(|e| e.to_string())
    })();
    if result.is_err() {
        let _ = fs::remove_file(staged);
    }
    result
}

pub fn run(args: &[String], access: &Value, authority: &Value) -> Result<Vec<String>, String> {
    let action = args.first().map(String::as_str).unwrap_or("");
    if !matches!(action, "plan" | "apply" | "install-timer") {
        return Err("access host needs plan or apply --policy ROOT-OWNED.json [--write]".into());
    }
    let path = args
        .windows(2)
        .find(|w| w[0] == "--policy")
        .map(|w| Path::new(&w[1]))
        .ok_or("missing --policy")?;
    protected(path)?;
    let policy: Policy = serde_json::from_slice(&fs::read(path).map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())?;
    validate(&policy)?;
    if action == "install-timer" {
        return install_timer(args, path);
    }
    let _lock = if action == "apply" && !args.iter().any(|a| a == "--dry-run") {
        if !args.iter().any(|a| a == "--write") {
            return Err("host apply requires --write".into());
        }
        if !cfg!(target_os = "linux") {
            return Err("host apply currently supports Linux only".into());
        }
        crate::ssh_access::require_root("host grant enforcement")?;
        protected(&std::env::current_exe().map_err(|e| e.to_string())?)?;
        protected(Path::new("/var/lib"))?;
        let base = Path::new("/var/lib/mycelium/access");
        fs::create_dir_all(base).map_err(|e| e.to_string())?;
        protected(base)?;
        let lock_path = base.join("reconcile.lock");
        if lock_path.exists() {
            protected(&lock_path)?;
        }
        let file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(lock_path)
            .map_err(|e| e.to_string())?;
        file.try_lock()
            .map_err(|e| format!("another host reconciliation holds the lock: {e}"))?;
        Some(file)
    } else {
        None
    };
    let state_path = Path::new("/var/lib/mycelium/access/managed-users.json");
    let previous = if state_path.exists() {
        protected(state_path)?;
        serde_json::from_slice(&fs::read(state_path).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?
    } else {
        BTreeSet::new()
    };
    // Retain evidence outside the daemon's writable home. A carrier cannot
    // resurrect a grant by omitting an already-observed signed revocation.
    let evidence_path = Path::new("/var/lib/mycelium/access/evidence.json");
    let mut retained_access = if access.is_null() {
        serde_json::json!({"grants":[],"revocations":[]})
    } else {
        access.clone()
    };
    let mut retained_authority = if authority.is_null() {
        serde_json::json!([])
    } else {
        authority.clone()
    };
    if !retained_access["grants"].is_array()
        || !retained_access["revocations"].is_array()
        || !retained_authority.is_array()
    {
        eprintln!("mycelium: malformed carrier snapshot; enforcing retained signed evidence only");
        retained_access = serde_json::json!({"grants":[],"revocations":[]});
        retained_authority = serde_json::json!([]);
    }
    let mut cached_evidence = None;
    if evidence_path.exists() {
        protected(evidence_path)?;
        let retained: Value =
            serde_json::from_slice(&fs::read(evidence_path).map_err(|e| e.to_string())?)
                .map_err(|e| e.to_string())?;
        cached_evidence = Some(retained.clone());
        for field in ["grants", "revocations"] {
            let entries = retained_access[field]
                .as_array_mut()
                .ok_or("invalid access snapshot")?;
            for item in retained["access"][field]
                .as_array()
                .ok_or("invalid retained access evidence")?
            {
                if !entries.contains(item) {
                    entries.push(item.clone());
                }
            }
        }
        let entries = retained_authority
            .as_array_mut()
            .ok_or("invalid authority snapshot")?;
        for item in retained["authority"]
            .as_array()
            .ok_or("invalid retained authority evidence")?
        {
            if !entries.contains(item) {
                entries.push(item.clone());
            }
        }
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| e.to_string())?
        .as_secs();
    let result = derive(
        &policy,
        &retained_access,
        &retained_authority,
        previous.clone(),
        now,
    );
    let (plan, verified) = match result {
        Ok(result) => result,
        Err(error) => {
            let Some(cached) = cached_evidence else {
                return Err(error);
            };
            eprintln!("mycelium: invalid fresh access evidence ({error}); enforcing root-retained signed evidence only");
            retained_authority = cached["authority"].clone();
            derive(
                &policy,
                &cached["access"],
                &retained_authority,
                previous,
                now,
            )?
        }
    };
    if action == "plan" || args.iter().any(|a| a == "--dry-run") {
        return Ok(vec![
            serde_json::to_string_pretty(&plan).map_err(|e| e.to_string())?
        ]);
    }
    if !args.iter().any(|a| a == "--write") {
        return Err("host apply requires --write".into());
    }
    if !cfg!(target_os = "linux") {
        return Err("host apply currently supports Linux only".into());
    }
    crate::ssh_access::require_root("host grant enforcement")?;
    protected(&std::env::current_exe().map_err(|e| e.to_string())?)?;
    protected(Path::new(&policy.ca_public))?;
    let base = Path::new("/var/lib/mycelium/access");
    protected(Path::new("/var/lib"))?;
    fs::create_dir_all(base).map_err(|e| e.to_string())?;
    protected(base)?;
    let staged_sudo = base.join("sudoers-candidate");
    install(&staged_sudo, plan.sudoers.as_bytes(), 0o440)?;
    command(
        "visudo",
        &["-cf", staged_sudo.to_str().ok_or("non-UTF8 path")?],
    )?;
    for user in plan.accounts.keys() {
        let output = Command::new("id")
            .args(["-u", user])
            .output()
            .map_err(|e| e.to_string())?;
        if output.status.success() && String::from_utf8_lossy(&output.stdout).trim() == "0" {
            return Err(format!("refusing to manage UID 0 alias {user}"));
        }
    }
    // Preflight every PAM stack before changing accounts or SSH policy.
    let old_marker = "account required pam_access.so accessfile=/etc/security/mycelium-access.conf";
    let bootstrap = Path::new("/usr/local/libexec/mycelium-access/mycelium");
    if !policy.pam_services.is_empty() {
        protected(bootstrap)?;
    }
    if !path
        .to_string_lossy()
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b"/_-.".contains(&b))
    {
        return Err("PAM policy path must be a safe absolute path atom".into());
    }
    let marker = format!(
        "account required pam_exec.so quiet seteuid {} access host pam-check --policy {}",
        bootstrap.display(),
        path.display()
    );
    let mut pam = Vec::new();
    for service in &policy.pam_services {
        let module_present = [
            "/usr/lib/security/pam_exec.so",
            "/usr/lib/x86_64-linux-gnu/security/pam_exec.so",
            "/usr/lib/aarch64-linux-gnu/security/pam_exec.so",
            "/lib/security/pam_exec.so",
        ]
        .iter()
        .any(|p| Path::new(p).is_file());
        if !module_present {
            return Err("pam_exec.so unavailable; no host changes made".into());
        }
        let path = format!("/etc/pam.d/{service}");
        protected(Path::new(&path))?;
        let old = fs::read_to_string(&path).map_err(|e| e.to_string())?;
        let backup = format!("{path}.mycelium-pre");
        if !Path::new(&backup).exists() {
            install(Path::new(&backup), old.as_bytes(), 0o600)?;
        }
        let preserved=old.lines().filter(|l|*l != old_marker && !l.starts_with("account required pam_exec.so quiet seteuid /usr/local/libexec/mycelium-access/mycelium access host pam-check --policy ")).collect::<Vec<_>>().join("\n");
        let new = format!("{marker}\n{preserved}\n");
        pam.push((path, new));
    }
    install(
        evidence_path,
        &serde_json::to_vec(
            &serde_json::json!({"access": verified["_retained"], "authority": retained_authority}),
        )
        .map_err(|e| e.to_string())?,
        0o600,
    )?;
    // Record ownership before any created accounts, so subsequent expiry denies
    // them even when an interrupted apply left only a partial installation.
    install(
        state_path,
        &serde_json::to_vec(&plan.managed_users).map_err(|e| e.to_string())?,
        0o600,
    )?;
    install(
        Path::new("/etc/security/mycelium-access.conf"),
        plan.pam_access.as_bytes(),
        0o644,
    )?;
    install(
        Path::new("/etc/sudoers.d/mycelium-grants"),
        plan.sudoers.as_bytes(),
        0o440,
    )?;
    for (path, content) in pam {
        install(Path::new(&path), content.as_bytes(), 0o644)?;
    }
    let bundle = base.join(format!("ssh-bundle-{}-{now}", std::process::id()));
    let krl = base.join("revoked.krl");
    let krl_args = vec![
        "krl".into(),
        "--ca-public".into(),
        policy.ca_public.clone(),
        "--path".into(),
        krl.display().to_string(),
        "--write".into(),
    ];
    crate::ssh_access::run(&krl_args, &verified)?;
    let mut bundle_args = vec![
        "host-bundle".into(),
        "--ca-public".into(),
        policy.ca_public,
        "--krl".into(),
        krl.display().to_string(),
        "--path".into(),
        bundle.display().to_string(),
        "--write".into(),
        "--allow-empty".into(),
    ];
    for (user, roles) in &plan.accounts {
        for role in roles {
            bundle_args.extend(["--allow".into(), format!("{user}={role}")]);
        }
    }
    crate::ssh_access::run(&bundle_args, &verified)?;
    // The legacy --allow interface knows roles but not human identity. Replace
    // its generated principal text with the independently verified grant map.
    for (user, principals) in &plan.ssh_principals {
        let contents = principals
            .iter()
            .map(|p| format!("{p}\n"))
            .collect::<String>();
        install(
            &bundle.join("principals").join(user),
            contents.as_bytes(),
            0o644,
        )?;
    }
    if !crate::ssh_access::host_bundle_matches_installed(&bundle)? {
        crate::ssh_access::run(
            &[
                "host-apply".into(),
                "--bundle".into(),
                bundle.display().to_string(),
                "--write".into(),
            ],
            &verified,
        )?;
    }
    fs::remove_dir_all(&bundle).map_err(|e| format!("remove generated host bundle: {e}"))?;
    command("visudo", &["-c"])?;
    Ok(vec![format!("verified grants applied: {} accounts, {} sudo users; PAM account policy updated (no passwords changed)", plan.accounts.len(), plan.sudo_users.len())])
}

/// PAM account evaluation is offline and rechecks expiry at login/sudo time.
/// It never contacts the user daemon and never consumes its `active` flags.
pub(crate) fn pam_check(args: &[String]) -> Result<Vec<String>, String> {
    crate::ssh_access::require_root("PAM grant evaluation")?;
    if std::env::var("PAM_TYPE").as_deref() != Ok("account") {
        return Err("PAM grant check requires account context".into());
    }
    let user = std::env::var("PAM_USER").map_err(|_| "missing PAM_USER")?;
    let service = std::env::var("PAM_SERVICE").map_err(|_| "missing PAM_SERVICE")?;
    let path = args
        .windows(2)
        .find(|w| w[0] == "--policy")
        .map(|w| Path::new(&w[1]))
        .ok_or("missing --policy")?;
    protected(path)?;
    let policy: Policy = serde_json::from_slice(&fs::read(path).map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())?;
    validate(&policy)?;
    if !policy.pam_services.contains(&service) {
        return Err("PAM service is not admitted by root policy".into());
    }
    let managed = Path::new("/var/lib/mycelium/access/managed-users.json");
    protected(managed)?;
    let users: BTreeSet<String> =
        serde_json::from_slice(&fs::read(managed).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;
    if !users.contains(&user) {
        return Ok(vec![]);
    } // unmanaged local-owner/recovery accounts unchanged
    let evidence = Path::new("/var/lib/mycelium/access/evidence.json");
    protected(evidence)?;
    let value: Value = serde_json::from_slice(&fs::read(evidence).map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())?;
    let at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| e.to_string())?
        .as_secs();
    let (plan, _) = derive(&policy, &value["access"], &value["authority"], users, at)?;
    if !plan.accounts.contains_key(&user) {
        return Err("managed account has no active, non-revoked signed grant".into());
    }
    Ok(vec![])
}

fn install_timer(args: &[String], policy: &Path) -> Result<Vec<String>, String> {
    if !cfg!(target_os = "linux") {
        return Err("host access timer requires Linux".into());
    }
    crate::ssh_access::require_root("host access timer")?;
    if !args.iter().any(|a| a == "--write") {
        return Err("timer installation requires --write".into());
    }
    let binary = std::env::current_exe().map_err(|e| e.to_string())?;
    protected(&binary)?;
    let home = args
        .windows(2)
        .find(|w| w[0] == "--daemon-home")
        .map(|w| w[1].as_str())
        .ok_or("missing --daemon-home")?;
    for path in [
        binary.to_str().ok_or("invalid binary path")?,
        policy.to_str().ok_or("invalid policy path")?,
        home,
    ] {
        if !path.starts_with('/')
            || !path
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"/_-.".contains(&b))
        {
            return Err("systemd paths must be absolute safe path atoms".into());
        }
    }
    let update_path = args
        .windows(2)
        .find(|w| w[0] == "--updates")
        .map(|w| Path::new(&w[1]));
    let action = if let Some(updates) = update_path {
        protected(updates)?;
        let text = updates.to_str().ok_or("invalid update policy path")?;
        if !text
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"/_-.".contains(&b))
        {
            return Err("unsafe systemd update path".into());
        }
        format!(
            "supervise --policy {} --updates {} --write",
            policy.display(),
            updates.display()
        )
    } else {
        format!("apply --policy {} --write", policy.display())
    };
    let service = format!("[Unit]\nDescription=Reconcile verified Mycelium host grants\n[Service]\nType=oneshot\nEnvironment=PATH=/usr/sbin:/usr/bin:/sbin:/bin\nEnvironment=MYCELIUM_HOME={home}\nEnvironment=MYCELIUM_NO_AUTOSTART=1\nExecStart={} access host {action}\n",binary.display());
    let timer = "[Unit]\nDescription=Refresh Mycelium account, sudo and PAM grants\n[Timer]\nOnActiveSec=30s\nOnUnitActiveSec=2m\nAccuracySec=5s\n[Install]\nWantedBy=timers.target\n";
    install(
        Path::new("/etc/systemd/system/mycelium-host-access.service"),
        service.as_bytes(),
        0o644,
    )?;
    install(
        Path::new("/etc/systemd/system/mycelium-host-access.timer"),
        timer.as_bytes(),
        0o644,
    )?;
    command("systemctl", &["daemon-reload"])?;
    command(
        "systemctl",
        &["enable", "--now", "mycelium-host-access.timer"],
    )?;
    Ok(vec!["installed root-owned two-minute host access reconciliation; cached signed grants expire even when gossip is unavailable".into()])
}

#[cfg(test)]
mod tests {
    use super::*;
    fn policy() -> Policy {
        Policy {
            version: 1,
            authority_roots: BTreeSet::new(),
            legacy_access_keys: BTreeSet::from(["a".repeat(64)]),
            legacy_release_keys: BTreeSet::new(),
            accepted_roles: BTreeSet::from(["operator".into()]),
            sudo_roles: BTreeSet::new(),
            ca_public: "/etc/ssh/ca.pub".into(),
            pam_services: BTreeSet::new(),
        }
    }
    #[test]
    fn unsafe_accounts_rejected() {
        for s in ["root", "-o", "james ALL=ALL", "a\nroot", ""] {
            assert!(atom(s).is_err());
        }
        assert!(atom("mames").is_ok());
    }
    #[test]
    fn privileged_paths_reject_writable_files() {
        use std::os::unix::fs::PermissionsExt;
        let path = std::env::temp_dir().join(format!(
            "mycelium-host-access-writable-{}",
            std::process::id()
        ));
        let file = fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&path)
            .unwrap();
        file.set_permissions(fs::Permissions::from_mode(0o666))
            .unwrap();
        assert!(protected(&path).is_err());
        drop(file);
        fs::remove_file(path).unwrap();
    }
    #[test]
    fn sudo_requires_host_accepted_role() {
        let mut p = policy();
        p.sudo_roles.insert("admin".into());
        assert!(validate(&p).is_err());
    }
    #[test]
    fn peer_membership_cannot_grant_access() {
        let state = serde_json::json!({"grants":[], "revocations":[]});
        assert!(derive(
            &policy(),
            &state,
            &serde_json::json!([]),
            BTreeSet::new(),
            10
        )
        .is_err());
    }
    #[test]
    fn pam_does_not_replace_authentication() {
        let mut p = policy();
        p.pam_services.insert("common-auth".into());
        assert!(validate(&p).is_err());
    }
    fn signed_fixture() -> (Policy, AccessRecord) {
        let key = ed25519_dalek::SigningKey::from_bytes(&[7; 32]);
        let record = AccessRecord::sign(
            &key,
            AccessStatement::Grant {
                grant_id: "test".into(),
                principal: "james".into(),
                serial: 1,
                roles: vec!["operator".into()],
                scopes: vec![],
                unix_users: vec!["mames".into()],
                ssh_public_keys: vec![],
                oidc_audiences: vec![],
                oidc_ssh_key_exchange: false,
                not_before: 10,
                not_after: 20,
            },
        )
        .unwrap();
        let mut p = policy();
        p.legacy_access_keys = BTreeSet::from([record.signer.clone()]);
        p.sudo_roles.insert("operator".into());
        (p, record)
    }
    fn snapshot(record: &AccessRecord, active: bool, revocations: Vec<AccessRecord>) -> Value {
        serde_json::json!({"grants":[{"active":active,"record":record}],"revocations":revocations})
    }
    #[test]
    fn active_flags_are_not_authority() {
        let (p, r) = signed_fixture();
        let (plan, _) = derive(
            &p,
            &snapshot(&r, false, vec![]),
            &serde_json::json!([]),
            BTreeSet::new(),
            15,
        )
        .unwrap();
        assert!(plan.sudo_users.contains("mames"));
        let (expired, _) = derive(
            &p,
            &snapshot(&r, true, vec![]),
            &serde_json::json!([]),
            plan.managed_users,
            20,
        )
        .unwrap();
        assert!(expired.sudo_users.is_empty());
        assert!(expired.pam_access.contains("- : mames : ALL"));
        assert!(!expired.pam_access.contains("+ : mames : ALL"));
    }
    #[test]
    fn tampering_and_untrusted_signers_cannot_grant_sudo() {
        let (p, mut r) = signed_fixture();
        if let AccessStatement::Grant { unix_users, .. } = &mut r.statement {
            unix_users.push("ajmwagar".into());
        }
        assert!(derive(
            &p,
            &snapshot(&r, true, vec![]),
            &serde_json::json!([]),
            BTreeSet::new(),
            15
        )
        .is_err());
        assert!(derive(
            &policy(),
            &snapshot(&r, true, vec![]),
            &serde_json::json!([]),
            BTreeSet::new(),
            15
        )
        .is_err());
    }
    #[test]
    fn revocation_wins_and_future_revocation_waits() {
        let (p, r) = signed_fixture();
        let key = ed25519_dalek::SigningKey::from_bytes(&[7; 32]);
        let revoke = AccessRecord::sign(
            &key,
            AccessStatement::Revoke {
                revocation_id: "rev".into(),
                grant_id: Some("test".into()),
                principal: None,
                serial: None,
                revoked_at: 16,
                reason: "test".into(),
            },
        )
        .unwrap();
        for (now, allowed) in [(15, true), (16, false)] {
            let (plan, _) = derive(
                &p,
                &snapshot(&r, true, vec![revoke.clone()]),
                &serde_json::json!([]),
                BTreeSet::new(),
                now,
            )
            .unwrap();
            assert_eq!(plan.sudo_users.contains("mames"), allowed);
        }
    }
    #[test]
    fn removing_issuer_revokes_previously_managed_users() {
        let (_, r) = signed_fixture();
        let (plan, _) = derive(
            &policy(),
            &snapshot(&r, true, vec![]),
            &serde_json::json!([]),
            BTreeSet::from(["mames".into()]),
            15,
        )
        .unwrap();
        assert!(plan.sudo_users.is_empty());
        assert!(plan.pam_access.contains("- : mames : ALL"));
    }
    #[test]
    fn issuer_reauthorization_uses_retained_signed_evidence() {
        let (p, r) = signed_fixture();
        let (denied, retained) = derive(
            &policy(),
            &snapshot(&r, true, vec![]),
            &serde_json::json!([]),
            BTreeSet::from(["mames".into()]),
            15,
        )
        .unwrap();
        assert!(denied.sudo_users.is_empty());
        let (restored, _) = derive(
            &p,
            &retained["_retained"],
            &serde_json::json!([]),
            denied.managed_users,
            16,
        )
        .unwrap();
        assert!(restored.sudo_users.contains("mames"));
    }
    #[test]
    fn retained_revocation_prevents_carrier_resurrection() {
        let (p, r) = signed_fixture();
        let key = ed25519_dalek::SigningKey::from_bytes(&[7; 32]);
        let revoke = AccessRecord::sign(
            &key,
            AccessStatement::Revoke {
                revocation_id: "rev".into(),
                grant_id: Some("test".into()),
                principal: None,
                serial: None,
                revoked_at: 15,
                reason: "test".into(),
            },
        )
        .unwrap();
        let (plan, retained) = derive(
            &p,
            &snapshot(&r, true, vec![revoke]),
            &serde_json::json!([]),
            BTreeSet::from(["mames".into()]),
            16,
        )
        .unwrap();
        assert!(plan.accounts.is_empty());
        let (offline, _) = derive(
            &p,
            &retained,
            &serde_json::json!([]),
            plan.managed_users,
            17,
        )
        .unwrap();
        assert!(offline.sudo_users.is_empty());
        assert!(offline.pam_access.contains("- : mames : ALL"));
    }
    #[test]
    fn same_role_does_not_authorize_another_persons_account() {
        let (p, r) = signed_fixture();
        let key = ed25519_dalek::SigningKey::from_bytes(&[7; 32]);
        let mut statement = r.statement.clone();
        if let AccessStatement::Grant {
            grant_id,
            principal,
            unix_users,
            ..
        } = &mut statement
        {
            *grant_id = "sam".into();
            *principal = "sam".into();
            *unix_users = vec!["sam".into()];
        }
        let sam = AccessRecord::sign(&key, statement).unwrap();
        let mut state = snapshot(&r, true, vec![]);
        state["grants"]
            .as_array_mut()
            .unwrap()
            .push(serde_json::json!({"active":true,"record":sam}));
        let (plan, _) = derive(&p, &state, &serde_json::json!([]), BTreeSet::new(), 15).unwrap();
        let sam_certificate = BTreeSet::from([
            "mycelium-role-operator".to_owned(),
            mycelium_peer_protocol::ssh_role_principal("sam", "operator"),
        ]);
        assert!(plan.ssh_principals["mames"].is_disjoint(&sam_certificate));
        assert!(!plan.ssh_principals["sam"].is_disjoint(&sam_certificate));
    }
    #[test]
    fn sudo_lease_is_grant_clamped_and_bounded_when_timer_stops() {
        let (p, mut r) = signed_fixture();
        let (plan, _) = derive(
            &p,
            &snapshot(&r, true, vec![]),
            &serde_json::json!([]),
            BTreeSet::new(),
            15,
        )
        .unwrap();
        assert!(plan.sudoers.contains("NOTAFTER=19700101000020Z"));
        if let AccessStatement::Grant { not_after, .. } = &mut r.statement {
            *not_after = 86400;
        }
        r = AccessRecord::sign(
            &ed25519_dalek::SigningKey::from_bytes(&[7; 32]),
            r.statement,
        )
        .unwrap();
        let (plan, _) = derive(
            &p,
            &snapshot(&r, true, vec![]),
            &serde_json::json!([]),
            BTreeSet::new(),
            15,
        )
        .unwrap();
        assert!(plan.sudoers.contains("NOTAFTER=19700101000515Z"));
    }
}
