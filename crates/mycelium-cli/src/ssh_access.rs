use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use mycelium_peer_protocol::{AccessRecord, AccessStatement};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct HostAccountIntent {
    name: String,
    state: String,
    password_locked: bool,
    supplementary_groups: Vec<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct HostBundleManifest {
    version: u32,
    #[serde(default)]
    accounts: Vec<HostAccountIntent>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct SshClientProfile {
    pub version: u32,
    pub principal: String,
    pub default_unix_user: String,
    #[serde(default)]
    pub unix_users: Vec<String>,
    #[serde(default)]
    pub roles: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct SshHostPolicy {
    version: u32,
    accepted_roles: Vec<String>,
    ca_public: PathBuf,
}

pub fn run(args: &[String], state: &Value) -> Result<Vec<String>, String> {
    match args.first().map(String::as_str) {
        Some("ca-init") => ca_init(args),
        Some("issue") => issue(args, state),
        Some("krl") => krl(args, state),
        Some("host-bundle") => host_bundle(args, state),
        Some("host-apply") => host_apply(args),
        Some("host-rollout") => host_rollout(args),
        Some("renewal-authorize") => Err("renewal-authorize must publish a signed access grant through the CLI dispatcher".into()),
        Some("client-config") => client_config(args),
        Some("profile") => profile(args),
        Some("host-policy") => host_policy(args, state),
        Some("directory") => directory(args, state),
        Some(action) => Err(format!("unknown access ssh action `{action}`")),
        None => Err(
            "access ssh needs ca-init, issue, krl, host-bundle, host-apply, host-rollout, directory, or client-config"
                .into(),
        ),
    }
}

fn host_policy_path() -> PathBuf {
    myceliumd::home_dir().join("ssh/host-policy.json")
}

fn host_policy(args: &[String], state: &Value) -> Result<Vec<String>, String> {
    match args.get(1).map(String::as_str) {
        Some("set") => host_policy_set(args),
        Some("status") => {
            let policy = load_host_policy()?;
            let mappings = mappings_for_roles(&policy.accepted_roles, state)?;
            Ok(vec![serde_json::to_string_pretty(&serde_json::json!({
                "policy": policy,
                "access_view_ready": access_view_has_evidence(state),
                "resolved_accounts": mappings,
            }))
            .map_err(|error| error.to_string())?])
        }
        Some("reconcile") => host_policy_reconcile(args, state),
        Some("install-timer") => host_policy_install_timer(args),
        _ => Err("access ssh host-policy needs set, status, reconcile, or install-timer".into()),
    }
}

fn host_policy_set(args: &[String]) -> Result<Vec<String>, String> {
    require_write(args)?;
    let mut accepted_roles = repeated(args, "--role")
        .into_iter()
        .map(str::to_owned)
        .collect::<Vec<_>>();
    accepted_roles.sort();
    accepted_roles.dedup();
    let policy = SshHostPolicy {
        version: 1,
        accepted_roles,
        ca_public: PathBuf::from(required(args, "--ca-public")?),
    };
    validate_host_policy(&policy)?;
    let path = host_policy_path();
    fs::create_dir_all(path.parent().expect("host policy has parent"))
        .map_err(|error| format!("create host-policy directory: {error}"))?;
    let staging = path.with_extension("json.staging");
    fs::write(
        &staging,
        serde_json::to_vec_pretty(&policy).map_err(|error| error.to_string())?,
    )
    .map_err(|error| format!("write staged host policy: {error}"))?;
    fs::rename(&staging, &path)
        .map_err(|error| format!("install host policy {}: {error}", path.display()))?;
    Ok(vec![format!(
        "host accepts gossiped SSH roles [{}]",
        policy.accepted_roles.join(", ")
    )])
}

fn load_host_policy() -> Result<SshHostPolicy, String> {
    let path = host_policy_path();
    let policy: SshHostPolicy = serde_json::from_slice(
        &fs::read(&path)
            .map_err(|error| format!("read host policy {}: {error}", path.display()))?,
    )
    .map_err(|error| format!("parse host policy {}: {error}", path.display()))?;
    validate_host_policy(&policy)?;
    Ok(policy)
}

fn validate_host_policy(policy: &SshHostPolicy) -> Result<(), String> {
    if policy.version != 1 || policy.accepted_roles.is_empty() || policy.accepted_roles.len() > 32 {
        return Err("SSH host policy needs version 1 and 1-32 accepted roles".into());
    }
    for role in &policy.accepted_roles {
        config_atom_value("role", role)?;
    }
    if !policy.ca_public.is_absolute() || !policy.ca_public.is_file() {
        return Err(format!(
            "SSH host policy CA public key is unavailable: {}",
            policy.ca_public.display()
        ));
    }
    Ok(())
}

fn mappings_for_roles(
    roles: &[String],
    state: &Value,
) -> Result<BTreeMap<String, BTreeSet<String>>, String> {
    let mut args = vec!["--from-access".to_owned(), "--allow-empty".to_owned()];
    for role in roles {
        args.extend(["--role".to_owned(), role.clone()]);
    }
    role_mappings(&args, state)
}

fn access_view_has_evidence(state: &Value) -> bool {
    ["grants", "revocations"].into_iter().any(|field| {
        state[field]
            .as_array()
            .is_some_and(|records| !records.is_empty())
    })
}

fn host_policy_reconcile(args: &[String], state: &Value) -> Result<Vec<String>, String> {
    let policy = load_host_policy()?;
    if !access_view_has_evidence(state) {
        return Err(
            "no gossiped access records have converged; refusing to replace SSH policy".into(),
        );
    }
    let mappings = mappings_for_roles(&policy.accepted_roles, state)?;
    if args.iter().any(|argument| argument == "--dry-run") {
        return Ok(vec![serde_json::to_string_pretty(&serde_json::json!({
            "dry_run": true,
            "accepted_roles": policy.accepted_roles,
            "resolved_accounts": mappings,
        }))
        .map_err(|error| error.to_string())?]);
    }
    require_write(args)?;
    require_root("SSH host-policy reconciliation")?;
    let root = myceliumd::home_dir().join(format!(
        "ssh/reconcile-staging-{}-{}",
        std::process::id(),
        now()?
    ));
    let bundle = root.join("bundle");
    let krl_path = root.join("revoked.krl");
    fs::create_dir_all(&root).map_err(|error| format!("create reconcile staging: {error}"))?;
    let result = (|| {
        krl(
            &[
                "--ca-public".to_owned(),
                policy.ca_public.to_string_lossy().into_owned(),
                "--path".to_owned(),
                krl_path.to_string_lossy().into_owned(),
                "--write".to_owned(),
            ],
            state,
        )?;
        let mut bundle_args = vec![
            "--ca-public".to_owned(),
            policy.ca_public.to_string_lossy().into_owned(),
            "--krl".to_owned(),
            krl_path.to_string_lossy().into_owned(),
            "--path".to_owned(),
            bundle.to_string_lossy().into_owned(),
            "--write".to_owned(),
            "--allow-empty".to_owned(),
        ];
        for (user, roles) in &mappings {
            for role in roles {
                bundle_args.extend(["--allow".into(), format!("{user}={role}")]);
            }
        }
        host_bundle(&bundle_args, state)?;
        if host_bundle_matches_installed(&bundle)? {
            return Ok(vec!["SSH host policy already converged".into()]);
        }
        host_apply(&[
            "--bundle".into(),
            bundle.to_string_lossy().into_owned(),
            "--write".into(),
        ])
    })();
    let _ = fs::remove_dir_all(&root);
    result
}

pub(crate) fn require_root(action: &str) -> Result<(), String> {
    let output = Command::new("/usr/bin/id")
        .arg("-u")
        .output()
        .map_err(|error| format!("determine effective user: {error}"))?;
    if output.status.success() && String::from_utf8_lossy(&output.stdout).trim() == "0" {
        Ok(())
    } else {
        Err(format!("{action} needs root"))
    }
}

pub(crate) fn host_bundle_matches_installed(bundle: &Path) -> Result<bool, String> {
    let installed = Path::new("/etc/ssh");
    if !public_policy_directory_matches(&installed.join("mycelium"))
        || !public_policy_directory_matches(&installed.join("mycelium/principals"))
    {
        return Ok(false);
    }
    for (desired, current) in [
        (
            bundle.join("user_ca.pub"),
            installed.join("mycelium/user_ca.pub"),
        ),
        (
            bundle.join("60-mycelium-access.conf"),
            installed.join("sshd_config.d/60-mycelium-access.conf"),
        ),
    ] {
        if fs::read(desired).ok() != fs::read(current).ok() {
            return Ok(false);
        }
    }
    if !krl_files_match(
        &bundle.join("revoked.krl"),
        &installed.join("mycelium/revoked.krl"),
    )? {
        return Ok(false);
    }
    let manifest = load_host_manifest(bundle)?;
    for account in &manifest.accounts {
        if !Command::new("id")
            .args(["-u", &account.name])
            .status()
            .map_err(|error| format!("look up account {}: {error}", account.name))?
            .success()
            || fs::read(bundle.join("principals").join(&account.name)).ok()
                != fs::read(installed.join("mycelium/principals").join(&account.name)).ok()
        {
            return Ok(false);
        }
    }
    let expected = manifest
        .accounts
        .iter()
        .map(|account| account.name.as_str())
        .collect::<BTreeSet<_>>();
    let current = fs::read_dir(installed.join("mycelium/principals"))
        .map(|entries| {
            entries
                .filter_map(|entry| entry.ok())
                .filter_map(|entry| entry.file_name().into_string().ok())
                .collect::<BTreeSet<_>>()
        })
        .unwrap_or_default();
    Ok(current.iter().map(String::as_str).collect::<BTreeSet<_>>() == expected)
}

fn krl_files_match(desired: &Path, current: &Path) -> Result<bool, String> {
    let desired_bytes = fs::read(desired)
        .map_err(|error| format!("read desired KRL {}: {error}", desired.display()))?;
    let current_bytes = match fs::read(current) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(format!("read installed KRL {}: {error}", current.display())),
    };
    if !krl_bytes_match(&desired_bytes, &current_bytes) {
        return Ok(false);
    }
    // Let OpenSSH validate the complete format, including sections/extensions.
    // Invalid installed data must be repaired, never treated as converged.
    for path in [desired, current] {
        let output = Command::new("ssh-keygen")
            .args(["-Q", "-l", "-f"])
            .arg(path)
            .output()
            .map_err(|error| format!("validate KRL {}: {error}", path.display()))?;
        if !output.status.success() {
            return Ok(false);
        }
    }
    Ok(true)
}

fn krl_bytes_match(desired: &[u8], current: &[u8]) -> bool {
    // OpenSSH PROTOCOL.krl v1: magic(8), format(4), version(8),
    // generated_date(8), flags(8), reserved/string, comment/string.
    // Only generated_date is incidental. Keep every other byte significant;
    // CA binding, revocations, version, flags and comments must still match.
    // https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.krl
    const HEADER: &[u8] = b"SSHKRL\n\0\0\0\0\x01";
    desired.len() >= 44
        && current.len() >= 44
        && desired.starts_with(HEADER)
        && current.starts_with(HEADER)
        && desired[..20] == current[..20]
        && desired[28..] == current[28..]
}

// Start relative to timer activation, not machine boot: installation/re-enabling
// can happen long after boot, with no retained oneshot activation timestamp.
const SSH_POLICY_TIMER: &str = "[Unit]\nDescription=Periodically reconcile Mycelium SSH access policy\n\n[Timer]\nOnActiveSec=2m\nOnUnitActiveSec=2m\nRandomizedDelaySec=30s\n\n[Install]\nWantedBy=timers.target\n";

fn host_policy_install_timer(args: &[String]) -> Result<Vec<String>, String> {
    require_write(args)?;
    require_root("SSH host-policy timer installation")?;
    if !cfg!(target_os = "linux") {
        return Err(
            "automatic SSH host-policy reconciliation currently supports Linux only".into(),
        );
    }
    load_host_policy()?;
    let binary = std::env::current_exe().map_err(|error| format!("locate Mycelium: {error}"))?;
    let home = myceliumd::home_dir();
    // Legacy SSH-only timers must not execute user-owned code as root or
    // trust user-writable policy/state. User-daemon installations should use
    // access host install-timer, which independently verifies signed evidence.
    for path in [&binary, &home, &host_policy_path()] {
        crate::host_access::protected(path).map_err(|error| format!(
            "unsafe legacy SSH timer: {error}; use access host install-timer with root-owned policy instead"
        ))?;
    }
    for path in [&binary, &home] {
        config_value_text("systemd path", &path.to_string_lossy())?;
    }
    let unit = format!(
        "[Unit]\nDescription=Reconcile Mycelium SSH access policy\nAfter=network-online.target\n\n[Service]\nType=oneshot\nEnvironment=MYCELIUM_HOME={}\nEnvironment=MYCELIUM_NO_AUTOSTART=1\nExecStart={} access ssh host-policy reconcile --write\n",
        home.display(), binary.display()
    );
    fs::write("/etc/systemd/system/mycelium-ssh-policy.service", unit)
        .map_err(|error| format!("write SSH policy service: {error}"))?;
    fs::write(
        "/etc/systemd/system/mycelium-ssh-policy.timer",
        SSH_POLICY_TIMER,
    )
    .map_err(|error| format!("write SSH policy timer: {error}"))?;
    command("systemctl", &["daemon-reload"])?;
    command(
        "systemctl",
        &["enable", "--now", "mycelium-ssh-policy.timer"],
    )?;
    command("systemctl", &["restart", "mycelium-ssh-policy.timer"])?;
    Ok(vec![
        "installed two-minute gossiped SSH policy reconciliation timer".into(),
    ])
}

fn profile_path() -> PathBuf {
    myceliumd::home_dir().join("ssh/profile.json")
}

pub(crate) fn preferred_unix_user() -> Result<Option<String>, String> {
    let path = profile_path();
    match fs::read(&path) {
        Ok(bytes) => {
            let profile: SshClientProfile = serde_json::from_slice(&bytes)
                .map_err(|error| format!("parse SSH profile {}: {error}", path.display()))?;
            validate_profile(&profile)?;
            Ok(Some(profile.default_unix_user))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(format!("read SSH profile {}: {error}", path.display())),
    }
}

fn profile(args: &[String]) -> Result<Vec<String>, String> {
    match args.get(1).map(String::as_str) {
        Some("show") => {
            let path = profile_path();
            let bytes = fs::read(&path)
                .map_err(|error| format!("read SSH profile {}: {error}", path.display()))?;
            let profile: SshClientProfile = serde_json::from_slice(&bytes)
                .map_err(|error| format!("parse SSH profile {}: {error}", path.display()))?;
            validate_profile(&profile)?;
            Ok(vec![
                serde_json::to_string_pretty(&profile).map_err(|e| e.to_string())?
            ])
        }
        Some("set") => {
            require_write(args)?;
            let principal = required(args, "--principal")?.to_owned();
            let default_unix_user = required(args, "--unix-user")?.to_owned();
            let mut unix_users = repeated(args, "--allow-user")
                .into_iter()
                .map(str::to_owned)
                .collect::<Vec<_>>();
            if !unix_users.contains(&default_unix_user) {
                unix_users.push(default_unix_user.clone());
            }
            unix_users.sort();
            unix_users.dedup();
            let mut roles = repeated(args, "--role")
                .into_iter()
                .map(str::to_owned)
                .collect::<Vec<_>>();
            roles.sort();
            roles.dedup();
            let profile = SshClientProfile {
                version: 1,
                principal,
                default_unix_user,
                unix_users,
                roles,
            };
            validate_profile(&profile)?;
            let path = profile_path();
            fs::create_dir_all(path.parent().expect("profile has parent"))
                .map_err(|error| format!("create SSH profile directory: {error}"))?;
            let staging = path.with_extension("json.staging");
            fs::write(
                &staging,
                serde_json::to_vec_pretty(&profile).map_err(|error| error.to_string())?,
            )
            .map_err(|error| format!("write staged SSH profile: {error}"))?;
            fs::rename(&staging, &path)
                .map_err(|error| format!("install SSH profile {}: {error}", path.display()))?;
            Ok(vec![format!(
                "SSH profile {} now defaults to {}",
                profile.principal, profile.default_unix_user
            )])
        }
        _ => Err(
            "access ssh profile needs `show` or `set --principal ID --unix-user USER --write`"
                .into(),
        ),
    }
}

fn validate_profile(profile: &SshClientProfile) -> Result<(), String> {
    if profile.version != 1 {
        return Err(format!(
            "unsupported SSH profile version {}",
            profile.version
        ));
    }
    config_value_text("SSH principal", &profile.principal)?;
    config_atom_value("default Unix user", &profile.default_unix_user)?;
    if profile.default_unix_user == "root"
        || !profile.unix_users.contains(&profile.default_unix_user)
        || profile.unix_users.len() > 16
        || profile.roles.len() > 32
    {
        return Err("SSH profile has an unsafe or inconsistent default Unix user".into());
    }
    for user in &profile.unix_users {
        config_atom_value("Unix user", user)?;
        if user == "root" {
            return Err("SSH profile cannot select root".into());
        }
    }
    for role in &profile.roles {
        config_atom_value("role", role)?;
    }
    Ok(())
}

pub(crate) fn renewal_statement(
    args: &[String],
    state: &Value,
) -> Result<(AccessStatement, PathBuf), String> {
    require_write(args)?;
    let grant_id = required(args, "--grant")?;
    let node_id = required(args, "--node")?;
    let ttl = parse_duration(value(args, "--credential-ttl").unwrap_or("8h"))?;
    let scope = myceliumd::ssh_renewal::scope(node_id, ttl)?;
    let entry = state["grants"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|g| g["active"] == true && g["record"]["statement"]["grant_id"] == grant_id)
        .ok_or("renewal needs an active signed --grant; it cannot revive expired access")?;
    let record: mycelium_peer_protocol::AccessRecord =
        serde_json::from_value(entry["record"].clone()).map_err(|e| e.to_string())?;
    record.verify()?;
    let mut statement = record.statement;
    let at = now()?;
    let AccessStatement::Grant {
        grant_id: id,
        serial,
        scopes,
        roles,
        unix_users,
        ssh_public_keys,
        not_before,
        not_after,
        ..
    } = &mut statement
    else {
        return Err("not an access grant".into());
    };
    if roles.is_empty()
        || unix_users.is_empty()
        || ssh_public_keys.is_empty()
        || at < *not_before
        || at >= *not_after
    {
        return Err("renewal grant needs current roles, Unix users and enrolled SSH keys".into());
    }
    for role in repeated(args, "--role") {
        if !roles.iter().any(|r| r == role) {
            return Err("renewal cannot add a role missing from the selected grant".into());
        }
    }
    for user in repeated(args, "--unix-user") {
        if !unix_users.iter().any(|u| u == user) {
            return Err("renewal cannot add a Unix user missing from the selected grant".into());
        }
    }
    if let Some(duration) = value(args, "--authorization-ttl") {
        let duration = parse_duration(duration)?;
        if duration == 0 || duration > 365 * 86400 {
            return Err("authorization TTL must be between 1 second and 365 days".into());
        }
        *not_after = at.saturating_add(duration);
    }
    *id = format!(
        "ssh-renewal-{}-{at}-{}",
        &node_id[..8],
        &mycelium_peer_protocol::sha256_hex(grant_id.as_bytes())[..8]
    );
    *serial = at;
    *not_before = at.saturating_sub(30);
    scopes.retain(|s| !s.starts_with("ssh-renewal:"));
    scopes.push(scope);
    let key = value(args, "--signing-key")
        .map(PathBuf::from)
        .unwrap_or_else(|| myceliumd::home_dir().join("access.key"));
    Ok((statement, key))
}

/// One host's installed SSH acceptance: the roles each Unix account will take.
///
/// This is observed host state, not a grant. `directory collect` reads it from
/// `/etc/ssh/mycelium/principals/<user>`; `directory show` intersects it with the
/// signed grants the local access view has converged.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct SshDirectoryInventory {
    version: u32,
    #[serde(default)]
    targets: Vec<SshDirectoryTarget>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct SshDirectoryTarget {
    /// Operator-facing target name. It is a lookup hint, never a credential.
    id: String,
    #[serde(default)]
    label: Option<String>,
    #[serde(default)]
    kind: Option<String>,
    #[serde(default)]
    site: Option<String>,
    /// Unix account -> accepted roles, exactly as installed on the host.
    #[serde(default)]
    accounts: BTreeMap<String, BTreeSet<String>>,
}

/// The active grants one principal holds, already narrowed to roles and accounts.
struct HeldGrant {
    grant_id: String,
    roles: BTreeSet<String>,
    unix_users: BTreeSet<String>,
}

/// One target as this principal may use it.
#[derive(Debug, Serialize)]
struct DirectoryTarget {
    id: String,
    label: String,
    kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    site: Option<String>,
    /// Whether this caller may open a shell on the target.
    shell: bool,
    /// Roles the principal holds that this host accepts.
    roles: Vec<String>,
    /// Unix accounts the principal may log in as.
    accounts: Vec<String>,
}

#[derive(Debug, Serialize)]
struct DirectoryView {
    principal: String,
    roles: Vec<String>,
    unix_users: Vec<String>,
    grants: Vec<String>,
    /// Records the access view carried that failed their own signature check.
    /// They never contribute entitlements; they are listed so a corrupt or
    /// forged gossip record is visible instead of silently shrinking the view.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    unverified: Vec<String>,
    targets: Vec<DirectoryTarget>,
}

fn directory_path() -> PathBuf {
    myceliumd::home_dir().join("ssh/directory.json")
}

fn directory(args: &[String], state: &Value) -> Result<Vec<String>, String> {
    match args.get(1).map(String::as_str) {
        Some("collect") => directory_collect(args),
        Some(action) if !action.starts_with('-') => Err(format!(
            "unknown access ssh directory action `{action}`; use `show` or `collect`"
        )),
        _ => directory_show(args, state),
    }
}

fn directory_show(args: &[String], state: &Value) -> Result<Vec<String>, String> {
    let principal = match value(args, "--principal") {
        Some(principal) => {
            validate_principal(principal)?;
            principal.to_owned()
        }
        None => profile_principal()?,
    };
    let path = value(args, "--from")
        .map(PathBuf::from)
        .unwrap_or_else(directory_path);
    let inventory = load_directory(&path)?;
    let (held, unverified) = held_grants(state, &principal, now()?)?;
    let view = directory_view(
        &principal,
        &held,
        &inventory,
        args.iter().any(|argument| argument == "--all"),
        unverified,
    );
    if args.iter().any(|argument| argument == "--json") {
        return Ok(vec![serde_json::to_string_pretty(&view)
            .map_err(|error| format!("encode SSH directory: {error}"))?]);
    }
    Ok(render_directory(&view))
}

/// Collect each target's installed acceptance into one inventory file.
///
/// The remote read touches root-owned policy, so it uses the same
/// non-interactive `sudo -n` contract `host-apply` relies on. A target that
/// cannot be read fails the collection instead of contributing an empty,
/// misleading entry.
fn directory_collect(args: &[String]) -> Result<Vec<String>, String> {
    require_write(args)?;
    let destination = Path::new(required(args, "--path")?);
    let targets = repeated(args, "--target");
    if targets.is_empty() {
        return Err("directory collect needs at least one --target SSH-HOST".into());
    }
    let site = value(args, "--site").map(str::to_owned);
    let mut inventory = SshDirectoryInventory {
        version: 1,
        targets: Vec::new(),
    };
    for target in &targets {
        config_atom_value("SSH target", target)?;
        if inventory.targets.iter().any(|entry| entry.id == *target) {
            return Err(format!("duplicate --target `{target}`"));
        }
        inventory.targets.push(SshDirectoryTarget {
            id: (*target).to_owned(),
            label: Some((*target).to_owned()),
            kind: Some("host".into()),
            site: site.clone(),
            accounts: collect_host_acceptance(target)?,
        });
    }
    inventory.targets.sort_by(|a, b| a.id.cmp(&b.id));
    let staging = destination_staging(destination)?;
    fs::write(
        &staging.path,
        serde_json::to_vec_pretty(&inventory)
            .map_err(|error| format!("encode SSH directory inventory: {error}"))?,
    )
    .map_err(|error| format!("write staged SSH directory inventory: {error}"))?;
    private_permissions(&staging.path, 0o600)?;
    fs::rename(&staging.path, destination).map_err(|error| {
        format!(
            "install SSH directory inventory {}: {error}",
            destination.display()
        )
    })?;
    let accounts = inventory
        .targets
        .iter()
        .map(|target| target.accounts.len())
        .sum::<usize>();
    Ok(vec![format!(
        "wrote SSH directory {}; {} hosts, {} accounts",
        destination.display(),
        inventory.targets.len(),
        accounts
    )])
}

fn collect_host_acceptance(target: &str) -> Result<BTreeMap<String, BTreeSet<String>>, String> {
    let directory = "/etc/ssh/mycelium/principals";
    let listing = ssh_capture(target, &["ls", "-1", directory])?;
    let mut accounts = BTreeMap::new();
    for account in listing
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
    {
        config_atom_value("Unix account", account)?;
        let path = format!("{directory}/{account}");
        let contents = ssh_capture(target, &["cat", &path])?;
        accounts.insert(
            account.to_owned(),
            parse_role_principals(account, &contents)?,
        );
    }
    Ok(accounts)
}

fn ssh_capture(target: &str, remote: &[&str]) -> Result<String, String> {
    let output = Command::new("ssh")
        .args([
            "-o",
            "BatchMode=yes",
            "-o",
            "ConnectTimeout=15",
            target,
            "sudo",
            "-n",
            "--",
        ])
        .args(remote)
        .output()
        .map_err(|error| format!("run ssh {target}: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "read SSH acceptance from {target}: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    String::from_utf8(output.stdout)
        .map_err(|_| format!("{target} returned non-UTF-8 principal data"))
}

fn parse_role_principals(account: &str, contents: &str) -> Result<BTreeSet<String>, String> {
    let mut roles = BTreeSet::new();
    for line in contents
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
    {
        let role = line.strip_prefix("mycelium-role-").ok_or_else(|| {
            format!("account `{account}` accepts `{line}`, which is not a Mycelium role principal")
        })?;
        config_atom_value("role", role)?;
        roles.insert(role.to_owned());
    }
    Ok(roles)
}

fn load_directory(path: &Path) -> Result<SshDirectoryInventory, String> {
    let bytes = fs::read(path).map_err(|error| {
        format!(
            "read SSH directory inventory {}: {error}; collect one with `mycelium access ssh directory collect --target HOST --path {} --write`",
            path.display(),
            path.display()
        )
    })?;
    let inventory: SshDirectoryInventory = serde_json::from_slice(&bytes)
        .map_err(|error| format!("parse SSH directory inventory {}: {error}", path.display()))?;
    if inventory.version != 1 {
        return Err(format!(
            "SSH directory inventory {} needs version 1",
            path.display()
        ));
    }
    Ok(inventory)
}

fn profile_principal() -> Result<String, String> {
    let path = profile_path();
    let bytes = fs::read(&path).map_err(|error| {
        format!(
            "read SSH profile {}: {error}; pass --principal or set one with `mycelium access ssh profile set`",
            path.display()
        )
    })?;
    let profile: SshClientProfile = serde_json::from_slice(&bytes)
        .map_err(|error| format!("parse SSH profile {}: {error}", path.display()))?;
    validate_profile(&profile)?;
    Ok(profile.principal)
}

/// Principals are `name` or `oidc:<issuer>#<subject>`; the latter carries `:`,
/// `/` and `#`, so the SSH-config atom rules do not apply.
fn validate_principal(principal: &str) -> Result<(), String> {
    if principal.is_empty()
        || principal.len() > 256
        || !principal.bytes().all(|byte| byte.is_ascii_graphic())
    {
        return Err("principal must be 1-256 printable, whitespace-free characters".into());
    }
    Ok(())
}

fn held_grants(
    state: &Value,
    principal: &str,
    at: u64,
) -> Result<(Vec<HeldGrant>, Vec<String>), String> {
    let mut held = Vec::new();
    let mut unverified = Vec::new();
    for entry in state["grants"].as_array().into_iter().flatten() {
        if entry["active"].as_bool() != Some(true) {
            continue;
        }
        let record: AccessRecord = serde_json::from_value(entry["record"].clone())
            .map_err(|error| format!("decode access record: {error}"))?;
        let statement = record.statement.clone();
        if record.verify().is_err() {
            if let AccessStatement::Grant { grant_id, .. } = &statement {
                unverified.push(grant_id.clone());
            }
            continue;
        }
        let AccessStatement::Grant {
            grant_id,
            principal: owner,
            roles,
            unix_users,
            not_before,
            not_after,
            ..
        } = statement
        else {
            continue;
        };
        if owner != principal || at < not_before || at >= not_after {
            continue;
        }
        held.push(HeldGrant {
            grant_id,
            roles: roles.into_iter().collect(),
            unix_users: unix_users.into_iter().collect(),
        });
    }
    held.sort_by(|a, b| a.grant_id.cmp(&b.grant_id));
    unverified.sort();
    unverified.dedup();
    Ok((held, unverified))
}

/// A target is visible only when a held role is accepted for an account the
/// grant actually names. Roles alone are not enough: the host's
/// `principals/<user>` file decides which account takes them.
fn directory_view(
    principal: &str,
    grants: &[HeldGrant],
    inventory: &SshDirectoryInventory,
    include_all: bool,
    unverified: Vec<String>,
) -> DirectoryView {
    let mut roles = BTreeSet::new();
    let mut unix_users = BTreeSet::new();
    let mut grant_ids = Vec::new();
    for grant in grants {
        roles.extend(grant.roles.iter().cloned());
        unix_users.extend(grant.unix_users.iter().cloned());
        grant_ids.push(grant.grant_id.clone());
    }
    let mut targets = Vec::new();
    for target in &inventory.targets {
        let mut accepted = BTreeSet::new();
        let mut accounts = BTreeSet::new();
        for (account, account_roles) in &target.accounts {
            if !unix_users.contains(account) {
                continue;
            }
            let allowed = account_roles
                .intersection(&roles)
                .cloned()
                .collect::<BTreeSet<_>>();
            if allowed.is_empty() {
                continue;
            }
            accepted.extend(allowed);
            accounts.insert(account.clone());
        }
        let shell = !accounts.is_empty();
        if !shell && !include_all {
            continue;
        }
        targets.push(DirectoryTarget {
            id: target.id.clone(),
            label: target.label.clone().unwrap_or_else(|| target.id.clone()),
            kind: target.kind.clone().unwrap_or_else(|| "host".into()),
            site: target.site.clone(),
            shell,
            roles: accepted.into_iter().collect(),
            accounts: accounts.into_iter().collect(),
        });
    }
    targets.sort_by(|a, b| a.id.cmp(&b.id));
    DirectoryView {
        principal: principal.to_owned(),
        roles: roles.into_iter().collect(),
        unix_users: unix_users.into_iter().collect(),
        grants: grant_ids,
        unverified,
        targets,
    }
}

fn render_directory(view: &DirectoryView) -> Vec<String> {
    let mut lines = vec![format!("principal {}", view.principal)];
    if view.roles.is_empty() {
        lines.push("roles none (no active grant)".into());
    } else {
        lines.push(format!("roles {}", view.roles.join(", ")));
    }
    if !view.unverified.is_empty() {
        lines.push(format!(
            "unverified grants {} (excluded)",
            view.unverified.join(", ")
        ));
    }
    if view.targets.is_empty() {
        lines.push("targets none".into());
        return lines;
    }
    lines.push(format!("targets {}", view.targets.len()));
    for target in &view.targets {
        if !target.shell {
            lines.push(format!("  {} no shell", target.id));
            continue;
        }
        lines.push(format!(
            "  {} accounts={} roles={}",
            target.id,
            target.accounts.join(","),
            target.roles.join(",")
        ));
    }
    lines
}

fn host_rollout(args: &[String]) -> Result<Vec<String>, String> {
    require_write(args)?;
    let bundle = Path::new(required(args, "--bundle")?);
    validate_host_bundle(bundle)?;
    let targets = repeated(args, "--target");
    if targets.is_empty() {
        return Err("host-rollout needs at least one --target".into());
    }
    let remote_binary =
        value(args, "--remote-bin").unwrap_or("/home/ajmwagar/.mycelium/bin/mycelium");
    config_value_text("remote Mycelium binary", remote_binary)?;
    let mut lines = Vec::new();
    for (index, target) in targets.iter().enumerate() {
        validate_rollout_target(target)?;
        let bundle_name = bundle
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| "host bundle path needs a UTF-8 directory name".to_string())?;
        config_value_text("host bundle directory name", bundle_name)?;
        let remote_parent = format!("/tmp/mycelium-host-rollout-{}-{index}", std::process::id());
        let remote_bundle = format!("{remote_parent}/{bundle_name}");
        command_owned(
            "ssh",
            vec![
                "-o".into(),
                "BatchMode=yes".into(),
                (*target).into(),
                "mkdir".into(),
                "-p".into(),
                remote_parent.clone(),
            ],
        )?;
        command_owned(
            "scp",
            vec![
                "-q".into(),
                "-O".into(),
                "-r".into(),
                bundle.display().to_string(),
                format!("{target}:{remote_parent}/"),
            ],
        )?;
        command_owned(
            "ssh",
            vec![
                "-o".into(),
                "BatchMode=yes".into(),
                (*target).into(),
                "sudo".into(),
                "-n".into(),
                remote_binary.into(),
                "access".into(),
                "ssh".into(),
                "host-apply".into(),
                "--bundle".into(),
                remote_bundle,
                "--write".into(),
            ],
        )?;
        lines.push(format!("converged SSH access policy on {target}"));
    }
    Ok(lines)
}

fn validate_rollout_target(target: &str) -> Result<(), String> {
    if target.is_empty()
        || target.len() > 320
        || !target.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_' | b':' | b'@')
        })
    {
        return Err(format!("unsafe rollout target `{target}`"));
    }
    Ok(())
}

fn command_owned(program: &str, args: Vec<String>) -> Result<(), String> {
    let output = Command::new(program)
        .args(&args)
        .output()
        .map_err(|error| format!("run {program}: {error}"))?;
    if output.status.success() {
        Ok(())
    } else {
        Err(format!(
            "{} {} failed: {}",
            program,
            args.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        ))
    }
}

fn host_apply(args: &[String]) -> Result<Vec<String>, String> {
    require_write(args)?;
    let bundle = Path::new(required(args, "--bundle")?);
    validate_host_bundle(bundle)?;
    let manifest = load_host_manifest(bundle)?;
    if !cfg!(any(target_os = "linux", target_os = "macos")) {
        return Err("SSH host bundle application currently supports Linux and macOS only".into());
    }
    let uid = Command::new("id")
        .arg("-u")
        .output()
        .map_err(|e| format!("determine effective user: {e}"))?;
    if !uid.status.success() || String::from_utf8_lossy(&uid.stdout).trim() != "0" {
        return Err("SSH host bundle application needs root; run this command through sudo".into());
    }

    let ssh = Path::new("/etc/ssh");
    let managed = ssh.join("mycelium");
    let drop_in = ssh.join("sshd_config.d/60-mycelium-access.conf");
    let backup = ssh.join(format!("mycelium.pre-{}", now()?));
    fs::create_dir_all(&backup)
        .map_err(|e| format!("create rollback directory {}: {e}", backup.display()))?;
    let prior = [
        (managed.join("user_ca.pub"), "user_ca.pub"),
        (managed.join("revoked.krl"), "revoked.krl"),
        (drop_in.clone(), "60-mycelium-access.conf"),
    ];
    for (source, name) in &prior {
        if source.is_file() {
            fs::copy(source, backup.join(name))
                .map_err(|e| format!("back up {}: {e}", source.display()))?;
        }
    }
    let prior_principals = managed.join("principals");
    if prior_principals.is_dir() {
        copy_directory_files(&prior_principals, &backup.join("principals"))?;
    }
    public_policy_directory(&managed)?;
    fs::create_dir_all(drop_in.parent().expect("drop-in has parent"))
        .map_err(|e| format!("create sshd drop-in directory: {e}"))?;
    let mut created_accounts = Vec::new();
    let mut install = || -> Result<(), String> {
        install_mode(
            &bundle.join("user_ca.pub"),
            &managed.join("user_ca.pub"),
            0o644,
        )?;
        install_mode(
            &bundle.join("revoked.krl"),
            &managed.join("revoked.krl"),
            0o644,
        )?;
        install_mode(&bundle.join("60-mycelium-access.conf"), &drop_in, 0o644)?;
        let principals = managed.join("principals");
        if principals.exists() {
            fs::remove_dir_all(&principals)
                .map_err(|e| format!("replace {}: {e}", principals.display()))?;
        }
        public_policy_directory(&principals)?;
        for entry in fs::read_dir(bundle.join("principals"))
            .map_err(|e| format!("read host principals: {e}"))?
        {
            let entry = entry.map_err(|e| format!("read host principal entry: {e}"))?;
            if entry.file_type().map_err(|e| e.to_string())?.is_file() {
                install_mode(&entry.path(), &principals.join(entry.file_name()), 0o644)?;
            }
        }
        created_accounts = reconcile_host_accounts(&manifest.accounts)?;
        command("sshd", &["-t"])?;
        reload_sshd()?;
        Ok(())
    };
    if let Err(error) = install() {
        for (destination, name) in &prior {
            let saved = backup.join(name);
            if saved.is_file() {
                let _ = install_mode(&saved, destination, 0o644);
            } else {
                let _ = fs::remove_file(destination);
            }
        }
        let principals = managed.join("principals");
        let _ = fs::remove_dir_all(&principals);
        if backup.join("principals").is_dir() {
            let _ = public_policy_directory(&principals);
            let _ = copy_directory_files(&backup.join("principals"), &principals);
        }
        let _ = command("sshd", &["-t"]);
        let _ = reload_sshd();
        rollback_created_accounts(&created_accounts);
        return Err(format!(
            "SSH host bundle failed and prior files were restored from {}: {error}",
            backup.display()
        ));
    }
    Ok(vec![
        format!(
            "installed SSH trust bundle; rollback copy retained at {}",
            backup.display()
        ),
        format!(
            "reconciled {} managed account(s); created {}",
            manifest.accounts.len(),
            created_accounts.len()
        ),
    ])
}

fn load_host_manifest(bundle: &Path) -> Result<HostBundleManifest, String> {
    serde_json::from_slice(
        &fs::read(bundle.join("manifest.json"))
            .map_err(|error| format!("read host bundle manifest: {error}"))?,
    )
    .map_err(|error| format!("parse host bundle manifest: {error}"))
}

fn reconcile_host_accounts(accounts: &[HostAccountIntent]) -> Result<Vec<String>, String> {
    let mut created = Vec::new();
    for account in accounts {
        validate_managed_account(account)?;
        let lookup = Command::new("id")
            .args(["-u", &account.name])
            .output()
            .map_err(|error| format!("look up account {}: {error}", account.name))?;
        if lookup.status.success() {
            let uid = String::from_utf8_lossy(&lookup.stdout).trim().to_owned();
            if uid == "0" {
                return Err(format!(
                    "refusing to bind managed access role to UID 0 account `{}`",
                    account.name
                ));
            }
            continue;
        }
        if !cfg!(target_os = "linux") {
            return Err(format!(
                "managed account `{}` is missing; automatic creation currently supports Linux only",
                account.name
            ));
        }
        command(
            "useradd",
            &["--create-home", "--shell", "/bin/bash", &account.name],
        )?;
        created.push(account.name.clone());
        if let Err(error) = command("passwd", &["--lock", &account.name]) {
            rollback_created_accounts(&created);
            return Err(error);
        }
    }
    Ok(created)
}

fn rollback_created_accounts(accounts: &[String]) {
    for account in accounts.iter().rev() {
        // Preserve the newly created home directory: rollback removes only the
        // account record and never recursively deletes user data.
        let _ = Command::new("userdel").arg(account).status();
    }
}

fn validate_managed_account(account: &HostAccountIntent) -> Result<(), String> {
    config_atom_value("managed account", &account.name)?;
    if account.state != "present"
        || !account.password_locked
        || !account.supplementary_groups.is_empty()
    {
        return Err(format!(
            "managed account `{}` must be present, password-locked, and have no supplementary groups",
            account.name
        ));
    }
    Ok(())
}

fn copy_directory_files(source: &Path, destination: &Path) -> Result<(), String> {
    fs::create_dir_all(destination)
        .map_err(|e| format!("create {}: {e}", destination.display()))?;
    for entry in fs::read_dir(source).map_err(|e| format!("read {}: {e}", source.display()))? {
        let entry = entry.map_err(|e| format!("read directory entry: {e}"))?;
        if entry.file_type().map_err(|e| e.to_string())?.is_file() {
            fs::copy(entry.path(), destination.join(entry.file_name()))
                .map_err(|e| format!("copy principal policy: {e}"))?;
        }
    }
    Ok(())
}

fn reload_sshd() -> Result<(), String> {
    #[cfg(target_os = "linux")]
    {
        if command("systemctl", &["reload", "sshd"]).is_err()
            && command("systemctl", &["reload", "ssh"]).is_err()
        {
            // Minimal Linux containers and non-systemd hosts retain the
            // distribution's init-script reload; never fake a successful reload.
            command("service", &["ssh", "reload"])?;
        }
    }
    // launchd invokes sshd for each inbound macOS connection, so the next
    // connection picks up the validated configuration without a restart.
    Ok(())
}

fn validate_host_bundle(bundle: &Path) -> Result<(), String> {
    for name in [
        "user_ca.pub",
        "revoked.krl",
        "60-mycelium-access.conf",
        "manifest.json",
    ] {
        if !bundle.join(name).is_file() {
            return Err(format!(
                "SSH host bundle {} is missing {name}",
                bundle.display()
            ));
        }
    }
    if !bundle.join("principals").is_dir() {
        return Err(format!(
            "SSH host bundle {} is missing principals directory",
            bundle.display()
        ));
    }
    Ok(())
}

// sshd opens AuthorizedPrincipalsFile as the target account. Its public policy
// ancestors must be traversable even when enrollment runs with UMask=0077.
// This applies only to Mycelium's policy directories, never keys or backups.
fn public_policy_directory(path: &Path) -> Result<(), String> {
    fs::create_dir_all(path).map_err(|e| format!("create {}: {e}", path.display()))?;
    private_permissions(path, 0o755)
}

fn public_policy_directory_matches(path: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::metadata(path).is_ok_and(|metadata| {
            metadata.is_dir() && metadata.permissions().mode() & 0o777 == 0o755
        })
    }
    #[cfg(not(unix))]
    path.is_dir()
}

fn install_mode(source: &Path, destination: &Path, mode: u32) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    let staged = destination.with_extension(format!("mycelium-install-{}", std::process::id()));
    fs::copy(source, &staged).map_err(|e| format!("stage {}: {e}", destination.display()))?;
    fs::set_permissions(&staged, fs::Permissions::from_mode(mode))
        .map_err(|e| format!("set permissions on {}: {e}", staged.display()))?;
    fs::rename(&staged, destination).map_err(|e| format!("install {}: {e}", destination.display()))
}

fn client_config(args: &[String]) -> Result<Vec<String>, String> {
    require_write(args)?;
    let alias = config_atom(args, "--host")?;
    let hostname = config_atom(args, "--hostname")?;
    let user = config_atom(args, "--user")?;
    let identity = config_value(args, "--identity")?;
    let certificate = config_value(args, "--certificate")?;
    let port = value(args, "--port")
        .map(|port| {
            port.parse::<u16>()
                .map_err(|_| format!("invalid SSH port `{port}`"))
        })
        .transpose()?;
    let destination = Path::new(required(args, "--path")?);
    if destination.exists() {
        return Err(format!(
            "refusing to replace existing SSH client config {}",
            destination.display()
        ));
    }
    let mut config = format!(
        "# Managed by Mycelium. Include this file from ~/.ssh/config.\n\
         Host {alias}\n\
           HostName {hostname}\n\
           User {user}\n"
    );
    if let Some(port) = port {
        config.push_str(&format!("  Port {port}\n"));
    }
    config.push_str(&format!(
        "  IdentityFile {identity}\n\
           CertificateFile {certificate}\n\
           IdentitiesOnly yes\n"
    ));
    let staging_guard = destination_staging(destination)?;
    let staging = staging_guard.path.clone();
    fs::write(&staging, config)
        .map_err(|e| format!("write staged SSH client config {}: {e}", staging.display()))?;
    private_permissions(&staging, 0o600)?;
    fs::rename(&staging, destination)
        .map_err(|e| format!("install SSH client config {}: {e}", destination.display()))?;
    Ok(vec![format!(
        "wrote SSH client config {}; add `Include {}` to ~/.ssh/config",
        destination.display(),
        destination.display()
    )])
}

fn host_bundle(args: &[String], state: &Value) -> Result<Vec<String>, String> {
    require_write(args)?;
    let ca_public = required(args, "--ca-public")?;
    let krl = required(args, "--krl")?;
    let destination = Path::new(required(args, "--path")?);
    if destination.exists() {
        return Err(format!(
            "refusing to replace existing SSH host bundle {}",
            destination.display()
        ));
    }
    let staging_guard = destination_staging(destination)?;
    let staging = staging_guard.path.clone();
    if staging.exists() {
        fs::remove_dir_all(&staging)
            .map_err(|e| format!("remove stale staging directory {}: {e}", staging.display()))?;
    }
    fs::create_dir_all(&staging)
        .map_err(|e| format!("create staging directory {}: {e}", staging.display()))?;
    let role_mappings = role_mappings(args, state)?;
    let result = (|| {
        let principals = staging.join("principals");
        fs::create_dir_all(&principals).map_err(|e| format!("create principals directory: {e}"))?;
        for (user, roles) in &role_mappings {
            let contents = roles
                .iter()
                .map(|role| format!("mycelium-role-{role}\n"))
                .collect::<String>();
            fs::write(principals.join(user), contents)
                .map_err(|e| format!("write role principal: {e}"))?;
        }
        fs::copy(ca_public, staging.join("user_ca.pub"))
            .map_err(|e| format!("copy SSH CA public key: {e}"))?;
        fs::copy(krl, staging.join("revoked.krl"))
            .map_err(|e| format!("copy SSH revocation list: {e}"))?;
        fs::write(
            staging.join("60-mycelium-access.conf"),
            "# Managed by Mycelium; existing SSH authentication remains enabled.\n\
             TrustedUserCAKeys /etc/ssh/mycelium/user_ca.pub\n\
             RevokedKeys /etc/ssh/mycelium/revoked.krl\n\
             AuthorizedPrincipalsFile /etc/ssh/mycelium/principals/%u\n\
             PubkeyAuthentication yes\n",
        )
        .map_err(|e| format!("write sshd drop-in: {e}"))?;
        let manifest = HostBundleManifest {
            version: 2,
            accounts: role_mappings
                .keys()
                .map(|name| HostAccountIntent {
                    name: name.clone(),
                    state: "present".into(),
                    password_locked: true,
                    supplementary_groups: Vec::new(),
                })
                .collect(),
        };
        fs::write(
            staging.join("manifest.json"),
            serde_json::to_vec_pretty(&manifest)
                .map_err(|e| format!("encode host bundle manifest: {e}"))?,
        )
        .map_err(|e| format!("write host bundle manifest: {e}"))?;
        fs::rename(&staging, destination)
            .map_err(|e| format!("install host bundle {}: {e}", destination.display()))
    })();
    if result.is_err() {
        let _ = fs::remove_dir_all(&staging);
    }
    result?;
    Ok(vec![format!(
        "wrote SSH host bundle {}; validate with `sshd -t` before installation",
        destination.display()
    )])
}

fn role_mappings(
    args: &[String],
    state: &Value,
) -> Result<BTreeMap<String, BTreeSet<String>>, String> {
    let mut mappings = BTreeMap::<String, BTreeSet<String>>::new();
    for assignment in repeated(args, "--allow") {
        let (user, role) = assignment
            .split_once('=')
            .ok_or_else(|| format!("invalid --allow `{assignment}`; expected USER=ROLE"))?;
        config_atom_value("Unix user", user)?;
        config_atom_value("role", role)?;
        if user == "root" {
            return Err("refusing to manage SSH role access for the root account".into());
        }
        mappings
            .entry(user.to_owned())
            .or_default()
            .insert(role.to_owned());
    }
    if args.iter().any(|argument| argument == "--from-access") {
        let selected_roles = repeated(args, "--role")
            .into_iter()
            .collect::<BTreeSet<_>>();
        if selected_roles.is_empty() {
            return Err("host-bundle --from-access needs at least one --role".into());
        }
        for entry in state["grants"].as_array().into_iter().flatten() {
            if entry["active"].as_bool() != Some(true) {
                continue;
            }
            let statement: AccessStatement =
                serde_json::from_value(entry["record"]["statement"].clone())
                    .map_err(|error| format!("decode active access grant: {error}"))?;
            let AccessStatement::Grant {
                roles, unix_users, ..
            } = statement
            else {
                continue;
            };
            for role in roles
                .into_iter()
                .filter(|role| selected_roles.contains(role.as_str()))
            {
                config_atom_value("role", &role)?;
                for user in &unix_users {
                    config_atom_value("Unix user", user)?;
                    if user == "root" {
                        return Err("refusing to derive SSH access for root".into());
                    }
                    mappings
                        .entry(user.clone())
                        .or_default()
                        .insert(role.clone());
                }
            }
        }
    }
    if mappings.is_empty() && !args.iter().any(|argument| argument == "--allow-empty") {
        return Err("SSH host bundle needs at least one resolved USER=ROLE mapping".into());
    }
    Ok(mappings)
}

fn ca_init(args: &[String]) -> Result<Vec<String>, String> {
    require_write(args)?;
    let path = required(args, "--path")?;
    if Path::new(path).exists() || PathBuf::from(format!("{path}.pub")).exists() {
        return Err(format!("refusing to replace existing SSH CA at {path}"));
    }
    if let Some(parent) = Path::new(path).parent() {
        fs::create_dir_all(parent).map_err(|e| format!("create {}: {e}", parent.display()))?;
    }
    command(
        "ssh-keygen",
        &[
            "-q",
            "-t",
            "ed25519",
            "-N",
            "",
            "-C",
            "mycelium access authority",
            "-f",
            path,
        ],
    )?;
    Ok(vec![format!(
        "created SSH user CA {path} (public key: {path}.pub)"
    )])
}

fn issue(args: &[String], state: &Value) -> Result<Vec<String>, String> {
    issue_bound(args, state, None, None, None)
}

pub(crate) fn issue_for_invite(
    public_key_path: &Path,
    ca: &Path,
    output: &Path,
    invitation_id: &str,
    name: &str,
    serial: u64,
    unix_users: &[String],
    roles: &[String],
    ttl: u64,
) -> Result<(), String> {
    if unix_users.is_empty() || ttl == 0 {
        return Err("invitation has no Unix principals or credential lifetime".into());
    }
    let public_key = fs::read_to_string(public_key_path)
        .map_err(|error| format!("read SSH public key {}: {error}", public_key_path.display()))?;
    key_material(&public_key)?;
    let staging_guard = destination_staging(output)?;
    let temp = staging_guard.path.clone();
    fs::copy(public_key_path, &temp)
        .map_err(|error| format!("prepare certificate input {}: {error}", temp.display()))?;
    private_permissions(&temp, 0o600)?;
    // A role-bound certificate must not also carry its Unix account as a
    // principal: older hosts that trust the CA without AuthorizedPrincipalsFile
    // would otherwise accept it and bypass the host's role policy.
    let principals = if roles.is_empty() {
        unix_users.to_vec()
    } else {
        roles
            .iter()
            .flat_map(|role| {
                [
                    format!("mycelium-role-{role}"),
                    mycelium_peer_protocol::ssh_role_principal(name, role),
                ]
            })
            .collect()
    };
    let principals = principals.join(",");
    let validity = format!("+0s:+{ttl}s");
    let serial = serial.to_string();
    let identity = format!("mycelium:invite:{invitation_id}:{name}");
    let result = command(
        "ssh-keygen",
        &[
            "-q",
            "-s",
            path_str(ca)?,
            "-I",
            &identity,
            "-n",
            &principals,
            "-V",
            &validity,
            "-z",
            &serial,
            path_str(&temp)?,
        ],
    );
    let generated = PathBuf::from(format!(
        "{}-cert.pub",
        temp.to_string_lossy()
            .strip_suffix(".pub")
            .unwrap_or(&temp.to_string_lossy())
    ));
    if let Err(error) = result {
        let _ = fs::remove_file(&temp);
        let _ = fs::remove_file(&generated);
        return Err(error);
    }
    fs::rename(&generated, output)
        .map_err(|error| format!("install certificate {}: {error}", output.display()))?;
    let _ = fs::remove_file(&temp);
    Ok(())
}

fn path_str(path: &Path) -> Result<&str, String> {
    path.to_str()
        .ok_or_else(|| format!("path is not UTF-8: {}", path.display()))
}

pub(crate) fn issue_for_oidc(
    args: &[String],
    state: &Value,
    principal: &str,
    audience: &str,
    _identity_expires_at: u64,
) -> Result<Vec<String>, String> {
    let grant_id = if let Some(grant_id) = value(args, "--grant") {
        grant_id.to_owned()
    } else {
        let matches = state["grants"]
            .as_array()
            .into_iter()
            .flatten()
            .filter(|entry| {
                entry["active"].as_bool() == Some(true)
                    && entry["record"]["statement"]["principal"].as_str() == Some(principal)
                    && entry["record"]["statement"]["oidc_audiences"]
                        .as_array()
                        .is_some_and(|audiences| audiences.iter().any(|value| value == audience))
            })
            .filter_map(|entry| entry["record"]["statement"]["grant_id"].as_str())
            .collect::<Vec<_>>();
        match matches.as_slice() {
            [grant_id] => (*grant_id).to_owned(),
            [] => return Err(format!("no active grant matches OIDC principal `{principal}`")),
            _ => {
                return Err(format!(
                    "multiple active grants match OIDC principal `{principal}`; select one with --grant"
                ))
            }
        }
    };
    let mut bound_args = args.to_vec();
    if value(args, "--grant").is_none() {
        bound_args.push("--grant".into());
        bound_args.push(grant_id);
    }
    issue_bound(&bound_args, state, Some(principal), Some(audience), None)
}

fn issue_bound(
    args: &[String],
    state: &Value,
    expected_principal: Option<&str>,
    expected_audience: Option<&str>,
    identity_expires_at: Option<u64>,
) -> Result<Vec<String>, String> {
    require_write(args)?;
    let grant_id = required(args, "--grant")?;
    let public_key_path = required(args, "--public-key")?;
    let ca = required(args, "--ca")?;
    let output = required(args, "--path")?;
    let requested_ttl = parse_duration(value(args, "--ttl").unwrap_or("8h"))?;
    let now = now()?;

    let grant = state["grants"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|entry| {
            entry["active"].as_bool() == Some(true)
                && entry["record"]["statement"]["grant_id"].as_str() == Some(grant_id)
        })
        .ok_or_else(|| format!("grant `{grant_id}` is missing, inactive, or revoked"))?;
    let statement: AccessStatement = serde_json::from_value(grant["record"]["statement"].clone())
        .map_err(|e| format!("decode grant `{grant_id}`: {e}"))?;
    let AccessStatement::Grant {
        principal,
        serial,
        roles,
        unix_users,
        ssh_public_keys,
        oidc_audiences,
        oidc_ssh_key_exchange,
        not_before,
        not_after,
        ..
    } = statement
    else {
        return Err(format!("record `{grant_id}` is not a grant"));
    };
    if expected_principal.is_some_and(|expected| expected != principal) {
        return Err(format!(
            "grant `{grant_id}` belongs to `{principal}`, not authenticated principal `{}`",
            expected_principal.unwrap_or_default()
        ));
    }
    if expected_audience
        .is_some_and(|expected| !oidc_audiences.iter().any(|value| value == expected))
    {
        return Err(format!(
            "grant `{grant_id}` does not authorize OIDC audience `{}`",
            expected_audience.unwrap_or_default()
        ));
    }
    if unix_users.is_empty() {
        return Err(format!("grant `{grant_id}` has no unix_users principals"));
    }
    if now < not_before || now >= not_after {
        return Err(format!("grant `{grant_id}` is outside its validity window"));
    }
    let public_key = fs::read_to_string(public_key_path)
        .map_err(|e| format!("read SSH public key {public_key_path}: {e}"))?;
    let key_fingerprint = key_material(&public_key)?;
    let key_is_enrolled = ssh_public_keys
        .iter()
        .filter_map(|key| key_material(key).ok())
        .any(|allowed| allowed == key_fingerprint);
    if !key_is_enrolled && !(expected_principal.is_some() && oidc_ssh_key_exchange) {
        return Err(format!(
            "public key is not authorized by grant `{grant_id}`"
        ));
    }
    let expires_at =
        identity_expires_at.map_or(not_after, |token_expiry| not_after.min(token_expiry));
    let ttl = requested_ttl.min(expires_at.saturating_sub(now));
    if ttl == 0 {
        return Err(format!(
            "grant `{grant_id}` or authenticated identity has expired"
        ));
    }

    let staging_guard = destination_staging(Path::new(output))?;
    let temp = staging_guard.path.clone();
    fs::copy(public_key_path, &temp)
        .map_err(|e| format!("prepare certificate input {}: {e}", temp.display()))?;
    private_permissions(&temp, 0o600)?;
    // Match invitation-issued certificates: a role-bound identity must not
    // also carry its Unix account as a principal, because older hosts that
    // only trust the CA could otherwise bypass the host's role mapping.
    let principals = if roles.is_empty() {
        unix_users.join(",")
    } else {
        roles
            .iter()
            .flat_map(|role| {
                [
                    format!("mycelium-role-{role}"),
                    mycelium_peer_protocol::ssh_role_principal(&principal, role),
                ]
            })
            .collect::<Vec<_>>()
            .join(",")
    };
    let validity = format!("+0s:+{ttl}s");
    let serial = serial.to_string();
    let identity = format!("mycelium:{grant_id}:{principal}");
    let result = command(
        "ssh-keygen",
        &[
            "-q",
            "-s",
            ca,
            "-I",
            &identity,
            "-n",
            &principals,
            "-V",
            &validity,
            "-z",
            &serial,
            temp.to_str().ok_or("temporary path is not UTF-8")?,
        ],
    );
    let generated = PathBuf::from(format!(
        "{}-cert.pub",
        temp.to_string_lossy()
            .strip_suffix(".pub")
            .unwrap_or(&temp.to_string_lossy())
    ));
    if let Err(error) = result {
        let _ = fs::remove_file(&temp);
        let _ = fs::remove_file(&generated);
        return Err(error);
    }
    fs::rename(&generated, output).map_err(|e| format!("install certificate {output}: {e}"))?;
    let _ = fs::remove_file(&temp);
    Ok(vec![format!(
        "issued {output} for grant={grant_id} serial={serial} principals={principals} ttl={ttl}s"
    )])
}

fn krl(args: &[String], state: &Value) -> Result<Vec<String>, String> {
    require_write(args)?;
    let ca_public = required(args, "--ca-public")?;
    let output = required(args, "--path")?;
    let mut serials: BTreeSet<u64> = state["revocations"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|record| record["statement"]["serial"].as_u64())
        .collect();
    // Principal- and grant-wide revocations need to become concrete OpenSSH
    // serial revocations too. The converged view already performed the
    // selector matching, so derive the affected serials instead of requiring
    // the authority to duplicate them in the revoke statement.
    serials.extend(
        state["grants"]
            .as_array()
            .into_iter()
            .flatten()
            .filter(|grant| {
                grant["revoked_by"]
                    .as_array()
                    .is_some_and(|records| !records.is_empty())
            })
            .filter_map(|grant| grant["record"]["statement"]["serial"].as_u64()),
    );
    let spec = temporary_key_path(output);
    let contents = serials
        .iter()
        .map(|serial| format!("serial: {serial}\n"))
        .collect::<String>();
    fs::write(&spec, contents).map_err(|e| format!("write {}: {e}", spec.display()))?;
    if let Some(parent) = Path::new(output).parent() {
        fs::create_dir_all(parent).map_err(|e| format!("create {}: {e}", parent.display()))?;
    }
    let result = command(
        "ssh-keygen",
        &[
            "-q",
            "-k",
            "-f",
            output,
            "-s",
            ca_public,
            spec.to_str().ok_or("temporary path is not UTF-8")?,
        ],
    );
    let _ = fs::remove_file(&spec);
    result?;
    Ok(vec![format!(
        "wrote {output} with {} revoked serial(s)",
        serials.len()
    )])
}

fn value<'a>(args: &'a [String], flag: &str) -> Option<&'a str> {
    args.iter()
        .position(|arg| arg == flag)
        .and_then(|i| args.get(i + 1))
        .map(String::as_str)
}

fn repeated<'a>(args: &'a [String], flag: &str) -> Vec<&'a str> {
    args.iter()
        .enumerate()
        .filter(|(_, argument)| argument.as_str() == flag)
        .filter_map(|(index, _)| args.get(index + 1).map(String::as_str))
        .collect()
}

fn config_atom_value(name: &str, value: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._+-".contains(&byte))
    {
        return Err(format!("{name} contains unsafe characters"));
    }
    Ok(())
}

fn required<'a>(args: &'a [String], flag: &str) -> Result<&'a str, String> {
    value(args, flag).ok_or_else(|| format!("access ssh needs {flag}"))
}

fn config_atom<'a>(args: &'a [String], flag: &str) -> Result<&'a str, String> {
    let value = required(args, flag)?;
    if value.is_empty()
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_graphic() && !b"#*?![]".contains(&byte))
    {
        return Err(format!("SSH config {flag} contains unsafe characters"));
    }
    Ok(value)
}

fn config_value<'a>(args: &'a [String], flag: &str) -> Result<&'a str, String> {
    let value = required(args, flag)?;
    config_value_text(flag, value)?;
    Ok(value)
}

fn config_value_text(name: &str, value: &str) -> Result<(), String> {
    if value.is_empty()
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_graphic() && byte != b'#')
    {
        return Err(format!("SSH config {name} contains unsafe characters"));
    }
    Ok(())
}

fn require_write(args: &[String]) -> Result<(), String> {
    args.iter()
        .any(|arg| arg == "--write")
        .then_some(())
        .ok_or_else(|| "SSH access changes require --write".into())
}

fn key_material(value: &str) -> Result<String, String> {
    let mut fields = value.split_whitespace();
    let kind = fields.next().ok_or("SSH public key has no algorithm")?;
    let body = fields.next().ok_or("SSH public key has no key material")?;
    Ok(format!("{kind} {body}"))
}

fn parse_duration(value: &str) -> Result<u64, String> {
    let split = value
        .find(|c: char| !c.is_ascii_digit())
        .ok_or_else(|| format!("duration `{value}` needs a suffix: s, m, h, or d"))?;
    let amount = value[..split]
        .parse::<u64>()
        .map_err(|_| format!("invalid duration `{value}`"))?;
    let factor = match &value[split..] {
        "s" => 1,
        "m" => 60,
        "h" => 3600,
        "d" => 86400,
        _ => return Err(format!("invalid duration suffix in `{value}`")),
    };
    amount
        .checked_mul(factor)
        .ok_or_else(|| format!("duration `{value}` is too large"))
}

fn now() -> Result<u64, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|e| format!("system clock: {e}"))
}

fn temporary_key_path(seed: &str) -> PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos());
    std::env::temp_dir().join(format!(
        "mycelium-ssh-{}-{nonce}-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed),
        Path::new(seed)
            .file_name()
            .and_then(|v| v.to_str())
            .unwrap_or("key")
    ))
}

/// Atomic installs must stage on the destination filesystem, not in `/tmp`.
/// Keep intermediate keys/configuration private and clean up every error path.
struct DestinationStaging {
    root: PathBuf,
    path: PathBuf,
}

impl Drop for DestinationStaging {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn destination_staging(destination: &Path) -> Result<DestinationStaging, String> {
    let parent = destination
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)
        .map_err(|error| format!("create staging parent {}: {error}", parent.display()))?;
    for _ in 0..16 {
        let name = temporary_key_path("staging")
            .file_name()
            .ok_or("temporary staging name missing")?
            .to_owned();
        let root = parent.join(name);
        let mut builder = fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        match builder.create(&root) {
            Ok(()) => {
                return Ok(DestinationStaging {
                    path: root.join("key.pub"),
                    root,
                })
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => {
                return Err(format!(
                    "create private staging {}: {error}",
                    root.display()
                ))
            }
        }
    }
    Err("cannot allocate unique private destination staging".into())
}

fn private_permissions(path: &Path, mode: u32) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(mode))
            .map_err(|error| format!("secure staging {}: {error}", path.display()))?;
    }
    #[cfg(not(unix))]
    let _ = (path, mode);
    Ok(())
}

fn command(program: &str, args: &[&str]) -> Result<(), String> {
    let output = Command::new(program)
        .args(args)
        .output()
        .map_err(|e| format!("run {program}: {e}"))?;
    if output.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();
    Err(format!("{program} failed ({}): {stderr}", output.status))
}

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    #[test]
    fn public_policy_directory_repairs_restrictive_mode_without_exposing_backups() {
        use std::os::unix::fs::PermissionsExt;
        let root = super::temporary_key_path("public-policy-test");
        super::fs::create_dir(&root).unwrap();
        let policy = root.join("mycelium");
        let principals = policy.join("principals");
        let backup = root.join("backup");
        for directory in [&policy, &principals, &backup] {
            super::fs::create_dir(directory).unwrap();
            super::fs::set_permissions(directory, super::fs::Permissions::from_mode(0o700))
                .unwrap();
        }
        assert!(!super::public_policy_directory_matches(&policy));
        assert!(!super::public_policy_directory_matches(&principals));
        super::public_policy_directory(&policy).unwrap();
        super::public_policy_directory(&principals).unwrap();
        for directory in [&policy, &principals] {
            assert!(super::public_policy_directory_matches(directory));
            assert_eq!(
                super::fs::metadata(directory).unwrap().permissions().mode() & 0o777,
                0o755
            );
        }
        assert_eq!(
            super::fs::metadata(&backup).unwrap().permissions().mode() & 0o777,
            0o700
        );
        super::fs::remove_dir_all(root).unwrap();
    }
    use super::*;

    #[test]
    fn destination_staging_is_private_unique_and_failure_preserves_output() {
        let base = temporary_key_path("destination-staging-test");
        fs::create_dir(&base).unwrap();
        let output = base.join("nested/certificate.pub");
        let first = destination_staging(&output).unwrap();
        let second = destination_staging(&output).unwrap();
        assert_eq!(first.root.parent(), output.parent());
        assert_ne!(first.root, second.root);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&first.root).unwrap().permissions().mode() & 0o777,
                0o700
            );
        }
        fs::write(&output, "existing certificate").unwrap();
        fs::write(&first.path, "failed staging").unwrap();
        let staging_root = first.root.clone();
        drop(first);
        assert!(!staging_root.exists());
        assert_eq!(fs::read_to_string(&output).unwrap(), "existing certificate");
        drop(second);
        fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn destination_staging_handles_relative_filename_output() {
        let staging = destination_staging(Path::new("certificate.pub")).unwrap();
        assert_eq!(staging.root.parent(), Some(Path::new(".")));
        let root = staging.root.clone();
        drop(staging);
        assert!(!root.exists());
    }

    #[test]
    fn ssh_policy_timer_schedules_after_late_install_or_restart() {
        assert!(SSH_POLICY_TIMER.contains("\nOnActiveSec=2m\n"));
        assert!(SSH_POLICY_TIMER.contains("\nOnUnitActiveSec=2m\n"));
        assert!(!SSH_POLICY_TIMER.contains("OnBootSec="));
    }

    #[test]
    fn krl_comparison_ignores_only_creation_time() {
        let mut original = b"SSHKRL\n\0\0\0\0\x01".to_vec();
        original.resize(44, 0);
        let mut later = original.clone();
        later[20..28].copy_from_slice(&1234u64.to_be_bytes());
        assert!(krl_bytes_match(&original, &later));
        for offset in (0..20).chain(28..original.len()) {
            let mut changed = later.clone();
            changed[offset] ^= 1;
            assert!(!krl_bytes_match(&original, &changed), "offset {offset}");
        }
        assert!(!krl_bytes_match(&original[..28], &later[..28]));
        let mut extended = later.clone();
        extended.push(1);
        assert!(!krl_bytes_match(&original, &extended));
    }

    #[test]
    fn krl_comparison_validates_format_and_detects_revocation_changes() {
        let root =
            std::env::temp_dir().join(format!("mycelium-krl-compare-{}", std::process::id()));
        fs::create_dir_all(&root).unwrap();
        let ca = root.join("ca");
        command(
            "ssh-keygen",
            &["-q", "-t", "ed25519", "-N", "", "-f", ca.to_str().unwrap()],
        )
        .unwrap();
        let desired = root.join("desired.krl");
        let current = root.join("current.krl");
        let args = vec![
            "--ca-public".into(),
            ca.with_extension("pub").to_string_lossy().into_owned(),
            "--path".into(),
            desired.to_string_lossy().into_owned(),
            "--write".into(),
        ];
        krl(&args, &serde_json::json!({"grants":[], "revocations":[]})).unwrap();
        let mut bytes = fs::read(&desired).unwrap();
        bytes[20..28].copy_from_slice(&1u64.to_be_bytes());
        fs::write(&current, &bytes).unwrap();
        assert!(krl_files_match(&desired, &current).unwrap());
        assert!(!krl_files_match(&desired, &root.join("missing")).unwrap());
        fs::remove_file(&desired).unwrap();
        krl(
            &args,
            &serde_json::json!({"grants":[], "revocations":[{"statement":{"serial":42}}]}),
        )
        .unwrap();
        assert!(!krl_files_match(&desired, &current).unwrap());
        // A matching malformed body is not evidence of convergence.
        bytes.push(1);
        fs::write(&desired, &bytes).unwrap();
        fs::write(&current, &bytes).unwrap();
        assert!(!krl_files_match(&desired, &current).unwrap());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn durations_are_explicit_and_bounded() {
        assert_eq!(parse_duration("8h").unwrap(), 28_800);
        assert_eq!(parse_duration("15m").unwrap(), 900);
        assert!(parse_duration("8").is_err());
        assert!(parse_duration("1fortnight").is_err());
    }

    #[test]
    fn comments_do_not_change_key_identity() {
        assert_eq!(
            key_material("ssh-ed25519 AAAA alice").unwrap(),
            "ssh-ed25519 AAAA"
        );
    }

    #[test]
    fn host_bundle_validation_requires_the_complete_contract() {
        let root = std::env::temp_dir().join(format!(
            "mycelium-host-bundle-test-{}-{}",
            std::process::id(),
            now().unwrap()
        ));
        fs::create_dir_all(&root).unwrap();
        assert!(validate_host_bundle(&root)
            .unwrap_err()
            .contains("user_ca.pub"));
        for name in [
            "user_ca.pub",
            "revoked.krl",
            "60-mycelium-access.conf",
            "manifest.json",
        ] {
            fs::write(root.join(name), "test").unwrap();
        }
        fs::create_dir(root.join("principals")).unwrap();
        validate_host_bundle(&root).unwrap();
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn host_bundle_maps_roles_and_defaults_to_no_certificate_principals() {
        let root = std::env::temp_dir().join(format!(
            "mycelium-host-role-test-{}-{}",
            std::process::id(),
            now().unwrap()
        ));
        fs::create_dir_all(&root).unwrap();
        let ca = root.join("ca.pub");
        let krl = root.join("revoked.krl");
        fs::write(&ca, "ssh-ed25519 AAAA test").unwrap();
        fs::write(&krl, "krl").unwrap();
        let denied = root.join("denied");
        let empty_state = serde_json::json!({"grants": []});
        let error = host_bundle(
            &[
                "--ca-public".into(),
                ca.to_string_lossy().into_owned(),
                "--krl".into(),
                krl.to_string_lossy().into_owned(),
                "--path".into(),
                denied.to_string_lossy().into_owned(),
                "--write".into(),
            ],
            &empty_state,
        )
        .unwrap_err();
        assert!(error.contains("at least one resolved"));
        assert!(!denied.exists());

        let allowed = root.join("allowed");
        host_bundle(
            &[
                "--ca-public".into(),
                ca.to_string_lossy().into_owned(),
                "--krl".into(),
                krl.to_string_lossy().into_owned(),
                "--allow".into(),
                "mames=home-operator".into(),
                "--path".into(),
                allowed.to_string_lossy().into_owned(),
                "--write".into(),
            ],
            &empty_state,
        )
        .unwrap();
        assert_eq!(
            fs::read_to_string(allowed.join("principals/mames")).unwrap(),
            "mycelium-role-home-operator\n"
        );
        let manifest = load_host_manifest(&allowed).unwrap();
        assert_eq!(
            manifest.accounts,
            vec![HostAccountIntent {
                name: "mames".into(),
                state: "present".into(),
                password_locked: true,
                supplementary_groups: Vec::new(),
            }]
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn active_grants_derive_personal_accounts_for_selected_roles() {
        let state = serde_json::json!({
            "grants": [
                {"active": true, "record": {"statement": {
                    "kind": "grant", "grant_id": "avery", "principal": "ajmwagar",
                    "serial": 1, "roles": ["fleet-admin"], "unix_users": ["ajmwagar"],
                    "not_before": 1, "not_after": 9999999999u64
                }}},
                {"active": true, "record": {"statement": {
                    "kind": "grant", "grant_id": "james", "principal": "mames",
                    "serial": 2, "roles": ["home-operator"], "unix_users": ["mames"],
                    "not_before": 1, "not_after": 9999999999u64
                }}}
            ]
        });
        let args = vec![
            "--from-access".into(),
            "--role".into(),
            "home-operator".into(),
        ];
        assert_eq!(
            role_mappings(&args, &state).unwrap(),
            BTreeMap::from([("mames".into(), BTreeSet::from(["home-operator".into()]))])
        );
    }

    #[test]
    fn host_policy_distinguishes_unconverged_from_intentionally_empty_access() {
        let empty = serde_json::json!({"grants": [], "revocations": []});
        assert!(!access_view_has_evidence(&empty));

        let revoked = serde_json::json!({
            "grants": [{
                "active": false,
                "record": {"statement": {
                    "kind": "grant", "grant_id": "james", "principal": "mames",
                    "serial": 2, "roles": ["home-operator"], "unix_users": ["mames"],
                    "not_before": 1, "not_after": 9999999999u64
                }},
                "revoked_by": ["revoke-james"]
            }],
            "revocations": [{"record": {"statement": {
                "kind": "revoke", "revocation_id": "revoke-james",
                "grant_ids": ["james"], "principals": [], "serials": [],
                "not_before": 1
            }}}]
        });
        assert!(access_view_has_evidence(&revoked));
        assert!(mappings_for_roles(&["home-operator".into()], &revoked)
            .unwrap()
            .is_empty());
    }

    #[test]
    fn ssh_profile_requires_a_personal_non_root_default() {
        let valid = SshClientProfile {
            version: 1,
            principal: "ajmwagar".into(),
            default_unix_user: "ajmwagar".into(),
            unix_users: vec!["ajmwagar".into(), "fpladmin".into()],
            roles: vec!["fleet-admin".into()],
        };
        validate_profile(&valid).unwrap();
        let mut invalid = valid;
        invalid.default_unix_user = "root".into();
        assert!(validate_profile(&invalid).is_err());
    }

    #[test]
    fn client_config_is_scoped_to_one_alias() {
        let root = std::env::temp_dir().join(format!(
            "mycelium-ssh-config-test-{}-{}",
            std::process::id(),
            now().unwrap()
        ));
        let path = root.join("buddy.conf");
        let args = vec![
            "client-config",
            "--host",
            "mycelium-lab",
            "--hostname",
            "lab.example.test",
            "--user",
            "buddy",
            "--identity",
            "~/.ssh/id_ed25519",
            "--certificate",
            "~/.ssh/id_ed25519-cert.pub",
            "--port",
            "2222",
            "--path",
            path.to_str().unwrap(),
            "--write",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect::<Vec<_>>();
        client_config(&args).unwrap();
        let config = fs::read_to_string(&path).unwrap();
        assert!(config.contains("Host mycelium-lab\n"));
        assert!(config.contains("HostName lab.example.test\n"));
        assert!(config.contains("User buddy\n"));
        assert!(config.contains("Port 2222\n"));
        assert!(config.contains("CertificateFile ~/.ssh/id_ed25519-cert.pub\n"));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn invitation_issues_a_bounded_openssh_certificate() {
        if Command::new("ssh-keygen").arg("-h").output().is_err() {
            return;
        }
        let root = std::env::temp_dir().join(format!(
            "mycelium-invite-ssh-test-{}-{}",
            std::process::id(),
            now().unwrap()
        ));
        fs::create_dir_all(&root).unwrap();
        let ca = root.join("ca");
        let user = root.join("user");
        let certificate = root.join("user-cert.pub");
        for key in [&ca, &user] {
            command(
                "ssh-keygen",
                &[
                    "-q",
                    "-t",
                    "ed25519",
                    "-N",
                    "",
                    "-f",
                    path_str(key).unwrap(),
                ],
            )
            .unwrap();
        }
        issue_for_invite(
            &user.with_extension("pub"),
            &ca,
            &certificate,
            "invite-1",
            "buddy",
            42,
            &["operator".into()],
            &["home-operator".into()],
            3600,
        )
        .unwrap();
        let inspected = Command::new("ssh-keygen")
            .args(["-L", "-f"])
            .arg(&certificate)
            .output()
            .unwrap();
        let output = String::from_utf8_lossy(&inspected.stdout);
        assert!(inspected.status.success());
        assert!(output.contains("mycelium-role-home-operator"));
        assert!(output.contains("mycelium:invite:invite-1:buddy"));
        assert!(output.contains("operator"));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn openssh_issues_and_revokes_a_granted_key() {
        if Command::new("ssh-keygen").arg("-h").output().is_err() {
            return;
        }
        let root = std::env::temp_dir().join(format!(
            "mycelium-ssh-test-{}-{}",
            std::process::id(),
            now().unwrap()
        ));
        fs::create_dir_all(&root).unwrap();
        let ca = root.join("ca");
        let user = root.join("user");
        let cert = root.join("user-cert.pub");
        command(
            "ssh-keygen",
            &["-q", "-t", "ed25519", "-N", "", "-f", ca.to_str().unwrap()],
        )
        .unwrap();
        command(
            "ssh-keygen",
            &[
                "-q",
                "-t",
                "ed25519",
                "-N",
                "",
                "-f",
                user.to_str().unwrap(),
            ],
        )
        .unwrap();
        let public_key = fs::read_to_string(user.with_extension("pub")).unwrap();
        let timestamp = now().unwrap();
        let mut state = serde_json::json!({
            "grants": [{
                "active": true,
                "revoked_by": [],
                "record": { "statement": {
                    "kind": "grant", "grant_id": "grant-1", "principal": "oidc:https://issuer.example#user-42",
                    "serial": 42, "roles": ["network-admin"], "scopes": ["site:home"], "unix_users": ["avery"],
                    "ssh_public_keys": [public_key], "oidc_audiences": ["mycelium"],
                    "oidc_ssh_key_exchange": false,
                    "not_before": timestamp - 1, "not_after": timestamp + 3600
                }}
            }],
            "revocations": []
        });
        let issue_args = vec![
            "issue",
            "--grant",
            "grant-1",
            "--public-key",
            user.with_extension("pub").to_str().unwrap(),
            "--ca",
            ca.to_str().unwrap(),
            "--path",
            cert.to_str().unwrap(),
            "--ttl",
            "10m",
            "--write",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect::<Vec<_>>();
        issue(&issue_args, &state).unwrap();
        assert!(cert.exists());
        let inspected = Command::new("ssh-keygen")
            .args(["-L", "-f"])
            .arg(&cert)
            .output()
            .unwrap();
        let inspected = String::from_utf8_lossy(&inspected.stdout);
        assert!(inspected.contains("mycelium-role-network-admin"));
        assert!(!inspected.lines().any(|line| line.trim() == "avery"));
        let oidc_cert = root.join("oidc-user-cert.pub");
        let oidc_args = vec![
            "ssh-issue",
            "--public-key",
            user.with_extension("pub").to_str().unwrap(),
            "--ca",
            ca.to_str().unwrap(),
            "--path",
            oidc_cert.to_str().unwrap(),
            "--ttl",
            "10m",
            "--write",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect::<Vec<_>>();
        let issued = issue_for_oidc(
            &oidc_args,
            &state,
            "oidc:https://issuer.example#user-42",
            "mycelium",
            timestamp + 300,
        )
        .unwrap();
        assert!(oidc_cert.exists());
        assert!(
            issued[0].contains("ttl=600s"),
            "the exchanged SSH credential must not inherit the JWT's remaining 300 seconds"
        );

        let mut wrong_principal_args = oidc_args.clone();
        wrong_principal_args.extend(["--grant".into(), "grant-1".into()]);
        assert!(issue_for_oidc(
            &wrong_principal_args,
            &state,
            "oidc:https://issuer.example#someone-else",
            "mycelium",
            timestamp + 300,
        )
        .unwrap_err()
        .contains("not authenticated principal"));
        assert!(issue_for_oidc(
            &wrong_principal_args,
            &state,
            "oidc:https://issuer.example#user-42",
            "some-other-client",
            timestamp + 300,
        )
        .unwrap_err()
        .contains("does not authorize OIDC audience"));
        state["grants"][0]["active"] = serde_json::json!(false);
        state["grants"][0]["revoked_by"] = serde_json::json!(["revoke-1"]);
        state["revocations"] = serde_json::json!([{
            "statement": { "kind": "revoke", "revocation_id": "revoke-1", "grant_id": "grant-1", "revoked_at": timestamp, "reason": "test" }
        }]);
        let krl_path = root.join("revoked.krl");
        let krl_args = vec![
            "krl",
            "--ca-public",
            ca.with_extension("pub").to_str().unwrap(),
            "--path",
            krl_path.to_str().unwrap(),
            "--write",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect::<Vec<_>>();
        krl(&krl_args, &state).unwrap();
        let query = Command::new("ssh-keygen")
            .args([
                "-Q",
                "-f",
                krl_path.to_str().unwrap(),
                cert.to_str().unwrap(),
            ])
            .output()
            .unwrap();
        assert!(
            !query.status.success(),
            "certificate serial 42 should be revoked"
        );
        fs::remove_dir_all(root).unwrap();
    }

    fn signed_record(statement: serde_json::Value) -> serde_json::Value {
        let key = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let statement: AccessStatement = serde_json::from_value(statement).unwrap();
        serde_json::to_value(AccessRecord::sign(&key, statement).unwrap()).unwrap()
    }

    fn directory_state(grants: &[(bool, serde_json::Value)]) -> serde_json::Value {
        serde_json::json!({
            "grants": grants
                .iter()
                .map(|(active, statement)| serde_json::json!({
                    "active": active,
                    "record": signed_record(statement.clone()),
                }))
                .collect::<Vec<_>>(),
            "revocations": []
        })
    }

    fn grant(id: &str, principal: &str, roles: &[&str], users: &[&str]) -> serde_json::Value {
        serde_json::json!({
            "kind": "grant",
            "grant_id": id,
            "principal": principal,
            "serial": 1,
            "roles": roles,
            "unix_users": users,
            "not_before": 1,
            "not_after": 9_999_999_999u64
        })
    }

    fn directory_target(id: &str, accounts: &[(&str, &[&str])]) -> SshDirectoryTarget {
        SshDirectoryTarget {
            id: id.to_owned(),
            label: None,
            kind: None,
            site: None,
            accounts: accounts
                .iter()
                .map(|(account, roles)| {
                    (
                        (*account).to_owned(),
                        roles.iter().map(|role| (*role).to_owned()).collect(),
                    )
                })
                .collect(),
        }
    }

    fn directory_inventory(targets: Vec<SshDirectoryTarget>) -> SshDirectoryInventory {
        SshDirectoryInventory {
            version: 1,
            targets,
        }
    }

    #[test]
    fn directory_lists_only_targets_the_principal_can_reach() {
        let state = directory_state(&[(
            true,
            grant(
                "avery",
                "ajmwagar",
                &["network-admin", "home-operator"],
                &["ajmwagar"],
            ),
        )]);
        let inventory = directory_inventory(vec![
            directory_target("batty", &[("mames", &["home-operator"])]),
            directory_target("agora-one", &[("ajmwagar", &["network-admin"])]),
            directory_target("pris", &[("ajmwagar", &["network-admin", "home-operator"])]),
        ]);
        let (held, unverified) = held_grants(&state, "ajmwagar", now().unwrap()).unwrap();
        let view = directory_view("ajmwagar", &held, &inventory, false, unverified);
        assert_eq!(view.roles, vec!["home-operator", "network-admin"]);
        assert_eq!(
            view.targets
                .iter()
                .map(|t| t.id.as_str())
                .collect::<Vec<_>>(),
            vec!["agora-one", "pris"]
        );
        assert!(view.targets.iter().all(|target| target.shell));
        assert_eq!(
            view.targets[1].roles,
            vec!["home-operator", "network-admin"]
        );
        assert_eq!(view.targets[0].accounts, vec!["ajmwagar"]);
    }

    #[test]
    fn directory_hides_targets_whose_account_the_grant_does_not_name() {
        let state = directory_state(&[(
            true,
            grant("avery", "ajmwagar", &["network-admin"], &["ajmwagar"]),
        )]);
        let inventory = directory_inventory(vec![directory_target(
            "batty",
            &[("mames", &["network-admin"])],
        )]);
        let (held, unverified) = held_grants(&state, "ajmwagar", now().unwrap()).unwrap();
        assert!(
            directory_view("ajmwagar", &held, &inventory, false, unverified)
                .targets
                .is_empty()
        );

        let (held, _) = held_grants(&state, "ajmwagar", now().unwrap()).unwrap();
        let all = directory_view("ajmwagar", &held, &inventory, true, Vec::new());
        assert_eq!(all.targets.len(), 1);
        assert!(!all.targets[0].shell);
    }

    #[test]
    fn directory_ignores_expired_inactive_and_foreign_grants() {
        let expired = serde_json::json!({
            "kind": "grant", "grant_id": "old", "principal": "ajmwagar", "serial": 1,
            "roles": ["network-admin"], "unix_users": ["ajmwagar"],
            "not_before": 1, "not_after": 2
        });
        let state = directory_state(&[
            (
                false,
                grant("muted", "ajmwagar", &["network-admin"], &["ajmwagar"]),
            ),
            (true, expired),
            (
                true,
                grant("other", "mames", &["network-admin"], &["ajmwagar"]),
            ),
        ]);
        let inventory = directory_inventory(vec![directory_target(
            "agora-one",
            &[("ajmwagar", &["network-admin"])],
        )]);
        let (held, unverified) = held_grants(&state, "ajmwagar", now().unwrap()).unwrap();
        assert!(held.is_empty());
        assert!(unverified.is_empty());
        assert!(
            directory_view("ajmwagar", &held, &inventory, false, unverified)
                .targets
                .is_empty()
        );
    }

    #[test]
    fn directory_excludes_records_that_fail_their_signature() {
        let mut record = signed_record(grant(
            "forged",
            "ajmwagar",
            &["network-admin"],
            &["ajmwagar"],
        ));
        record["statement"]["roles"] = serde_json::json!(["fleet-admin"]);
        let state = serde_json::json!({"grants": [{"active": true, "record": record}]});
        let inventory = directory_inventory(vec![directory_target(
            "agora-one",
            &[("ajmwagar", &["fleet-admin"])],
        )]);
        let (held, unverified) = held_grants(&state, "ajmwagar", now().unwrap()).unwrap();
        assert!(held.is_empty());
        assert_eq!(unverified, vec!["forged"]);
        let view = directory_view("ajmwagar", &held, &inventory, false, unverified);
        assert!(view.targets.is_empty());
        assert_eq!(render_directory(&view)[1], "roles none (no active grant)");
    }

    #[test]
    fn directory_collect_accepts_only_role_principals() {
        assert_eq!(
            parse_role_principals(
                "ajmwagar",
                "mycelium-role-network-admin\nmycelium-role-home-operator\n"
            )
            .unwrap(),
            BTreeSet::from(["home-operator".to_owned(), "network-admin".to_owned()])
        );
        assert!(parse_role_principals("ajmwagar", "mycelium-role-network-admin\n").is_ok());
        assert!(parse_role_principals("ajmwagar", "somebody-else\n").is_err());
    }
}
