//! Generic desired software placement and safe binary activation.
//!
//! Package manifests authorize immutable bytes. Placement rules consume only
//! derived node facts. Activation is deliberately constrained to Mycelium's
//! own state directory; service lifecycle is a separate driver boundary.

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use mycelium_peer_protocol::{sha256_hex, HardwareKind, PackageManifest, Platform};
use serde::{Deserialize, Serialize};

use crate::peer::PeerView;

type AnyError = Box<dyn std::error::Error + Send + Sync>;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SoftwarePolicy {
    pub schema_version: u16,
    #[serde(default)]
    pub defaults: SoftwareDefaults,
    #[serde(default)]
    pub rules: Vec<PlacementRule>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SoftwareDefaults {
    #[serde(default)]
    pub updates: UpdatePolicy,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum UpdatePolicy {
    Manual,
    Automatic {
        #[serde(default = "default_minimum_age")]
        minimum_cache_age_secs: u64,
        #[serde(default = "default_rollout_window")]
        rollout_window_secs: u64,
        #[serde(default = "default_retry_backoff")]
        retry_backoff_secs: u64,
    },
}

impl Default for UpdatePolicy {
    fn default() -> Self {
        Self::Manual
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlacementRule {
    pub name: String,
    #[serde(default)]
    pub selector: FactSelector,
    pub packages: Vec<DesiredPackage>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FactSelector {
    /// Every fact must be present. Empty means every enrolled node.
    #[serde(default)]
    pub all: BTreeSet<String>,
    /// No listed fact may be present.
    #[serde(default)]
    pub none: BTreeSet<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DesiredPackage {
    pub name: String,
    #[serde(default = "default_channel")]
    pub channel: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updates: Option<UpdatePolicy>,
    /// Locally declared exact compatibility requirements, not publisher commands.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub requires: BTreeMap<String, String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct SoftwareAssignment {
    pub node_id: String,
    pub hostname: String,
    pub package: String,
    pub channel: String,
    pub updates: UpdatePolicy,
    pub rules: BTreeSet<String>,
    pub requires: BTreeMap<String, String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ActivatedPackage {
    pub name: String,
    pub version: String,
    pub target: String,
    pub digest: String,
    pub executable: PathBuf,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PackageState {
    AwaitingManifest,
    AwaitingArtifact,
    Ready,
    Current,
    Drifted,
    Updated,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackageStatus {
    pub package: String,
    pub channel: String,
    pub installed_version: Option<String>,
    pub desired_version: Option<String>,
    pub state: PackageState,
    pub updates: UpdatePolicy,
    /// Present only when observed installed bytes or a locally bound service drift.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub drift: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct AutomaticState {
    #[serde(default)]
    pub last_attempts: BTreeMap<String, u64>,
}

fn default_channel() -> String {
    "stable".into()
}

fn default_minimum_age() -> u64 {
    900
}
fn default_rollout_window() -> u64 {
    1800
}
fn default_retry_backoff() -> u64 {
    3600
}

pub fn read_policy(path: &Path) -> Result<SoftwarePolicy, AnyError> {
    let policy: SoftwarePolicy = serde_json::from_slice(&std::fs::read(path)?)?;
    policy.validate()?;
    Ok(policy)
}

pub fn write_policy(source: &Path) -> Result<SoftwarePolicy, AnyError> {
    let policy = read_policy(source)?;
    let destination = crate::software_policy_path();
    if let Some(parent) = destination.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let temporary = destination.with_extension("json.tmp");
    std::fs::write(&temporary, serde_json::to_vec_pretty(&policy)?)?;
    std::fs::rename(temporary, destination)?;
    Ok(policy)
}

impl SoftwarePolicy {
    pub fn validate(&self) -> Result<(), String> {
        if self.schema_version != 1 {
            return Err(format!(
                "unsupported software policy schema {}",
                self.schema_version
            ));
        }
        let mut names = BTreeSet::new();
        for rule in &self.rules {
            validate_label("rule", &rule.name)?;
            if !names.insert(rule.name.as_str()) {
                return Err(format!("duplicate software rule `{}`", rule.name));
            }
            if rule.packages.is_empty() {
                return Err(format!("software rule `{}` has no packages", rule.name));
            }
            if !rule.selector.all.is_disjoint(&rule.selector.none) {
                return Err(format!(
                    "software rule `{}` requires and excludes the same fact",
                    rule.name
                ));
            }
            for package in &rule.packages {
                validate_label("package", &package.name)?;
                validate_label("channel", &package.channel)?;
                for (dependency, version) in &package.requires {
                    validate_label("dependency", dependency)?;
                    validate_label("dependency version", version)?;
                    if dependency == &package.name {
                        return Err("package cannot depend on itself".into());
                    }
                }
                validate_update_policy(package.updates.as_ref().unwrap_or(&self.defaults.updates))?;
            }
        }
        Ok(())
    }
}

pub fn plan(
    policy: &SoftwarePolicy,
    peers: &[PeerView],
) -> Result<Vec<SoftwareAssignment>, String> {
    policy.validate()?;
    let mut assignments = BTreeMap::<(String, String), SoftwareAssignment>::new();
    for peer in peers {
        let Some(hello) = &peer.hello else { continue };
        let facts = facts(peer);
        for rule in &policy.rules {
            if !rule.selector.all.is_subset(&facts) || !rule.selector.none.is_disjoint(&facts) {
                continue;
            }
            for package in &rule.packages {
                let key = (hello.node_id.clone(), package.name.clone());
                let assignment = assignments
                    .entry(key)
                    .or_insert_with(|| SoftwareAssignment {
                        node_id: hello.node_id.clone(),
                        hostname: hello.hostname.clone(),
                        package: package.name.clone(),
                        channel: package.channel.clone(),
                        updates: package
                            .updates
                            .clone()
                            .unwrap_or_else(|| policy.defaults.updates.clone()),
                        rules: BTreeSet::new(),
                        requires: package.requires.clone(),
                    });
                if assignment.channel != package.channel {
                    return Err(format!(
                        "conflicting channels for package `{}` on `{}`: `{}` and `{}`",
                        package.name, hello.hostname, assignment.channel, package.channel
                    ));
                }
                if assignment.requires != package.requires {
                    return Err(format!(
                        "conflicting dependencies for package `{}`",
                        package.name
                    ));
                }
                let updates = package
                    .updates
                    .clone()
                    .unwrap_or_else(|| policy.defaults.updates.clone());
                if assignment.updates != updates {
                    return Err(format!(
                        "conflicting update policies for package `{}` on `{}`",
                        package.name, hello.hostname
                    ));
                }
                assignment.rules.insert(rule.name.clone());
            }
        }
    }
    Ok(assignments.into_values().collect())
}

pub fn facts(peer: &PeerView) -> BTreeSet<String> {
    let mut facts = BTreeSet::new();
    let Some(hello) = &peer.hello else {
        return facts;
    };
    facts.insert(format!("platform.{}", platform_name(&hello.platform)));
    facts.insert(format!("arch.{}", hello.architecture));
    facts.insert(format!("site.{}", hello.site));
    facts.insert(format!("host.{}", hello.hostname));
    // Package assignment survives a hostname change.
    facts.insert(format!("node.{}", hello.node_id));
    facts.extend(hello.capabilities.iter().cloned());
    if let Some(snapshot) = &peer.hardware {
        for device in &snapshot.devices {
            facts.extend(device.capabilities.iter().cloned());
            if matches!(device.kind, HardwareKind::Accelerator) {
                facts.insert("resource.gpu".into());
            }
        }
    }
    facts
}

pub fn select<'a>(
    manifests: &'a [PackageManifest],
    name: &str,
    channel: &str,
    targets: &[String],
) -> Option<&'a PackageManifest> {
    manifests
        .iter()
        .filter(|item| {
            item.name == name && item.channel == channel && targets.contains(&item.target)
        })
        .max_by(|left, right| {
            compare_versions(&left.version, &right.version).then_with(|| {
                let preference = |item: &PackageManifest| {
                    targets
                        .iter()
                        .position(|target| target == &item.target)
                        .map(|index| targets.len() - index)
                        .unwrap_or_default()
                };
                preference(left).cmp(&preference(right))
            })
        })
}

pub fn reconcile(
    assignments: &[SoftwareAssignment],
    manifests: &[PackageManifest],
    targets: &[String],
    write: bool,
) -> Result<Vec<PackageStatus>, AnyError> {
    let ordered = dependency_order(assignments)?;
    if write {
        for assignment in &ordered {
            let directory = crate::software_dir().join(&assignment.package);
            if std::fs::symlink_metadata(directory.join("activation-pending.json")).is_ok() {
                let _lock = activation_lock(&directory)?;
                let binding = crate::software_service::binding(&assignment.package)?;
                recover_activation(
                    &directory,
                    &assignment.package,
                    binding
                        .as_ref()
                        .map(|binding| binding as &dyn crate::software_service::Lifecycle),
                )?;
            }
        }
    }
    // A dependent update set must be fully staged before touching any member.
    // Exact requirements intentionally fail rather than guessing ABI compatibility.
    let linked = linked_packages(assignments);
    if !linked.is_empty() {
        let mut changing = 0;
        for assignment in &ordered {
            if !linked.contains(&assignment.package) {
                continue;
            }
            let manifest = select(manifests, &assignment.package, &assignment.channel, targets)
                .ok_or_else(|| format!("update set lacks manifest for {}", assignment.package))?;
            manifest.verify()?;
            check_required_versions(assignment, &ordered, manifests, targets)?;
            let bytes = std::fs::read(crate::artifacts_dir().join(&manifest.artifact_digest))
                .map_err(|error| {
                    format!("update set not fully staged: {}: {error}", manifest.name)
                })?;
            if bytes.len() as u64 != manifest.artifact_size
                || sha256_hex(&bytes) != manifest.artifact_digest
            {
                return Err("update set contains corrupt cached bytes".into());
            }
            if write {
                let binding = crate::software_service::binding(&manifest.name)?.ok_or(
                    "dependent update set requires native health bindings for every member",
                )?;
                if current_health(manifest, &crate::software_dir(), Some(&binding)).is_err() {
                    changing += 1;
                }
            }
        }
        // Do not ship a partial cross-package rollback boundary. A single
        // changed member uses the qualified transaction; multiple changes need
        // a durable whole-set transaction, not a sequence of happy-path updates.
        if write {
            admit_linked_changes(changing)?;
        }
    }
    let mut statuses = Vec::new();
    for assignment in ordered {
        let installed_version = installed_version(&assignment.package);
        let Some(manifest) = select(manifests, &assignment.package, &assignment.channel, targets)
        else {
            statuses.push(status(
                assignment,
                installed_version,
                None,
                PackageState::AwaitingManifest,
            ));
            continue;
        };
        if installed_version.as_deref() == Some(manifest.version.as_str()) {
            let binding = crate::software_service::binding(&manifest.name)?;
            let health = current_health(
                manifest,
                &crate::software_dir(),
                binding
                    .as_ref()
                    .map(|binding| binding as &dyn crate::software_service::Lifecycle),
            );
            let mut observed = status(
                assignment,
                installed_version.clone(),
                Some(manifest.version.clone()),
                if health.is_ok() {
                    PackageState::Current
                } else {
                    PackageState::Drifted
                },
            );
            observed.drift = health.err().map(|error| error.to_string());
            if !write || observed.drift.is_none() {
                statuses.push(observed);
                continue;
            }
        }
        if !crate::artifacts_dir()
            .join(&manifest.artifact_digest)
            .is_file()
        {
            statuses.push(status(
                assignment,
                installed_version,
                Some(manifest.version.clone()),
                PackageState::AwaitingArtifact,
            ));
            continue;
        }
        if write {
            if matches!(assignment.updates, UpdatePolicy::Automatic { .. })
                && crate::software_service::binding(&manifest.name)?.is_none()
            {
                return Err(format!("automatic package {} has no locally authorized health/rollback service binding", manifest.name).into());
            }
            activate(manifest)?;
        }
        statuses.push(status(
            assignment,
            installed_version,
            Some(manifest.version.clone()),
            if write {
                PackageState::Updated
            } else {
                PackageState::Ready
            },
        ));
    }
    if write {
        write_statuses(&statuses)?;
    }
    Ok(statuses)
}

fn admit_linked_changes(changing: usize) -> Result<(), AnyError> {
    if changing > 1 {
        return Err(
            "linked update set changes multiple packages; whole-set rollback is not yet qualified"
                .into(),
        );
    }
    Ok(())
}

fn linked_packages(assignments: &[SoftwareAssignment]) -> BTreeSet<String> {
    let mut linked = BTreeSet::new();
    for assignment in assignments {
        if !assignment.requires.is_empty() {
            linked.insert(assignment.package.clone());
            linked.extend(assignment.requires.keys().cloned());
        }
    }
    linked
}

fn check_required_versions(
    assignment: &SoftwareAssignment,
    ordered: &[&SoftwareAssignment],
    manifests: &[PackageManifest],
    targets: &[String],
) -> Result<(), AnyError> {
    for (name, version) in &assignment.requires {
        let dependency = ordered
            .iter()
            .find(|item| item.package == *name)
            .ok_or_else(|| format!("dependency {name} is not assigned on this node"))?;
        let selected = select(manifests, name, &dependency.channel, targets)
            .ok_or_else(|| format!("update set lacks dependency {name}"))?;
        if selected.version != *version {
            return Err(format!(
                "{} requires {name}={version}, selected {}",
                assignment.package, selected.version
            )
            .into());
        }
    }
    Ok(())
}

fn dependency_order(
    assignments: &[SoftwareAssignment],
) -> Result<Vec<&SoftwareAssignment>, AnyError> {
    let mut pending = BTreeMap::new();
    for assignment in assignments {
        if assignments
            .first()
            .is_some_and(|first| first.node_id != assignment.node_id)
        {
            return Err("reconcile cannot mix nodes".into());
        }
        if pending
            .insert(assignment.package.clone(), assignment)
            .is_some()
        {
            return Err("reconcile requires one node and unique package assignments".into());
        }
    }
    for assignment in assignments {
        for name in assignment.requires.keys() {
            if !pending.contains_key(name) {
                return Err(format!("dependency {name} is not assigned on this node").into());
            }
        }
    }
    let mut ordered = Vec::new();
    let mut done = BTreeSet::new();
    while !pending.is_empty() {
        let name = pending
            .iter()
            .find(|(_, item)| item.requires.keys().all(|name| done.contains(name)))
            .map(|(name, _)| name.clone())
            .ok_or("cyclic package dependencies")?;
        ordered.push(pending.remove(&name).unwrap());
        done.insert(name);
    }
    Ok(ordered)
}

fn status(
    assignment: &SoftwareAssignment,
    installed_version: Option<String>,
    desired_version: Option<String>,
    state: PackageState,
) -> PackageStatus {
    PackageStatus {
        package: assignment.package.clone(),
        channel: assignment.channel.clone(),
        installed_version,
        desired_version,
        state,
        updates: assignment.updates.clone(),
        drift: None,
    }
}

/// "Current" means immutable signed bytes match, and any locally authorized
/// native service passes a PID-bound readiness observation. This never starts
/// services; reconcile --write reuses the existing activation/rollback boundary.
fn current_health(
    manifest: &PackageManifest,
    software: &Path,
    lifecycle: Option<&dyn crate::software_service::Lifecycle>,
) -> Result<(), AnyError> {
    manifest
        .verify()
        .map_err(|error| format!("package signature: {error}"))?;
    validate_label("package", &manifest.name)?;
    validate_label("version", &manifest.version)?;
    if std::fs::symlink_metadata(
        software
            .join(&manifest.name)
            .join("activation-pending.json"),
    )
    .is_ok()
    {
        return Err("interrupted activation requires explicit recovery".into());
    }
    let current = software.join(&manifest.name).join("current");
    if std::fs::read_link(&current)? != Path::new("releases").join(&manifest.version) {
        return Err("current package link is not the desired internal release".into());
    }
    let executable = current.join(&manifest.name);
    let bytes = std::fs::read(&executable)?;
    if bytes.len() as u64 != manifest.artifact_size
        || sha256_hex(&bytes) != manifest.artifact_digest
    {
        return Err("installed package bytes do not match signed manifest".into());
    }
    if let Some(lifecycle) = lifecycle {
        lifecycle.preflight(&executable)?;
        lifecycle.check(&manifest.artifact_digest)?;
    }
    Ok(())
}

fn installed_version(name: &str) -> Option<String> {
    std::fs::read_link(crate::software_dir().join(name).join("current"))
        .ok()
        .and_then(|path| {
            path.file_name()
                .map(|value| value.to_string_lossy().into_owned())
        })
}

fn write_statuses(statuses: &[PackageStatus]) -> Result<(), AnyError> {
    let path = crate::software_state_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let temporary = path.with_extension("json.tmp");
    std::fs::write(&temporary, serde_json::to_vec_pretty(statuses)?)?;
    std::fs::rename(temporary, path)?;
    Ok(())
}

pub fn persist_statuses(statuses: &[PackageStatus]) -> Result<(), AnyError> {
    write_statuses(statuses)
}

pub fn read_statuses() -> Vec<PackageStatus> {
    std::fs::read(crate::software_state_path())
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .unwrap_or_default()
}

pub fn automatic_assignments(
    assignments: Vec<SoftwareAssignment>,
    manifests: &[PackageManifest],
    targets: &[String],
    node_id: &str,
    now: u64,
    state: &mut AutomaticState,
) -> Vec<SoftwareAssignment> {
    // Until update-set rollback is qualified, dependency-linked components are
    // explicit reconcile only. Do not let filtering split a provider from its
    // dependent and accidentally bypass compatibility admission.
    let linked = linked_packages(&assignments);
    assignments
        .into_iter()
        .filter(|assignment| {
            if linked.contains(&assignment.package) {
                return false;
            }
            let UpdatePolicy::Automatic {
                minimum_cache_age_secs,
                rollout_window_secs,
                retry_backoff_secs,
            } = assignment.updates
            else {
                return false;
            };
            let Some(installed) = installed_version(&assignment.package) else {
                return false;
            };
            let Some(manifest) =
                select(manifests, &assignment.package, &assignment.channel, targets)
            else {
                return false;
            };
            match compare_versions(&manifest.version, &installed) {
                Ordering::Less => return false,
                Ordering::Equal => {
                    let binding = match crate::software_service::binding(&manifest.name) {
                        Ok(Some(binding)) => binding,
                        // Unbound packages do not authorize service repair.
                        _ => return false,
                    };
                    if current_health(manifest, &crate::software_dir(), Some(&binding)).is_ok() {
                        return false;
                    }
                }
                Ordering::Greater => {}
            }
            let Ok(metadata) =
                std::fs::metadata(crate::artifacts_dir().join(&manifest.artifact_digest))
            else {
                return false;
            };
            let cached_at = metadata
                .modified()
                .ok()
                .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|value| value.as_secs())
                .unwrap_or(now);
            let digest = sha256_hex(format!("{node_id}\0{}", assignment.package).as_bytes());
            let offset =
                u64::from_str_radix(&digest[..16], 16).unwrap_or_default() % rollout_window_secs;
            let eligible_at = cached_at
                .saturating_add(minimum_cache_age_secs)
                .saturating_add(offset);
            let retry_at = state
                .last_attempts
                .get(&assignment.package)
                .copied()
                .unwrap_or_default()
                .saturating_add(retry_backoff_secs);
            if now < eligible_at || now < retry_at {
                return false;
            }
            state.last_attempts.insert(assignment.package.clone(), now);
            true
        })
        .collect()
}

pub fn read_automatic_state() -> AutomaticState {
    std::fs::read(crate::software_automatic_state_path())
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .unwrap_or_default()
}

pub fn write_automatic_state(state: &AutomaticState) -> Result<(), AnyError> {
    let path = crate::software_automatic_state_path();
    let temporary = path.with_extension("json.tmp");
    std::fs::write(&temporary, serde_json::to_vec_pretty(state)?)?;
    std::fs::rename(temporary, path)?;
    Ok(())
}

fn compare_versions(left: &str, right: &str) -> Ordering {
    let numeric = |value: &str| {
        value
            .split('.')
            .map(str::parse::<u64>)
            .collect::<Result<Vec<_>, _>>()
    };
    match (numeric(left), numeric(right)) {
        (Ok(left), Ok(right)) => left.cmp(&right),
        _ => left.cmp(right),
    }
}

pub fn activate(manifest: &PackageManifest) -> Result<ActivatedPackage, AnyError> {
    validate_label("package", &manifest.name)?;
    let binding = crate::software_service::binding(&manifest.name)?;
    let result = activate_transaction(
        manifest,
        &crate::artifacts_dir(),
        &crate::software_dir(),
        binding
            .as_ref()
            .map(|binding| binding as &dyn crate::software_service::Lifecycle),
    );
    let directory = crate::software_dir().join(&manifest.name);
    std::fs::create_dir_all(&directory)?;
    let temporary = directory.join(".last-activation.tmp");
    std::fs::write(
        &temporary,
        serde_json::to_vec_pretty(&serde_json::json!({
            "version": manifest.version, "digest": manifest.artifact_digest,
            "verified_service": binding.is_some() && result.is_ok(),
            "error": result.as_ref().err().map(ToString::to_string)
        }))?,
    )?;
    std::fs::rename(temporary, directory.join("last-activation.json"))?;
    result
}

#[cfg(test)]
fn activate_from(
    manifest: &PackageManifest,
    artifacts: &Path,
    software: &Path,
) -> Result<ActivatedPackage, AnyError> {
    activate_transaction(manifest, artifacts, software, None)
}

/// Reuse checked activation and rollback with caller-owned roots. Privileged
/// callers must first authorize the signer and protect both directories.
pub fn activate_in(manifest: &PackageManifest, artifacts: &Path, software: &Path, lifecycle: Option<&dyn crate::software_service::Lifecycle>) -> Result<ActivatedPackage, AnyError> {
    activate_transaction(manifest,artifacts,software,lifecycle)
}

pub fn recover_in(name: &str, software: &Path, lifecycle: &dyn crate::software_service::Lifecycle) -> Result<(), AnyError> {
    validate_label("package",name)?;
    let directory = software.join(name);
    if !directory.exists() {return Ok(());}
    let _lock = activation_lock(&directory)?;
    recover_activation(&directory,name,Some(lifecycle))
}

fn activate_transaction(
    manifest: &PackageManifest,
    artifacts: &Path,
    software: &Path,
    lifecycle: Option<&dyn crate::software_service::Lifecycle>,
) -> Result<ActivatedPackage, AnyError> {
    manifest
        .verify()
        .map_err(|error| format!("package signature: {error}"))?;
    validate_label("package", &manifest.name)?;
    validate_label("version", &manifest.version)?;
    let package_dir = software.join(&manifest.name);
    std::fs::create_dir_all(&package_dir)?;
    let _lock = activation_lock(&package_dir)?;
    recover_activation(&package_dir, &manifest.name, lifecycle)?;
    let current = package_dir.join("current");
    let previous = match std::fs::read_link(&current) {
        Ok(previous) => Some(previous),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => return Err(error.into()),
    };
    if let Some(previous) = &previous {
        let components: Vec<_> = previous.components().collect();
        if components.len() != 2
            || components[0].as_os_str() != "releases"
            || !matches!(components[1], std::path::Component::Normal(_))
        {
            return Err("current package link is not an internal release".into());
        }
    }
    let artifact = artifacts.join(&manifest.artifact_digest);
    let bytes = std::fs::read(&artifact).map_err(|error| {
        format!(
            "package artifact {} is not cached: {error}",
            manifest.artifact_digest
        )
    })?;
    if bytes.len() as u64 != manifest.artifact_size
        || sha256_hex(&bytes) != manifest.artifact_digest
    {
        return Err("cached package artifact does not match signed manifest".into());
    }
    let release_dir = software
        .join(&manifest.name)
        .join("releases")
        .join(&manifest.version);
    std::fs::create_dir_all(&release_dir)?;
    let executable = release_dir.join(&manifest.name);
    if executable.exists() {
        if sha256_hex(&std::fs::read(&executable)?) != manifest.artifact_digest {
            return Err(
                "refusing to overwrite an immutable package version with different bytes".into(),
            );
        }
    } else {
        let temporary = release_dir.join(format!(".{}.tmp-{}", manifest.name, std::process::id()));
        std::fs::write(&temporary, bytes)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&temporary, std::fs::Permissions::from_mode(0o755))?;
        }
        std::fs::File::open(&temporary)?.sync_all()?;
        std::fs::rename(&temporary, &executable)?;
        sync_directory(&release_dir)?;
        sync_directory(&package_dir.join("releases"))?;
    }
    let previous_digest = previous
        .as_ref()
        .map(|path| {
            std::fs::read(package_dir.join(path).join(&manifest.name))
                .map(|bytes| sha256_hex(&bytes))
        })
        .transpose()?;
    let advance = || {
        switch_current(
            &package_dir,
            Some(&Path::new("releases").join(&manifest.version)),
        )
    };
    if let Some(lifecycle) = lifecycle {
        lifecycle.preflight(&current.join(&manifest.name))?;
        persist_activation(
            &package_dir,
            &PendingActivation {
                previous: previous.clone(),
                previous_digest: previous_digest.clone(),
            },
        )?;
        lifecycle.stop()?;
        let applied = advance()
            .and_then(|()| lifecycle.start())
            .and_then(|()| lifecycle.verify(&manifest.artifact_digest));
        if let Err(error) = applied {
            lifecycle.stop().map_err(|rollback| {
                format!(
                    "activation failed: {error}; could not stop candidate for rollback: {rollback}"
                )
            })?;
            switch_current(&package_dir, previous.as_deref())?;
            if let Some(digest) = previous_digest {
                lifecycle.start().and_then(|()| lifecycle.verify(&digest))
                    .map_err(|rollback| format!("activation failed: {error}; previous link restored but recovery failed: {rollback}"))?;
            }
            clear_activation(&package_dir)?;
            return Err(format!("activation failed and previous version restored: {error}").into());
        }
        clear_activation(&package_dir)?;
    } else {
        advance()?;
    }
    Ok(ActivatedPackage {
        name: manifest.name.clone(),
        version: manifest.version.clone(),
        target: manifest.target.clone(),
        digest: manifest.artifact_digest.clone(),
        executable,
    })
}

/// Written and synced before any disruptive action. Recovery deliberately
/// restores the prior release, never guesses whether an unverified candidate
/// completed successfully. A failed recovery retains the checkpoint.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PendingActivation {
    previous: Option<PathBuf>,
    previous_digest: Option<String>,
}

fn activation_lock(directory: &Path) -> Result<std::fs::File, AnyError> {
    let lock = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(directory.join(".activation.lock"))?;
    lock.try_lock()
        .map_err(|_| "another activation is already running for this package")?;
    Ok(lock)
}

/// Resume only locally checkpointed, previously authorized operations. Never
/// select or install a new release on startup. Return every failure visibly;
/// leave its checkpoint for an explicit retry rather than masking uncertainty.
pub fn recover_interrupted_activations() -> Result<Vec<String>, AnyError> {
    let entries = match std::fs::read_dir(crate::software_dir()) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error.into()),
    };
    let mut recovered = Vec::new();
    let mut errors = Vec::new();
    for entry in entries {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }
        let directory = entry.path();
        if std::fs::symlink_metadata(directory.join("activation-pending.json")).is_err() {
            continue;
        }
        let name = entry.file_name().to_string_lossy().into_owned();
        let result = (|| -> Result<(), AnyError> {
            validate_label("package", &name)?;
            let _lock = activation_lock(&directory)?;
            let binding = crate::software_service::binding(&name)?;
            recover_activation(
                &directory,
                &name,
                binding
                    .as_ref()
                    .map(|binding| binding as &dyn crate::software_service::Lifecycle),
            )
        })();
        match result {
            Ok(()) => recovered.push(name),
            Err(error) => errors.push(format!("{name}: {error}")),
        }
    }
    if errors.is_empty() {
        Ok(recovered)
    } else {
        Err(format!(
            "interrupted activation recovery failed: {}",
            errors.join("; ")
        )
        .into())
    }
}

fn persist_activation(directory: &Path, pending: &PendingActivation) -> Result<(), AnyError> {
    use std::io::Write;
    let temporary = directory.join(".activation-pending.tmp");
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    // A stale unpublished temporary is safe to discard under the package lock.
    if std::fs::symlink_metadata(&temporary).is_ok() {
        std::fs::remove_file(&temporary)?;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&temporary)?;
    file.write_all(&serde_json::to_vec(pending)?)?;
    file.sync_all()?;
    std::fs::rename(temporary, directory.join("activation-pending.json"))?;
    sync_directory(directory)
}

fn sync_directory(directory: &Path) -> Result<(), AnyError> {
    #[cfg(unix)]
    std::fs::File::open(directory)?.sync_all()?;
    Ok(())
}

fn clear_activation(directory: &Path) -> Result<(), AnyError> {
    std::fs::remove_file(directory.join("activation-pending.json"))?;
    sync_directory(directory)
}

fn recover_activation(
    directory: &Path,
    name: &str,
    lifecycle: Option<&dyn crate::software_service::Lifecycle>,
) -> Result<(), AnyError> {
    let path = directory.join("activation-pending.json");
    let metadata = match std::fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    if !metadata.is_file() || metadata.len() > 4096 {
        return Err("invalid activation recovery checkpoint".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err("activation recovery checkpoint must be owner-only".into());
        }
    }
    let pending: PendingActivation = serde_json::from_slice(&std::fs::read(path)?)?;
    let lifecycle = lifecycle.ok_or("interrupted activation lost its native service binding")?;
    match (&pending.previous, &pending.previous_digest) {
        (Some(previous), Some(digest)) => {
            let components: Vec<_> = previous.components().collect();
            if components.len() != 2
                || components[0].as_os_str() != "releases"
                || !matches!(components[1], std::path::Component::Normal(_))
                || sha256_hex(&std::fs::read(directory.join(previous).join(name))?) != *digest
            {
                return Err("previous release failed recovery integrity check".into());
            }
        }
        (None, None) => {}
        _ => return Err("inconsistent activation recovery checkpoint".into()),
    }
    lifecycle.preflight(&directory.join("current").join(name))?;
    lifecycle.stop()?;
    switch_current(directory, pending.previous.as_deref())?;
    if let Some(digest) = pending.previous_digest {
        lifecycle.start()?;
        lifecycle.verify(&digest)?;
    }
    clear_activation(directory)
}

fn switch_current(package_dir: &Path, target: Option<&Path>) -> Result<(), AnyError> {
    let current = package_dir.join("current");
    let Some(target) = target else {
        if current.exists() || std::fs::symlink_metadata(&current).is_ok() {
            std::fs::remove_file(current)?;
            sync_directory(package_dir)?;
        }
        return Ok(());
    };
    let temporary = package_dir.join(format!(".current-{}", std::process::id()));
    if std::fs::symlink_metadata(&temporary).is_ok() {
        std::fs::remove_file(&temporary)?;
    }
    #[cfg(unix)]
    std::os::unix::fs::symlink(target, &temporary)?;
    #[cfg(not(unix))]
    return Err("package activation requires Unix".into());
    std::fs::rename(temporary, current)?;
    sync_directory(package_dir)?;
    Ok(())
}

fn platform_name(platform: &Platform) -> &'static str {
    match platform {
        Platform::Linux => "linux",
        Platform::Darwin => "darwin",
    }
}

fn validate_label(kind: &str, value: &str) -> Result<(), String> {
    if value.is_empty()
        || matches!(value, "." | "..")
        || value.len() > 128
        || value
            .bytes()
            .any(|byte| !(byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.')))
    {
        return Err(format!("{kind} contains unsafe characters"));
    }
    Ok(())
}

fn validate_update_policy(policy: &UpdatePolicy) -> Result<(), String> {
    if let UpdatePolicy::Automatic {
        minimum_cache_age_secs,
        rollout_window_secs,
        retry_backoff_secs,
    } = policy
    {
        if *minimum_cache_age_secs < 60 || *rollout_window_secs < 300 || *retry_backoff_secs < 300 {
            return Err("automatic updates require minimum cache age >= 60s, rollout window >= 300s, and retry backoff >= 300s".into());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use mycelium_peer_protocol::PeerHello;

    fn peer(
        hostname: &str,
        platform: Platform,
        architecture: &str,
        capabilities: &[&str],
    ) -> PeerView {
        PeerView {
            origin: hostname.into(),
            hello: Some(PeerHello {
                node_id: hostname.into(),
                protocol_version: 1,
                site: "wagar-house".into(),
                hostname: hostname.into(),
                platform,
                architecture: architecture.into(),
                daemon_version: "test".into(),
                capabilities: capabilities.iter().map(|v| (*v).into()).collect(),
                interfaces: Vec::new(),
            }),
            health: None,
            hardware: None,
            transports: vec![],
            observed_endpoints: vec![],
            last_seen: 1,
        }
    }

    #[test]
    fn rules_are_derived_from_facts_and_merge_without_duplicates() {
        let policy = SoftwarePolicy {
            schema_version: 1,
            defaults: SoftwareDefaults::default(),
            rules: vec![
                PlacementRule {
                    name: "global".into(),
                    selector: FactSelector::default(),
                    packages: vec![DesiredPackage {
                        name: "unibus".into(),
                        channel: "stable".into(),
                        updates: None,
                        requires: BTreeMap::new(),
                    }],
                },
                PlacementRule {
                    name: "pi".into(),
                    selector: FactSelector {
                        all: BTreeSet::from(["node.raspberry-pi".into()]),
                        none: BTreeSet::new(),
                    },
                    packages: vec![DesiredPackage {
                        name: "isochrone".into(),
                        channel: "stable".into(),
                        updates: None,
                        requires: BTreeMap::new(),
                    }],
                },
            ],
        };
        let assignments = plan(
            &policy,
            &[
                peer("pi", Platform::Linux, "aarch64", &["node.raspberry-pi"]),
                peer("mac", Platform::Darwin, "aarch64", &[]),
            ],
        )
        .unwrap();
        assert_eq!(assignments.len(), 3);
        assert!(assignments
            .iter()
            .any(|item| item.hostname == "pi" && item.package == "isochrone"));
    }

    #[test]
    fn conflicting_channels_fail_loudly() {
        let policy = SoftwarePolicy {
            schema_version: 1,
            defaults: SoftwareDefaults::default(),
            rules: vec![
                PlacementRule {
                    name: "a".into(),
                    selector: FactSelector::default(),
                    packages: vec![DesiredPackage {
                        name: "unibus".into(),
                        channel: "stable".into(),
                        updates: None,
                        requires: BTreeMap::new(),
                    }],
                },
                PlacementRule {
                    name: "b".into(),
                    selector: FactSelector::default(),
                    packages: vec![DesiredPackage {
                        name: "unibus".into(),
                        channel: "canary".into(),
                        updates: None,
                        requires: BTreeMap::new(),
                    }],
                },
            ],
        };
        assert!(
            plan(&policy, &[peer("pi", Platform::Linux, "aarch64", &[])])
                .unwrap_err()
                .contains("conflicting channels")
        );
    }

    #[test]
    fn package_selection_compares_numeric_versions() {
        let key = ed25519_dalek::SigningKey::from_bytes(&[7; 32]);
        let package = |version: &str| {
            PackageManifest::sign(
                &key,
                "unibus".into(),
                version.into(),
                "stable".into(),
                "aarch64-apple-darwin".into(),
                version.as_bytes(),
            )
            .unwrap()
        };
        let packages = vec![package("1.9.0"), package("1.10.0")];
        assert_eq!(
            select(
                &packages,
                "unibus",
                "stable",
                &["aarch64-apple-darwin".into()]
            )
            .unwrap()
            .version,
            "1.10.0"
        );
    }

    #[test]
    fn stable_node_selector_survives_rename() {
        let before = peer("old-host", Platform::Linux, "x86_64", &[]);
        let mut after = before.clone();
        after.hello.as_mut().unwrap().hostname = "new-host".into();
        let stable = format!("node.{}", before.hello.as_ref().unwrap().node_id);
        assert!(facts(&before).contains(&stable));
        assert!(facts(&after).contains(&stable));
        assert!(!facts(&after).contains("host.old-host"));
    }

    #[test]
    fn activation_verifies_bytes_and_switches_current_atomically() {
        let root = crate::test_dir("software-test");
        let artifacts = root.join("artifacts");
        let software = root.join("software");
        std::fs::create_dir_all(&artifacts).unwrap();
        let key = ed25519_dalek::SigningKey::from_bytes(&[9; 32]);
        let package = PackageManifest::sign(
            &key,
            "unibus".into(),
            "1.0.0".into(),
            "stable".into(),
            "aarch64-apple-darwin".into(),
            b"binary",
        )
        .unwrap();
        std::fs::write(artifacts.join(&package.artifact_digest), b"binary").unwrap();
        let activated = activate_from(&package, &artifacts, &software).unwrap();
        assert_eq!(std::fs::read(activated.executable).unwrap(), b"binary");
        assert_eq!(
            std::fs::read_link(software.join("unibus/current")).unwrap(),
            Path::new("releases/1.0.0")
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn current_requires_signed_bytes_not_only_version() {
        let (root, artifacts, software, previous, _) = activation_fixture();
        let activated = activate_from(&previous, &artifacts, &software).unwrap();
        current_health(&previous, &software, None).unwrap();
        std::fs::write(&activated.executable, b"tampered").unwrap();
        assert!(current_health(&previous, &software, None)
            .unwrap_err()
            .to_string()
            .contains("installed package bytes"));
        // Repair must not overwrite a supposedly immutable release silently.
        assert!(activate_from(&previous, &artifacts, &software)
            .unwrap_err()
            .to_string()
            .contains("immutable package"));
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn current_rejects_external_release_link() {
        let (root, artifacts, software, previous, _) = activation_fixture();
        activate_from(&previous, &artifacts, &software).unwrap();
        let current = software.join("unibus/current");
        std::fs::remove_file(&current).unwrap();
        std::os::unix::fs::symlink(software.join("unibus/releases/1.0.0"), &current).unwrap();
        assert!(current_health(&previous, &software, None)
            .unwrap_err()
            .to_string()
            .contains("internal release"));
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn read_only_health_detects_drift_without_service_actions() {
        let (root, artifacts, software, previous, _) = activation_fixture();
        activate_from(&previous, &artifacts, &software).unwrap();
        let native = NativeProbe {
            healthy_digest: "stopped".into(),
            calls: Default::default(),
        };
        assert!(current_health(&previous, &software, Some(&native)).is_err());
        assert_eq!(*native.calls.borrow(), ["preflight", "verify"]);
        assert_eq!(
            std::fs::read_link(software.join("unibus/current")).unwrap(),
            Path::new("releases/1.0.0")
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn same_version_activation_repairs_service_and_is_idempotent_when_healthy() {
        let (root, artifacts, software, previous, _) = activation_fixture();
        activate_from(&previous, &artifacts, &software).unwrap();
        let native = NativeProbe {
            healthy_digest: previous.artifact_digest.clone(),
            calls: Default::default(),
        };
        activate_transaction(&previous, &artifacts, &software, Some(&native)).unwrap();
        assert_eq!(
            *native.calls.borrow(),
            ["preflight", "stop", "start", "verify"]
        );
        native.calls.borrow_mut().clear();
        current_health(&previous, &software, Some(&native)).unwrap();
        assert_eq!(*native.calls.borrow(), ["preflight", "verify"]);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn compute_policy_requires_explicit_roles_and_keeps_updates_manual() {
        let policy: SoftwarePolicy =
            serde_json::from_str(include_str!("../../../fungOS/compute/software-policy.json"))
                .unwrap();
        policy.validate().unwrap();
        assert!(plan(
            &policy,
            &[peer("gpu", Platform::Linux, "x86_64", &["resource.gpu"])]
        )
        .unwrap()
        .is_empty());
        let assignments = plan(
            &policy,
            &[peer(
                "worker",
                Platform::Linux,
                "x86_64",
                &["role.umie", "role.shroud"],
            )],
        )
        .unwrap();
        assert_eq!(assignments.len(), 2);
        assert!(assignments
            .iter()
            .all(|item| item.updates == UpdatePolicy::Manual));
        assert!(assignments.iter().any(|item| item.package == "umie"));
        assert!(assignments.iter().any(|item| item.package == "shroud"));
    }

    #[test]
    fn tooling_policy_is_explicit_linux_and_manual() {
        let policy: SoftwarePolicy =
            serde_json::from_str(include_str!("../../../fungOS/tooling/software-policy.json"))
                .unwrap();
        policy.validate().unwrap();
        let assignments = plan(
            &policy,
            &[
                peer("developer", Platform::Linux, "x86_64", &["role.shroudoci"]),
                peer("pi", Platform::Linux, "aarch64", &["role.shroudoci"]),
                peer("ordinary", Platform::Linux, "x86_64", &["role.shroud"]),
                peer("mac", Platform::Darwin, "x86_64", &["role.shroudoci"]),
            ],
        )
        .unwrap();
        assert_eq!(assignments.len(), 2);
        assert!(assignments
            .iter()
            .all(|assignment| assignment.package == "shroudoci"
                && assignment.updates == UpdatePolicy::Manual));
    }

    #[test]
    fn documented_policy_resolves_package_specific_updates() {
        let policy: SoftwarePolicy =
            serde_json::from_str(include_str!("../../../docs/examples/software-policy.json"))
                .unwrap();
        policy.validate().unwrap();
        assert_eq!(policy.defaults.updates, UpdatePolicy::Manual);
        let assignments = plan(
            &policy,
            &[peer("gpu", Platform::Linux, "aarch64", &["resource.gpu"])],
        )
        .unwrap();
        let yggdrasil = assignments
            .iter()
            .find(|item| item.package == "yggdrasil")
            .unwrap();
        assert!(matches!(
            yggdrasil.updates,
            UpdatePolicy::Automatic {
                minimum_cache_age_secs: 900,
                ..
            }
        ));
    }

    #[test]
    fn legacy_policy_defaults_to_manual_updates() {
        let policy: SoftwarePolicy = serde_json::from_str(
            r#"{"schema_version":1,"rules":[{"name":"base","packages":[{"name":"unibus"}]}]}"#,
        )
        .unwrap();
        let assignments = plan(&policy, &[peer("node", Platform::Linux, "aarch64", &[])]).unwrap();
        assert_eq!(assignments[0].updates, UpdatePolicy::Manual);
    }

    struct NativeProbe {
        healthy_digest: String,
        calls: std::cell::RefCell<Vec<&'static str>>,
    }

    impl crate::software_service::Lifecycle for NativeProbe {
        fn preflight(&self, _: &Path) -> Result<(), AnyError> {
            self.calls.borrow_mut().push("preflight");
            Ok(())
        }
        fn stop(&self) -> Result<(), AnyError> {
            self.calls.borrow_mut().push("stop");
            Ok(())
        }
        fn start(&self) -> Result<(), AnyError> {
            self.calls.borrow_mut().push("start");
            Ok(())
        }
        fn verify(&self, digest: &str) -> Result<(), AnyError> {
            self.calls.borrow_mut().push("verify");
            if digest == self.healthy_digest {
                Ok(())
            } else {
                Err("deliberately unhealthy candidate".into())
            }
        }
    }

    fn activation_fixture() -> (PathBuf, PathBuf, PathBuf, PackageManifest, PackageManifest) {
        let root = std::env::var_os("MYCELIUM_TEST_CRASH_ROOT")
            .map(PathBuf::from)
            .unwrap_or_else(|| crate::test_dir("native-update"));
        let artifacts = root.join("artifacts");
        let software = root.join("software");
        std::fs::create_dir_all(&artifacts).unwrap();
        let key = ed25519_dalek::SigningKey::from_bytes(&[19; 32]);
        let sign = |version: &str, bytes: &[u8]| {
            PackageManifest::sign(
                &key,
                "unibus".into(),
                version.into(),
                "test".into(),
                "x86_64-unknown-linux-musl".into(),
                bytes,
            )
            .unwrap()
        };
        let previous = sign("1.0.0", b"good");
        let candidate = sign("1.1.0", b"bad");
        std::fs::write(artifacts.join(&previous.artifact_digest), b"good").unwrap();
        std::fs::write(artifacts.join(&candidate.artifact_digest), b"bad").unwrap();
        (root, artifacts, software, previous, candidate)
    }

    #[test]
    fn interrupted_activation_restores_before_retry_and_keeps_failed_recovery() {
        let (root, artifacts, software, previous, candidate) = activation_fixture();
        activate_from(&previous, &artifacts, &software).unwrap();
        let directory = software.join("unibus");
        persist_activation(
            &directory,
            &PendingActivation {
                previous: Some(PathBuf::from("releases/1.0.0")),
                previous_digest: Some(previous.artifact_digest.clone()),
            },
        )
        .unwrap();
        // Persisted state after a process died following the pointer switch.
        activate_from(&candidate, &artifacts, &software).unwrap_err();
        std::fs::create_dir_all(directory.join("releases/1.1.0")).unwrap();
        std::fs::write(directory.join("releases/1.1.0/unibus"), b"bad").unwrap();
        switch_current(&directory, Some(Path::new("releases/1.1.0"))).unwrap();
        assert!(current_health(&candidate, &software, None)
            .unwrap_err()
            .to_string()
            .contains("interrupted"));
        let unhealthy = NativeProbe {
            healthy_digest: "none".into(),
            calls: Default::default(),
        };
        assert!(recover_activation(&directory, "unibus", Some(&unhealthy)).is_err());
        assert!(directory.join("activation-pending.json").exists());
        let native = NativeProbe {
            healthy_digest: previous.artifact_digest.clone(),
            calls: Default::default(),
        };
        recover_activation(&directory, "unibus", Some(&native)).unwrap();
        assert!(!directory.join("activation-pending.json").exists());
        current_health(&previous, &software, None).unwrap();
        assert_eq!(
            *native.calls.borrow(),
            ["preflight", "stop", "start", "verify"]
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn recovery_rejects_corrupt_previous_release_before_stopping_service() {
        let (root, artifacts, software, previous, _) = activation_fixture();
        activate_from(&previous, &artifacts, &software).unwrap();
        let directory = software.join("unibus");
        persist_activation(
            &directory,
            &PendingActivation {
                previous: Some(PathBuf::from("releases/1.0.0")),
                previous_digest: Some(previous.artifact_digest.clone()),
            },
        )
        .unwrap();
        std::fs::write(directory.join("current/unibus"), b"tampered").unwrap();
        let native = NativeProbe {
            healthy_digest: previous.artifact_digest,
            calls: Default::default(),
        };
        assert!(recover_activation(&directory, "unibus", Some(&native)).is_err());
        assert!(native.calls.borrow().is_empty());
        assert!(directory.join("activation-pending.json").exists());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn dependency_order_rejects_missing_and_cyclic_assignments() {
        let policy: SoftwarePolicy = serde_json::from_str(r#"{"schema_version":1,"rules":[{"name":"edge","packages":[{"name":"canvas","requires":{"unibus":"1.0.0"}},{"name":"unibus"}]}]}"#).unwrap();
        let mut assignments =
            plan(&policy, &[peer("qemu", Platform::Linux, "x86_64", &[])]).unwrap();
        let ordered = dependency_order(&assignments).unwrap();
        assert_eq!(
            ordered
                .iter()
                .map(|item| item.package.as_str())
                .collect::<Vec<_>>(),
            ["unibus", "canvas"]
        );
        assert!(dependency_order(&assignments[..1]).is_err());
        assignments
            .iter_mut()
            .find(|item| item.package == "unibus")
            .unwrap()
            .requires
            .insert("canvas".into(), "1.0.0".into());
        assert!(dependency_order(&assignments)
            .unwrap_err()
            .to_string()
            .contains("cyclic"));
    }

    #[test]
    fn exact_dependency_versions_fail_closed_and_auto_cannot_split_sets() {
        let (root, _, _, previous, candidate) = activation_fixture();
        let policy: SoftwarePolicy = serde_json::from_str(r#"{"schema_version":1,"rules":[{"name":"edge","packages":[{"name":"canvas","channel":"test","requires":{"unibus":"1.0.0"}},{"name":"unibus","channel":"test"}]}]}"#).unwrap();
        let assignments = plan(&policy, &[peer("qemu", Platform::Linux, "x86_64", &[])]).unwrap();
        let ordered = dependency_order(&assignments).unwrap();
        let canvas = assignments
            .iter()
            .find(|item| item.package == "canvas")
            .unwrap();
        let targets = [previous.target.clone()];
        check_required_versions(canvas, &ordered, &[previous.clone()], &targets).unwrap();
        assert!(
            check_required_versions(canvas, &ordered, &[previous, candidate], &targets)
                .unwrap_err()
                .to_string()
                .contains("selected 1.1.0")
        );
        let mut automatic = assignments;
        for assignment in &mut automatic {
            assignment.updates = UpdatePolicy::Automatic {
                minimum_cache_age_secs: 60,
                rollout_window_secs: 300,
                retry_backoff_secs: 300,
            };
        }
        let mut state = AutomaticState::default();
        assert!(
            automatic_assignments(automatic, &[], &targets, "qemu", u64::MAX, &mut state)
                .is_empty()
        );
        assert!(state.last_attempts.is_empty());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn multi_member_linked_changes_remain_blocked_until_atomic_rollback() {
        admit_linked_changes(0).unwrap();
        admit_linked_changes(1).unwrap();
        assert!(admit_linked_changes(2)
            .unwrap_err()
            .to_string()
            .contains("whole-set rollback"));
    }

    #[test]
    fn interrupted_first_install_removes_unverified_link() {
        let (root, artifacts, software, previous, candidate) = activation_fixture();
        activate_from(&candidate, &artifacts, &software).unwrap();
        let directory = software.join("unibus");
        persist_activation(
            &directory,
            &PendingActivation {
                previous: None,
                previous_digest: None,
            },
        )
        .unwrap();
        let native = NativeProbe {
            healthy_digest: previous.artifact_digest,
            calls: Default::default(),
        };
        recover_activation(&directory, "unibus", Some(&native)).unwrap();
        assert!(std::fs::symlink_metadata(directory.join("current")).is_err());
        assert_eq!(*native.calls.borrow(), ["preflight", "stop"]);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    #[cfg(unix)]
    fn killed_activation_child() {
        if std::env::var_os("MYCELIUM_TEST_CRASH_ROOT").is_none() {
            return;
        }
        struct Killed;
        impl crate::software_service::Lifecycle for Killed {
            fn preflight(&self, _: &Path) -> Result<(), AnyError> {
                Ok(())
            }
            fn stop(&self) -> Result<(), AnyError> {
                Ok(())
            }
            fn start(&self) -> Result<(), AnyError> {
                std::process::Command::new("kill")
                    .args(["-KILL", &std::process::id().to_string()])
                    .status()?;
                Err("kill failed".into())
            }
            fn verify(&self, _: &str) -> Result<(), AnyError> {
                unreachable!()
            }
        }
        let (_, artifacts, software, _, candidate) = activation_fixture();
        activate_transaction(&candidate, &artifacts, &software, Some(&Killed)).unwrap();
        panic!("child survived interruption");
    }

    #[test]
    #[cfg(unix)]
    fn sigkill_after_switch_recovers_previous_verified_release() {
        use std::os::unix::process::ExitStatusExt;
        let (root, artifacts, software, previous, _) = activation_fixture();
        activate_from(&previous, &artifacts, &software).unwrap();
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "software::tests::killed_activation_child",
                "--nocapture",
            ])
            .env("MYCELIUM_TEST_CRASH_ROOT", &root)
            .status()
            .unwrap();
        assert_eq!(status.signal(), Some(9));
        let directory = software.join("unibus");
        assert_eq!(
            std::fs::read_link(directory.join("current")).unwrap(),
            Path::new("releases/1.1.0")
        );
        assert!(directory.join("activation-pending.json").exists());
        let native = NativeProbe {
            healthy_digest: previous.artifact_digest,
            calls: Default::default(),
        };
        recover_activation(&directory, "unibus", Some(&native)).unwrap();
        assert_eq!(
            std::fs::read(directory.join("current/unibus")).unwrap(),
            b"good"
        );
        assert!(!directory.join("activation-pending.json").exists());
        std::fs::remove_dir_all(root).unwrap();
    }

    /// Booted only by the disposable qualification unit. This exercises the
    /// production checkpoint/link code across SIGKILL and an actual disk reboot;
    /// NativeProbe is a lifecycle fixture, not an application health claim.
    #[test]
    #[ignore = "requires marked disposable QEMU and performs guest reboot/poweroff"]
    #[cfg(target_os = "linux")]
    fn qemu_interrupted_activation_reboot() {
        use std::os::unix::process::ExitStatusExt;
        assert_eq!(
            std::fs::read_to_string("/sys/class/dmi/id/product_name")
                .unwrap()
                .trim(),
            "unibus-package-validation"
        );
        assert_eq!(
            std::fs::read_to_string("/run/unibus-package-validation")
                .unwrap()
                .trim(),
            "unibus-package-validation"
        );
        assert_eq!(
            std::env::var("MYCELIUM_TEST_CRASH_ROOT").unwrap(),
            "/var/lib/fungos-update-safety-proof"
        );
        let (root, artifacts, software, previous, _) = activation_fixture();
        let directory = software.join("unibus");
        if !directory.join("activation-pending.json").exists() {
            activate_from(&previous, &artifacts, &software).unwrap();
            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "software::tests::killed_activation_child",
                    "--nocapture",
                ])
                .env("MYCELIUM_TEST_CRASH_ROOT", &root)
                .status()
                .unwrap();
            assert_eq!(status.signal(), Some(9));
            assert!(directory.join("activation-pending.json").exists());
            println!("FUNGOS_UPDATE_SIGKILL_CHECKPOINTED");
            assert!(std::process::Command::new("sync")
                .status()
                .unwrap()
                .success());
            assert!(std::process::Command::new("systemctl")
                .args(["--no-block", "reboot"])
                .status()
                .unwrap()
                .success());
            std::thread::sleep(std::time::Duration::from_secs(15));
            panic!("guest did not reboot");
        }
        assert_eq!(
            std::fs::read_link(directory.join("current")).unwrap(),
            Path::new("releases/1.1.0")
        );
        let native = NativeProbe {
            healthy_digest: previous.artifact_digest,
            calls: Default::default(),
        };
        recover_activation(&directory, "unibus", Some(&native)).unwrap();
        assert_eq!(
            std::fs::read(directory.join("current/unibus")).unwrap(),
            b"good"
        );
        assert!(!directory.join("activation-pending.json").exists());
        assert_eq!(
            *native.calls.borrow(),
            ["preflight", "stop", "start", "verify"]
        );
        println!("FUNGOS_UPDATE_REBOOT_RECOVERY_VERIFIED");
        assert!(std::process::Command::new("systemctl")
            .args(["--no-block", "poweroff"])
            .status()
            .unwrap()
            .success());
    }

    #[test]
    fn unhealthy_service_restores_previous_bytes_and_verifies_recovery() {
        let (root, artifacts, software, previous, candidate) = activation_fixture();
        activate_from(&previous, &artifacts, &software).unwrap();
        let native = NativeProbe {
            healthy_digest: previous.artifact_digest,
            calls: Default::default(),
        };
        let error =
            activate_transaction(&candidate, &artifacts, &software, Some(&native)).unwrap_err();
        assert!(error.to_string().contains("previous version restored"));
        assert_eq!(
            std::fs::read(software.join("unibus/current/unibus")).unwrap(),
            b"good"
        );
        assert_eq!(
            *native.calls.borrow(),
            [
                "preflight",
                "stop",
                "start",
                "verify",
                "stop",
                "start",
                "verify"
            ]
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn healthy_service_advances_only_after_native_verification() {
        let (root, artifacts, software, previous, candidate) = activation_fixture();
        activate_from(&previous, &artifacts, &software).unwrap();
        let native = NativeProbe {
            healthy_digest: candidate.artifact_digest.clone(),
            calls: Default::default(),
        };
        activate_transaction(&candidate, &artifacts, &software, Some(&native)).unwrap();
        assert_eq!(
            std::fs::read(software.join("unibus/current/unibus")).unwrap(),
            b"bad"
        );
        assert_eq!(
            *native.calls.borrow(),
            ["preflight", "stop", "start", "verify"]
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn unhealthy_first_install_removes_candidate_link() {
        let (root, artifacts, software, previous, candidate) = activation_fixture();
        let native = NativeProbe {
            healthy_digest: previous.artifact_digest,
            calls: Default::default(),
        };
        assert!(activate_transaction(&candidate, &artifacts, &software, Some(&native)).is_err());
        assert!(std::fs::symlink_metadata(software.join("unibus/current")).is_err());
        assert_eq!(
            *native.calls.borrow(),
            ["preflight", "stop", "start", "verify", "stop"]
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn immutable_versions_and_activation_lock_prevent_overwrite() {
        let (root, artifacts, software, previous, mut candidate) = activation_fixture();
        activate_from(&previous, &artifacts, &software).unwrap();
        candidate.version = previous.version;
        let key = ed25519_dalek::SigningKey::from_bytes(&[19; 32]);
        candidate = PackageManifest::sign(
            &key,
            candidate.name,
            candidate.version,
            candidate.channel,
            candidate.target,
            b"bad",
        )
        .unwrap();
        assert!(activate_from(&candidate, &artifacts, &software)
            .unwrap_err()
            .to_string()
            .contains("immutable"));
        let lock = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(software.join("unibus/.activation.lock"))
            .unwrap();
        lock.try_lock().unwrap();
        assert!(activate_from(&candidate, &artifacts, &software)
            .unwrap_err()
            .to_string()
            .contains("already running"));
        assert_eq!(
            std::fs::read(software.join("unibus/current/unibus")).unwrap(),
            b"good"
        );
        drop(lock);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn path_components_and_corrupted_artifacts_fail_before_native_stop() {
        assert!(validate_label("name", "..").is_err());
        assert!(validate_label("name", ".").is_err());
        let (root, artifacts, software, previous, candidate) = activation_fixture();
        activate_from(&previous, &artifacts, &software).unwrap();
        std::fs::write(artifacts.join(&candidate.artifact_digest), b"tampered").unwrap();
        let native = NativeProbe {
            healthy_digest: previous.artifact_digest,
            calls: Default::default(),
        };
        assert!(activate_transaction(&candidate, &artifacts, &software, Some(&native)).is_err());
        assert!(native.calls.borrow().is_empty());
        std::fs::remove_dir_all(root).unwrap();
    }
}
