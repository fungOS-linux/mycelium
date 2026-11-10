//! Explicit, single-package Debian upgrades. APT owns repository authentication;
//! dpkg owns files/conffiles; existing local service bindings own health. Native
//! binary activation and Debian ownership must not overlap. No automatic rollout.
use crate::software_service::{Lifecycle, ServiceBinding};
use mycelium_peer_protocol::sha256_hex;
use serde::{Deserialize, Serialize};
use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};
type Error = Box<dyn std::error::Error + Send + Sync>;

/// Read dpkg's ownership database, including a symlink's resolved destination.
/// Missing ownership is distinct from a broken/missing dpkg-query command.
/// Native activation must call this before creating candidates or backups.
pub fn package_owner(path: &Path) -> Result<Option<String>, Error> {
    if !cfg!(target_os = "linux") {
        return Ok(None);
    }
    if !Path::new("/var/lib/dpkg/status").is_file() {
        return Ok(None);
    }
    let canonical = fs::canonicalize(path)?;
    for candidate in [path, canonical.as_path()] {
        let output = Command::new("dpkg-query")
            .args(["-S", candidate.to_str().ok_or("non-UTF8 ownership path")?])
            .env("LC_ALL", "C")
            .output()?;
        if output.status.code() == Some(1) {
            continue;
        }
        if !output.status.success() {
            return Err("dpkg-query ownership lookup failed".into());
        }
        let text = String::from_utf8(output.stdout)?;
        return parse_owner(&text, candidate).map(Some);
    }
    Ok(None)
}

fn parse_owner(output: &str, path: &Path) -> Result<String, Error> {
    let lines: Vec<_> = output.lines().collect();
    if lines.len() != 1 {
        return Err("ambiguous Debian executable ownership".into());
    }
    let (owner, owned) = lines[0]
        .split_once(": ")
        .ok_or("invalid dpkg ownership response")?;
    if owned != path.to_str().ok_or("non-UTF8 ownership path")?
        || !owner.split(':').all(|value| identity(value, false))
        || owner.contains(',')
    {
        return Err("unexpected Debian executable ownership".into());
    }
    Ok(owner.to_owned())
}

/// Fail before native writes to an executable managed by Debian.
pub fn require_native_executable(path: &Path) -> Result<(), Error> {
    if let Some(owner) = package_owner(path)? {
        return Err(format!("{} is owned by Debian package {owner}; use APT package updates, not native binary activation", path.display()).into());
    }
    Ok(())
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AptPlan {
    pub package: String,
    pub previous: String,
    pub candidate: String,
    pub architecture: String,
    pub previous_sha256: String,
    pub candidate_sha256: String,
    pub executable: PathBuf,
    pub service: ServiceBinding,
}

fn run(program: &str, args: &[&str], directory: Option<&Path>) -> Result<String, Error> {
    let mut command = Command::new(program);
    command
        .args(args)
        .env("LC_ALL", "C")
        .env("DEBIAN_FRONTEND", "noninteractive")
        .env("NEEDRESTART_MODE", "l")
        .env_remove("APT_CONFIG");
    if let Some(directory) = directory {
        command.current_dir(directory);
    }
    let output = command.output()?;
    if !output.status.success() {
        return Err(format!(
            "{program} failed: {}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    Ok(String::from_utf8(output.stdout)?)
}

fn identity(value: &str, version: bool) -> bool {
    !value.is_empty()
        && value.len() <= 200
        && value.as_bytes()[0].is_ascii_alphanumeric()
        && value.bytes().all(|b| {
            b.is_ascii_alphanumeric()
                || if version {
                    b".+:~-".contains(&b)
                } else {
                    b".+-".contains(&b)
                }
        })
}

fn checksum(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit())
}

fn index_digest(package: &str, version: &str) -> Result<String, Error> {
    let data = run(
        "apt-cache",
        &["show", "--no-all-versions", &format!("{package}={version}")],
        None,
    )?;
    let hashes: std::collections::BTreeSet<_> = data
        .lines()
        .filter_map(|s| s.strip_prefix("SHA256: "))
        .collect();
    if hashes.len() != 1 || !hashes.iter().all(|h| checksum(h)) {
        return Err("repository must supply one unambiguous SHA256 for exact version".into());
    }
    Ok(hashes.first().unwrap().to_string())
}

fn installed(package: &str) -> Result<(String, String), Error> {
    let value = run(
        "dpkg-query",
        &[
            "-W",
            "-f=${db:Status-Status}\n${Version}\n${Architecture}\n${db:Status-Want}",
            package,
        ],
        None,
    )?;
    let parts: Vec<_> = value.lines().collect();
    if parts.len() != 4 || parts[0] != "installed" || parts[3] != "install" {
        return Err("APT update requires an installed, non-held package".into());
    }
    Ok((parts[1].into(), parts[2].into()))
}

fn narrow_simulation(data: &str, package: &str) -> Result<(), Error> {
    let mut changed = false;
    for line in data.lines() {
        let words: Vec<_> = line.split_whitespace().collect();
        match words.first().copied() {
            Some("Remv") => return Err("APT transaction would remove a package".into()),
            Some("Inst" | "Conf") => {
                if words.get(1).copied() != Some(package) {
                    return Err("multi-package APT transactions are not qualified".into());
                }
                changed = true;
            }
            _ => {}
        }
    }
    if !changed {
        return Err("APT simulation did not select a package change".into());
    }
    Ok(())
}

pub fn plan(package: &str, version: &str, executable: &Path) -> Result<AptPlan, Error> {
    if !cfg!(target_os = "linux")
        || !identity(package, false)
        || !identity(version, true)
        || executable.parent() != Some(Path::new("/usr/bin"))
    {
        return Err("requires Linux, exact Debian identities and a /usr/bin executable".into());
    }
    if crate::home_dir()
        .join("software")
        .join(package)
        .join("current")
        .exists()
    {
        return Err("package already has native activation ownership".into());
    }
    let owner = run(
        "dpkg-query",
        &["-S", executable.to_str().ok_or("non-UTF8 executable")?],
        None,
    )?;
    if owner.trim() != format!("{package}: {}", executable.display()) {
        return Err("executable is not exclusively owned by this Debian package".into());
    }
    let (previous, architecture) = installed(package)?;
    if previous == version || !["amd64", "arm64"].contains(&architecture.as_str()) {
        return Err("requires a changed version on amd64 or arm64".into());
    }
    let service = crate::software_service::binding(package)?
        .ok_or("package has no locally authorized service binding")?;
    service.preflight(executable)?;
    narrow_simulation(
        &run(
            "apt-get",
            &[
                "-s",
                "--no-remove",
                "--no-install-recommends",
                "install",
                &format!("{package}={version}"),
            ],
            None,
        )?,
        package,
    )?;
    Ok(AptPlan {
        package: package.into(),
        candidate: version.into(),
        previous_sha256: index_digest(package, &previous)?,
        candidate_sha256: index_digest(package, version)?,
        previous,
        architecture,
        executable: executable.into(),
        service,
    })
}

pub fn digest(plan: &AptPlan) -> Result<String, Error> {
    Ok(sha256_hex(&serde_json::to_vec(plan)?))
}

/// Read-only process/digest/application health, not fresh repository admission.
pub fn health(package: &str, executable: &Path) -> Result<(), Error> {
    if !identity(package, false) || executable.parent() != Some(Path::new("/usr/bin")) {
        return Err("invalid Debian health target".into());
    }
    let owner = run(
        "dpkg-query",
        &["-S", executable.to_str().ok_or("non-UTF8 executable")?],
        None,
    )?;
    if owner.trim() != format!("{package}: {}", executable.display()) {
        return Err("health executable ownership mismatch".into());
    }
    let binding =
        crate::software_service::binding(package)?.ok_or("missing local health binding")?;
    binding.preflight(executable)?;
    binding.verify(&sha256_hex(&fs::read(executable)?))
}

fn stage(
    plan: &AptPlan,
    version: &str,
    expected: &str,
    directory: &Path,
) -> Result<(PathBuf, String), Error> {
    fs::create_dir(directory)?;
    run(
        "apt-get",
        &["download", &format!("{}={version}", plan.package)],
        Some(directory),
    )?;
    let files = fs::read_dir(directory)?
        .map(|e| e.map(|e| e.path()))
        .collect::<Result<Vec<_>, _>>()?;
    if files.len() != 1
        || !fs::symlink_metadata(&files[0])?.is_file()
        || sha256_hex(&fs::read(&files[0])?) != expected
    {
        return Err("downloaded Debian archive does not match the plan".into());
    }
    let archive = &files[0];
    let archive_str = archive.to_str().ok_or("non-UTF8 archive")?;
    let metadata = run(
        "dpkg-deb",
        &["-f", archive_str, "Package", "Version", "Architecture"],
        None,
    )?;
    if metadata
        != format!(
            "Package: {}\nVersion: {version}\nArchitecture: {}\n",
            plan.package, plan.architecture
        )
    {
        return Err("downloaded Debian identity mismatch".into());
    }
    let control = directory.join("control");
    run(
        "dpkg-deb",
        &["-e", archive_str, control.to_str().unwrap()],
        None,
    )?;
    reject_scripts(&control)?;
    let root = directory.join("root");
    run(
        "dpkg-deb",
        &["-x", archive_str, root.to_str().unwrap()],
        None,
    )?;
    let binary = root.join(plan.executable.strip_prefix("/")?);
    if !fs::symlink_metadata(&binary)?.is_file() {
        return Err("package executable must be a regular file".into());
    }
    Ok((archive.clone(), sha256_hex(&fs::read(binary)?)))
}

fn reject_scripts(control: &Path) -> Result<(), Error> {
    for name in ["preinst", "postinst", "prerm", "postrm", "triggers"] {
        if control.join(name).exists() {
            return Err("maintainer scripts/triggers are outside this recovery contract".into());
        }
    }
    Ok(())
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Pending {
    plan: AptPlan,
    previous_archive: PathBuf,
    previous_executable_sha256: String,
}

fn save(path: &Path, pending: &Pending) -> Result<(), Error> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(&serde_json::to_vec(pending)?)?;
    file.sync_all()?;
    fs::File::open(path.parent().ok_or("missing state parent")?)?.sync_all()?;
    Ok(())
}

fn install(path: &Path) -> Result<(), Error> {
    // No dependency resolution or other-package triggers after the checked plan.
    run(
        "dpkg",
        &[
            "--no-triggers",
            "--force-confold",
            "--install",
            path.to_str().ok_or("non-UTF8 archive")?,
        ],
        None,
    )?;
    run("systemctl", &["daemon-reload"], None)?;
    Ok(())
}

fn restore(pending: &Pending) -> Result<(), Error> {
    if sha256_hex(&fs::read(&pending.previous_archive)?) != pending.plan.previous_sha256 {
        return Err("retained rollback archive is corrupt; recovery remains pending".into());
    }
    pending.plan.service.stop()?;
    install(&pending.previous_archive)?;
    pending.plan.service.start()?;
    pending
        .plan
        .service
        .verify(&pending.previous_executable_sha256)?;
    if installed(&pending.plan.package)?.0 != pending.plan.previous {
        return Err("rollback version mismatch".into());
    }
    Ok(())
}

fn root() -> Result<(), Error> {
    if !cfg!(target_os = "linux") || run("id", &["-u"], None)?.trim() != "0" {
        return Err("APT mutation requires local Linux root".into());
    }
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let policy = fs::symlink_metadata(crate::home_dir().join("software-services.json"))?;
    if !policy.is_file() || policy.uid() != 0 || policy.permissions().mode() & 0o077 != 0 {
        return Err(
            "privileged APT service policy must be a root-owned private regular file".into(),
        );
    }
    Ok(())
}

fn state_lock() -> Result<(PathBuf, fs::File), Error> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
    let home = crate::home_dir();
    let metadata = fs::symlink_metadata(&home)?;
    if !metadata.is_dir() || metadata.uid() != 0 || metadata.permissions().mode() & 0o022 != 0 {
        return Err(
            "privileged APT state must have a root-owned, non-writable Mycelium home".into(),
        );
    }
    let state = home.join("apt");
    if state.exists() {
        let metadata = fs::symlink_metadata(&state)?;
        if !metadata.is_dir() || metadata.uid() != 0 || metadata.permissions().mode() & 0o077 != 0 {
            return Err("APT state must be a root-owned private directory".into());
        }
    } else {
        fs::create_dir(&state)?;
        fs::set_permissions(&state, fs::Permissions::from_mode(0o700))?;
    }
    let lock = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(state.join("lock"))?;
    lock.try_lock()
        .map_err(|_| "another Mycelium APT operation is running")?;
    Ok((state, lock))
}

/// An apply digest authorizes the exact observed plan, not a mutable version label.
/// Recovery is checkpointed before stop. A rollback is an explicit failed update,
/// never successful candidate activation.
pub fn apply(plan: &AptPlan, expected_digest: &str) -> Result<(), Error> {
    root()?;
    let (state, _lock) = state_lock()?;
    if !checksum(expected_digest) || digest(plan)? != expected_digest {
        return Err("APT plan digest mismatch".into());
    }
    // Refresh authenticated metadata, including Valid-Until, before re-admission.
    run("apt-get", &["update", "--error-on=any"], None)?;
    let fresh = self::plan(&plan.package, &plan.candidate, &plan.executable)?;
    if digest(&fresh)? != expected_digest {
        return Err("APT plan is stale (package, metadata or local binding changed)".into());
    }
    let checkpoint = state.join("activation-pending.json");
    if checkpoint.exists() {
        return Err("APT recovery pending; run software apt recover --write first".into());
    }
    // Unique attempts allow retry after an incomplete preflight/staging failure.
    let cache = PathBuf::from(
        run(
            "mktemp",
            &["-d", state.join("attempt.XXXXXX").to_str().unwrap()],
            None,
        )?
        .trim(),
    );
    let (previous_archive, previous_executable_sha256) = stage(
        plan,
        &plan.previous,
        &plan.previous_sha256,
        &cache.join("previous"),
    )?;
    let (candidate_archive, candidate_sha256) = stage(
        plan,
        &plan.candidate,
        &plan.candidate_sha256,
        &cache.join("candidate"),
    )?;
    for suffix in ["preinst", "postinst", "prerm", "postrm", "triggers"] {
        if Path::new("/var/lib/dpkg/info")
            .join(format!("{}.{suffix}", plan.package))
            .exists()
        {
            return Err("installed package has unqualified scripts/triggers".into());
        }
    }
    plan.service.check(&previous_executable_sha256)?;
    let pending = Pending {
        plan: plan.clone(),
        previous_archive,
        previous_executable_sha256,
    };
    save(&checkpoint, &pending)?;
    let attempt = (|| {
        plan.service.stop()?;
        install(&candidate_archive)?;
        plan.service.start()?;
        plan.service.verify(&candidate_sha256)?;
        if installed(&plan.package)?.0 != plan.candidate {
            return Err::<(), Error>("candidate version mismatch".into());
        }
        Ok(())
    })();
    if let Err(error) = attempt {
        restore(&pending).map_err(|recovery| {
            format!("update failed: {error}; recovery failed: {recovery}; checkpoint retained")
        })?;
        fs::remove_file(checkpoint)?;
        return Err(format!(
            "update failed: {error}; previous package restored and health verified"
        )
        .into());
    }
    fs::remove_file(checkpoint)?;
    Ok(())
}

pub fn recover() -> Result<(), Error> {
    root()?;
    let (state, _lock) = state_lock()?;
    let checkpoint = state.join("activation-pending.json");
    let pending: Pending = serde_json::from_slice(&fs::read(&checkpoint)?)?;
    // Re-admit the local binding; a stale checkpoint must not bypass revocation.
    let binding = crate::software_service::binding(&pending.plan.package)?
        .ok_or("recovery binding was revoked")?;
    if serde_json::to_vec(&binding)? != serde_json::to_vec(&pending.plan.service)? {
        return Err("recovery binding changed; explicit operator recovery required".into());
    }
    binding.preflight(&pending.plan.executable)?;
    restore(&pending)?;
    fs::remove_file(checkpoint)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn ownership_response_is_exact_and_unambiguous() {
        use std::path::Path;
        assert_eq!(
            super::parse_owner(
                "mycelium: /usr/bin/mycelium\n",
                Path::new("/usr/bin/mycelium")
            )
            .unwrap(),
            "mycelium"
        );
        assert_eq!(
            super::parse_owner(
                "mycelium:amd64: /usr/bin/mycelium\n",
                Path::new("/usr/bin/mycelium")
            )
            .unwrap(),
            "mycelium:amd64"
        );
        assert!(
            super::parse_owner("mycelium: /usr/bin/other\n", Path::new("/usr/bin/mycelium"))
                .is_err()
        );
        assert!(super::parse_owner(
            "one, two: /usr/bin/mycelium\n",
            Path::new("/usr/bin/mycelium")
        )
        .is_err());
        assert!(super::parse_owner(
            "one: /usr/bin/mycelium\ntwo: /usr/bin/mycelium\n",
            Path::new("/usr/bin/mycelium")
        )
        .is_err());
    }
    use super::*;
    #[test]
    fn exact_identities_only() {
        for value in ["", "--option", "x=1", "x;id", "x/y", "x\n"] {
            assert!(!identity(value, false));
        }
        assert!(identity("unibus-core", false));
        assert!(identity("1:0.1.0+test1", true));
    }
    #[test]
    fn solver_cannot_expand_scope() {
        assert!(narrow_simulation(
            "Inst unibus-core [0.1] (0.2 repo)\nConf unibus-core (0.2 repo)",
            "unibus-core"
        )
        .is_ok());
        for output in [
            "Inst libc6 (2.40 repo)",
            "Remv unibus-core",
            "Conf another (1)",
            "nothing",
        ] {
            assert!(narrow_simulation(output, "unibus-core").is_err());
        }
    }
    #[test]
    fn digest_validation() {
        assert!(checksum(&"a".repeat(64)));
        assert!(!checksum(&"z".repeat(64)));
    }
    #[test]
    fn plan_digest_binds_local_health_and_both_archives() {
        let mut plan = AptPlan {
            package: "unibus-core".into(), previous: "0.1.0".into(), candidate: "0.1.1".into(), architecture: "amd64".into(),
            previous_sha256: "a".repeat(64), candidate_sha256: "b".repeat(64), executable: "/usr/bin/unibus-router".into(),
            service: serde_json::from_value(serde_json::json!({"unit":"unibus-router.service","readiness":{"kind":"unix","path":"/run/unibus/health.sock","request":"health\n","expect_prefix":"READY unibus\n"}})).unwrap(),
        };
        let before = digest(&plan).unwrap();
        let roundtrip: AptPlan =
            serde_json::from_slice(&serde_json::to_vec(&plan).unwrap()).unwrap();
        assert_eq!(before, digest(&roundtrip).unwrap());
        plan.previous_sha256 = "c".repeat(64);
        assert_ne!(before, digest(&plan).unwrap());
        plan.previous_sha256 = "a".repeat(64);
        plan.service.unit = "different.service".into();
        assert_ne!(before, digest(&plan).unwrap());
    }
}
