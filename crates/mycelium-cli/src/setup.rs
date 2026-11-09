use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

pub async fn run(args: &[String]) -> Result<Vec<String>, String> {
    let packaged = crate::packaged::current()?;
    if args.iter().any(|argument| argument == "--packaged") && !packaged {
        return Err("--packaged requires the installed owner-built Mycelium Debian package".into());
    }
    let system_service = packaged || args.iter().any(|argument| argument == "--system-service");
    let local_gateway = args.iter().any(|argument| argument == "--local-gateway");
    let trust_gateway = args.iter().any(|argument| argument == "--trust-cert");
    if trust_gateway && !local_gateway {
        return Err("--trust-cert requires --local-gateway".into());
    }
    if local_gateway && packaged {
        return Err("--local-gateway is not available in the packaged system installation".into());
    }
    let home = value(args, "--path").map(expand_home).unwrap_or_else(|| {
        if packaged { PathBuf::from(crate::packaged::HOME) } else { myceliumd::home_dir() }
    });
    if packaged { crate::packaged::validate(&home, system_service)?; }
    if args.iter().any(|argument| argument == "--repair") {
        let mut lines = crate::enroll::repair_peer_service(
            &home,
            value(args, "--site"),
            system_service,
        )?;
        lines.extend(install_local_gateway(local_gateway, &home, trust_gateway).await?);
        // DNS is optional by design, so a resolver that cannot start is
        // reported here rather than turning a good peer repair into a failure.
        match crate::dns::ensure(&home).await {
            Ok(dns) => lines.extend(dns),
            Err(error) => lines.push(format!("DNS resolver not applied: {error}")),
        }
        return Ok(lines);
    }
    let claim_path = value(args, "--claim-file").map(expand_home);
    if value(args, "--claim").is_some() && claim_path.is_some() {
        return Err("setup accepts only one of --claim or --claim-file".into());
    }
    let claim_from_file = claim_path
        .as_deref()
        .map(read_claim_file)
        .transpose()?;
    let claim = value(args, "--claim").or(claim_from_file.as_deref());
    let embedded = claim
        .map(crate::invite::decode_pair_claim)
        .transpose()?
        .flatten();
    let gateway = embedded
        .as_ref()
        .map(|(endpoint, _, _, _)| endpoint.clone())
        .or_else(|| value(args, "--gateway").map(str::to_owned))
        .or_else(|| std::env::var("MYCELIUM_GATEWAY").ok())
        .ok_or_else(|| "setup needs a pairing claim or --gateway HTTPS-URL".to_owned())?;
    if gateway.starts_with("iroh-pair:") && !cfg!(feature = "iroh-sync") {
        return Err("Iroh enrollment requires a binary built with --features iroh-sync".into());
    }
    if embedded
        .as_ref()
        .is_some_and(|(_, _, _, kind)| *kind == crate::invite::InvitationKind::Peer)
    {
        let result = setup_peer(
            embedded.as_ref().expect("checked above"),
            Some(home.clone()),
            system_service,
        )
        .await;
        remove_consumed_claim(&result, claim_path.as_deref())?;
        let mut lines = result?;
        lines.extend(install_local_gateway(local_gateway, &home, trust_gateway).await?);
        return Ok(lines);
    }
    let ssh_dir = user_home()?.join(".ssh");
    let private_key = value(args, "--key")
        .map(expand_home)
        .unwrap_or_else(|| ssh_dir.join("id_ed25519"));
    let public_key = PathBuf::from(format!("{}.pub", private_key.display()));
    let certificate = value(args, "--certificate")
        .map(expand_home)
        .unwrap_or_else(|| myceliumd::home_dir().join("ssh/user-cert.pub"));

    if !private_key.is_file() || !public_key.is_file() {
        if private_key.exists() || public_key.exists() {
            return Err(format!(
                "SSH identity is incomplete: expected both {} and {}",
                private_key.display(),
                public_key.display()
            ));
        }
        if let Some(parent) = private_key.parent() {
            fs::create_dir_all(parent)
                .map_err(|error| format!("create {}: {error}", parent.display()))?;
        }
        let status = Command::new("ssh-keygen")
            .args(["-q", "-t", "ed25519", "-N", "", "-f"])
            .arg(&private_key)
            .status()
            .map_err(|error| format!("run ssh-keygen: {error}"))?;
        if !status.success() {
            return Err(format!("ssh-keygen exited with {status}"));
        }
    }

    let mut request = vec![
        "--gateway".to_owned(),
        gateway,
        "--public-key".to_owned(),
        path_string(&public_key)?,
        "--certificate".to_owned(),
        path_string(&certificate)?,
        "--write".to_owned(),
    ];
    let mut lines = if let Some(claim) = claim {
        let secret = embedded
            .as_ref()
            .map_or(claim, |(_, secret, _, _)| secret.as_str());
        request.extend(["--claim".to_owned(), secret.to_owned()]);
        crate::oidc_gateway::redeem(&request).await?
    } else {
        request.extend([
            "join".to_owned(),
            "--ttl".to_owned(),
            value(args, "--ttl").unwrap_or("8h").to_owned(),
        ]);
        copy_option(args, "--grant", &mut request);
        copy_option(args, "--provider", &mut request);
        copy_option(args, "--providers", &mut request);
        copy_option(args, "--token-env", &mut request);
        crate::oidc_gateway::join(&request).await?
    };
    persist_renewal_public_key(&public_key, &myceliumd::home_dir())?;
    lines.push(format!(
        "setup complete; SSH identity: {}, certificate: {}",
        private_key.display(),
        certificate.display()
    ));
    remove_consumed_claim(&Ok(()), claim_path.as_deref())?;
    lines.extend(install_local_gateway(local_gateway, &home, trust_gateway).await?);
    Ok(lines)
}

async fn install_local_gateway(
    local_gateway: bool,
    home: &Path,
    trust: bool,
) -> Result<Vec<String>, String> {
    if !local_gateway {
        return Ok(Vec::new());
    }
    crate::gateway::install_default(home, trust).await
}

fn read_claim_file(path: &Path) -> Result<String, String> {
    let metadata = fs::metadata(path)
        .map_err(|error| format!("read claim metadata {}: {error}", path.display()))?;
    if !metadata.is_file() {
        return Err(format!("claim file is not a regular file: {}", path.display()));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(format!(
                "claim file must not be accessible by group or other users: {}",
                path.display()
            ));
        }
    }
    if metadata.len() > 4096 {
        return Err(format!("claim file exceeds 4096 bytes: {}", path.display()));
    }
    let claim = fs::read_to_string(path)
        .map_err(|error| format!("read claim file {}: {error}", path.display()))?;
    let claim = claim.trim();
    if claim.is_empty() {
        return Err(format!("claim file is empty: {}", path.display()));
    }
    Ok(claim.to_owned())
}

fn remove_consumed_claim<T>(result: &Result<T, String>, path: Option<&Path>) -> Result<(), String> {
    if result.is_ok() {
        if let Some(path) = path {
            fs::remove_file(path)
                .map_err(|error| format!("remove consumed claim {}: {error}", path.display()))?;
        }
    }
    Ok(())
}

async fn setup_peer(
    claim: &(String, String, String, crate::invite::InvitationKind),
    home: Option<PathBuf>,
    system_service: bool,
) -> Result<Vec<String>, String> {
    let home = home.unwrap_or_else(myceliumd::home_dir);
    let packaged = crate::packaged::current()?;
    if packaged {
        crate::packaged::validate_new_peer(&home, system_service)?;
        crate::packaged::private_home(&home)?;
    }
    if claim.0.starts_with("iroh-pair:") && (home.join("iroh-sync.json").exists()
        || home.join("pki/node-key.pem").exists()) {
        return Err("refusing new-peer enrollment over an existing peer identity/configuration".into());
    }
    let staging = home.join("enrollment-staging");
    fs::create_dir_all(&staging)
        .map_err(|error| format!("create {}: {error}", staging.display()))?;
    let key = staging.join("node-key.pem");
    let csr = staging.join("node.csr");
    if key.exists() || csr.exists() {
        return Err(format!(
            "peer enrollment staging already exists at {}; remove it after checking whether an earlier enrollment completed",
            staging.display()
        ));
    }
    let key_text = path_string(&key)?;
    let csr_text = path_string(&csr)?;
    command(
        "openssl",
        &["genpkey", "-algorithm", "ED25519", "-out", &key_text],
    )?;
    command(
        "openssl",
        &[
            "req",
            "-new",
            "-key",
            &key_text,
            "-out",
            &csr_text,
            "-subj",
            &format!("/CN={}", claim.2),
            "-addext",
            "extendedKeyUsage=serverAuth,clientAuth",
        ],
    )?;
    let ssh_dir = if packaged { home.join("ssh") } else { user_home()?.join(".ssh") };
    let ssh_key = ssh_dir.join("id_ed25519");
    let ssh_public = PathBuf::from(format!("{}.pub", ssh_key.display()));
    if !ssh_key.is_file() || !ssh_public.is_file() {
        if ssh_key.exists() || ssh_public.exists() {
            return Err(
                "SSH identity is incomplete; expected id_ed25519 and id_ed25519.pub".into(),
            );
        }
        fs::create_dir_all(&ssh_dir)
            .map_err(|error| format!("create {}: {error}", ssh_dir.display()))?;
        let status = Command::new("ssh-keygen")
            .args(["-q", "-t", "ed25519", "-N", "", "-f"])
            .arg(&ssh_key)
            .status()
            .map_err(|error| format!("run ssh-keygen: {error}"))?;
        if !status.success() {
            return Err(format!("ssh-keygen exited with {status}"));
        }
    }
    let ssh_certificate = home.join("ssh/user-cert.pub");
    let mut request = vec![
        "--gateway".into(),
        claim.0.clone(),
        "--claim".into(),
        claim.1.clone(),
        "--peer-csr".into(),
        path_string(&csr)?,
        "--public-key".into(),
        path_string(&ssh_public)?,
        "--certificate".into(),
        path_string(&ssh_certificate)?,
        "--peer-key".into(),
        path_string(&key)?,
        "--home".into(),
        path_string(&home)?,
        "--write".into(),
    ];
    if system_service {
        request.push("--system-service".into());
    }
    let result = crate::oidc_gateway::redeem(&request).await;
    if result.is_ok() {
        persist_renewal_public_key(&ssh_public, &home)?;
        let _ = fs::remove_dir_all(&staging);
    }
    result
}

fn persist_renewal_public_key(public_key: &Path, home: &Path) -> Result<(), String> {
    let destination = home.join("ssh/public-key.pub");
    fs::create_dir_all(destination.parent().expect("SSH state has a parent"))
        .map_err(|error| format!("create SSH renewal state: {error}"))?;
    fs::copy(public_key, &destination).map_err(|error| {
        format!(
            "install SSH renewal public key {}: {error}",
            destination.display()
        )
    })?;
    Ok(())
}

fn command(program: &str, args: &[&str]) -> Result<(), String> {
    let output = Command::new(program)
        .args(args)
        .output()
        .map_err(|error| format!("run {program}: {error}"))?;
    if output.status.success() {
        Ok(())
    } else {
        Err(format!(
            "{program} failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ))
    }
}

fn value<'a>(args: &'a [String], flag: &str) -> Option<&'a str> {
    args.iter()
        .position(|arg| arg == flag)
        .and_then(|index| args.get(index + 1))
        .map(String::as_str)
}

fn copy_option(source: &[String], flag: &str, destination: &mut Vec<String>) {
    if let Some(option) = value(source, flag) {
        destination.extend([flag.to_owned(), option.to_owned()]);
    }
}

fn expand_home(value: &str) -> PathBuf {
    value.strip_prefix("~/").map_or_else(
        || PathBuf::from(value),
        |suffix| user_home().unwrap_or_default().join(suffix),
    )
}
fn user_home() -> Result<PathBuf, String> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or_else(|| "HOME is not set".to_owned())
}

fn path_string(path: &Path) -> Result<String, String> {
    path.to_str()
        .map(str::to_owned)
        .ok_or_else(|| format!("path is not UTF-8: {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temporary_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "mycelium-setup-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    #[test]
    fn claim_file_is_trimmed_and_removed_only_after_success() {
        let path = temporary_path("claim");
        fs::write(&path, "  MYC1-test-claim\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        }
        assert_eq!(read_claim_file(&path).unwrap(), "MYC1-test-claim");
        remove_consumed_claim(&Err::<(), _>("retry".into()), Some(&path)).unwrap();
        assert!(path.exists());
        remove_consumed_claim(&Ok(()), Some(&path)).unwrap();
        assert!(!path.exists());
    }

    #[cfg(unix)]
    #[test]
    fn claim_file_rejects_permissions_visible_to_other_users() {
        use std::os::unix::fs::PermissionsExt;

        let path = temporary_path("permissions");
        fs::write(&path, "MYC1-test-claim").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        let error = read_claim_file(&path).unwrap_err();
        assert!(error.contains("must not be accessible"));
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn optional_join_arguments_are_forwarded_without_a_shell() {
        let source = vec!["--provider".to_owned(), "company-sso".to_owned()];
        let mut destination = Vec::new();
        copy_option(&source, "--provider", &mut destination);
        assert_eq!(destination, source);
    }
}
