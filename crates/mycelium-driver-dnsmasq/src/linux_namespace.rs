//! Native systemd-resolved DNS delegates (258+). The owned suffix scope is
//! never a default DNS route. No uplink, synthetic interface, or DHCP changes.
use super::*;
const DIRECTORY: &str = "/etc/systemd/dns-delegate.d";
const FILE: &str = "mycelium.dns-delegate";
const SYSTEMCTL: &str = "/usr/bin/systemctl";
const RESOLVECTL: &str = "/usr/bin/resolvectl";
const BUSCTL: &str = "/usr/bin/busctl";
fn command(executable: &str, args: &[&str]) -> Result<String, String> {
    let output = Command::new("/usr/bin/timeout")
        .arg("15")
        .arg(executable)
        .args(args)
        .env("LC_ALL", "C")
        .output()
        .map_err(|e| e.to_string())?;
    if !output.status.success() {
        return Err(format!(
            "{} {} failed: {}",
            executable,
            args.join(" "),
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    String::from_utf8(output.stdout).map_err(|e| e.to_string())
}
fn supported(version: &str) -> bool {
    version
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|number| number.parse::<u32>().ok())
        .is_some_and(|n| n >= 258)
}
fn parameters(settings: &Settings) -> Result<(String, String), String> {
    if settings.resolver.mode != ResolverMode::LocalhostOnly || settings.resolver.listen.len() != 1
    {
        return Err("suffix routing requires one localhost-only listener".into());
    }
    let address = settings.resolver.listen[0];
    if !address.ip().is_loopback() || address.port() == 0 {
        return Err("suffix routing requires a loopback DNS server".into());
    }
    Ok((
        address.to_string(),
        canonical_domain(&settings.resolver.suffix)?,
    ))
}
fn candidate(server: &str, suffix: &str) -> String {
    format!("{MARKER}[Delegate]\nDNS={server}\nDomains=~{suffix}\nDefaultRoute=no\n")
}
fn previous(path: &Path) -> Result<Option<Vec<u8>>, String> {
    if fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_symlink()) {
        return Err("refusing symlink DNS delegation".into());
    }
    #[cfg(unix)]
    if let Ok(metadata) = fs::metadata(path) {
        use std::os::unix::fs::MetadataExt;
        if metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
            return Err("DNS delegation must be root-owned and non-writable by other users".into());
        }
    }
    match fs::read(path) {
        Ok(bytes) if bytes.starts_with(MARKER.as_bytes()) => Ok(Some(bytes)),
        Ok(_) => Err("DNS delegation belongs to another administrator".into()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.to_string()),
    }
}
fn backend() -> Result<(), String> {
    command(SYSTEMCTL, &["is-active", "--quiet", "systemd-resolved"])?;
    if !supported(&command(SYSTEMCTL, &["--version"])?) {
        return Err("suffix-only DNS delegates require systemd-resolved 258+; unchanged".into());
    }
    if fs::canonicalize("/etc/resolv.conf").map_err(|e| e.to_string())?
        != Path::new("/run/systemd/resolve/stub-resolv.conf")
    {
        return Err("OS does not use resolved's stub; refusing resolv.conf changes".into());
    }
    command(
        BUSCTL,
        &[
            "call",
            "org.freedesktop.resolve1",
            "/org/freedesktop/resolve1",
            "org.freedesktop.resolve1.Manager",
            "ListDelegates",
        ],
    )?;
    Ok(())
}
pub(super) fn plan(settings: &Settings) -> Result<Value, String> {
    backend()?;
    let (server, suffix) = parameters(settings)?;
    let path = Path::new(DIRECTORY).join(FILE);
    previous(&path)?;
    for directory in [
        DIRECTORY,
        "/run/systemd/dns-delegate.d",
        "/usr/local/lib/systemd/dns-delegate.d",
        "/usr/lib/systemd/dns-delegate.d",
    ] {
        let entries = match fs::read_dir(directory) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error.to_string()),
        };
        for entry in entries {
            let other = entry.map_err(|e| e.to_string())?.path();
            if other == path || other.extension().and_then(|s| s.to_str()) != Some("dns-delegate") {
                continue;
            }
            if other.file_name().and_then(|s| s.to_str()) == Some(FILE) {
                return Err("Mycelium DNS delegate name is already owned in another configuration directory".into());
            }
            let content = fs::read_to_string(&other).map_err(|e| e.to_string())?;
            if content.lines().any(|line| {
                line.trim().strip_prefix("Domains=").is_some_and(|domains| {
                    domains.split_whitespace().any(|domain| {
                        domain.trim_start_matches('~').trim_end_matches('.') == suffix
                    })
                })
            }) {
                return Err("DNS suffix is already delegated by another administrator".into());
            }
        }
    }
    Ok(
        json!({"backend":"systemd-resolved-dns-delegate","path":path,"candidate":candidate(&server,&suffix),"suffix":suffix,"default_dns_changed":false,"apply_supported":true}),
    )
}
fn reload() -> Result<(), String> {
    // SIGHUP reload retains dynamic per-link state; restarting would discard it.
    command(
        SYSTEMCTL,
        &[
            "kill",
            "--kill-whom=main",
            "--signal=HUP",
            "systemd-resolved.service",
        ],
    )?;
    Ok(())
}
fn snapshot_links() -> Result<Vec<(String, String)>, String> {
    let mut links = Vec::new();
    for entry in fs::read_dir("/sys/class/net").map_err(|e| e.to_string())? {
        let name = entry
            .map_err(|e| e.to_string())?
            .file_name()
            .into_string()
            .map_err(|_| "non-UTF8 network interface")?;
        for action in ["dns", "domain", "default-route"] {
            links.push((
                format!("{name}:{action}"),
                command(RESOLVECTL, &[action, &name])?,
            ));
        }
    }
    links.sort();
    Ok(links)
}
fn delegate_present() -> Result<bool, String> {
    Ok(command(
        BUSCTL,
        &[
            "call",
            "org.freedesktop.resolve1",
            "/org/freedesktop/resolve1",
            "org.freedesktop.resolve1.Manager",
            "GetDelegate",
            "s",
            "mycelium",
        ],
    )
    .is_ok())
}
fn delegate_property(property: &str) -> Result<Value, String> {
    let text = command(
        BUSCTL,
        &[
            "--json=short",
            "get-property",
            "org.freedesktop.resolve1",
            "/org/freedesktop/resolve1/dns_delegate/mycelium",
            "org.freedesktop.resolve1.DnsDelegate",
            property,
        ],
    )?;
    property_data(&text)
}
fn property_data(text: &str) -> Result<Value, String> {
    let value: Value = serde_json::from_str(text).map_err(|e| e.to_string())?;
    value
        .get("data")
        .cloned()
        .ok_or("invalid DNS delegate property".into())
}
fn write_delegate(path: &Path, bytes: &[u8]) -> Result<(), String> {
    atomic_write(path, bytes)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o644)).map_err(|e| e.to_string())?;
    }
    Ok(())
}
fn verify_delegate(server: &str, suffix: &str) -> Result<(), String> {
    let address: std::net::SocketAddr = server
        .parse()
        .map_err(|e: std::net::AddrParseError| e.to_string())?;
    let dns = delegate_property("DNS")?;
    let rows = dns.as_array().ok_or("invalid delegate DNS servers")?;
    let octets = match address.ip() {
        IpAddr::V4(ip) => ip.octets().to_vec(),
        IpAddr::V6(ip) => ip.octets().to_vec(),
    };
    if rows.len() != 1
        || rows[0][1] != json!(if address.is_ipv4() { 2 } else { 10 })
        || rows[0][2] != json!(octets)
        || rows[0][3] != json!(address.port())
        || delegate_property("Domains")? != json!([[suffix, true]])
        || delegate_property("DefaultRoute")? != json!(false)
    {
        return Err("runtime DNS delegate differs from suffix-only intent".into());
    }
    Ok(())
}
pub(super) fn installed(settings: &Settings) -> bool {
    parameters(settings).is_ok_and(|(server, suffix)| {
        previous(&Path::new(DIRECTORY).join(FILE))
            .is_ok_and(|old| old.as_deref() == Some(candidate(&server, &suffix).as_bytes()))
    }) && parameters(settings)
        .is_ok_and(|(server, suffix)| verify_delegate(&server, &suffix).is_ok())
}
fn negative_probe(suffix: &str) -> Result<(), String> {
    use std::net::UdpSocket;
    let socket = UdpSocket::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
    socket
        .set_read_timeout(Some(Duration::from_secs(3)))
        .map_err(|e| e.to_string())?;
    socket.connect("127.0.0.53:53").map_err(|e| e.to_string())?;
    let mut packet = vec![0x6d, 0x79, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
    let name = format!(
        "mycelium-nonexistent-{}-{}.{}",
        std::process::id(),
        now(),
        suffix
    );
    for label in name.split('.') {
        packet.push(label.len() as u8);
        packet.extend(label.as_bytes());
    }
    packet.extend([0, 0, 1, 0, 1]);
    socket.send(&packet).map_err(|e| e.to_string())?;
    let mut response = [0u8; 4096];
    let size = socket.recv(&mut response).map_err(|e| e.to_string())?;
    if size < 12 || response[..2] != packet[..2] || response[2] & 0x80 == 0 || response[3] & 15 != 3
    {
        return Err("unknown suffix name did not return NXDOMAIN through OS stub".into());
    }
    Ok(())
}
pub(super) async fn apply(settings: &Settings, remove: bool) -> Result<Value, String> {
    let plan = plan(settings)?;
    if command("/usr/bin/id", &["-u"])?.trim() != "0" {
        return Err("system DNS delegation requires root".into());
    }
    let path = Path::new(DIRECTORY).join(FILE);
    let old = previous(&path)?;
    if remove && old.is_none() {
        return Ok(json!({"installed":false,"default_dns_changed":false}));
    }
    let directory = Path::new(DIRECTORY);
    if fs::symlink_metadata(directory).is_ok_and(|m| m.file_type().is_symlink()) {
        return Err("refusing symlink DNS directory".into());
    }
    fs::create_dir_all(directory).map_err(|e| e.to_string())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let metadata = fs::metadata(directory).map_err(|e| e.to_string())?;
        if metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
            return Err("DNS directory must be root-owned and not writable by other users".into());
        }
    }
    let links = snapshot_links()?;
    command("/usr/bin/getent", &["ahosts", "example.org"])?;
    let first = if remove {
        None
    } else {
        let records = observe(settings).await?;
        let first = records
            .into_iter()
            .next()
            .ok_or("no fresh record for OS qualification")?;
        verify(settings, &first)?;
        Some(first)
    };
    let (server, suffix) = parameters(settings)?;
    let result: Result<(), String> = (|| {
        if remove {
            fs::remove_file(&path).map_err(|e| e.to_string())?;
        } else {
            write_delegate(&path, candidate(&server, &suffix).as_bytes())?;
        }
        reload()?;
        for _ in 0..20 {
            if if remove {
                !delegate_present()?
            } else {
                verify_delegate(&server, &suffix).is_ok()
            } {
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        if delegate_present()? != !remove {
            return Err("DNS delegate reload postcondition failed".into());
        }
        if !remove {
            verify_delegate(&server, &suffix)?;
        }
        if let Some(first) = &first {
            let answer = command("/usr/bin/getent", &["ahosts", &first.name])?;
            if !answer.lines().any(|line| {
                line.split_whitespace().next() == Some(first.address.to_string().as_str())
            }) {
                return Err("OS DNS answer differs from fresh peer observation".into());
            }
            negative_probe(&suffix)?;
        }
        if snapshot_links()? != links {
            return Err("per-link DNS changed during qualification".into());
        }
        command("/usr/bin/getent", &["ahosts", "example.org"])?;
        Ok(())
    })();
    if let Err(error) = result {
        let expected_present = old.is_some();
        let restored = if let Some(bytes) = old {
            write_delegate(&path, &bytes)
        } else if path.exists() {
            fs::remove_file(&path).map_err(|e| e.to_string())
        } else {
            Ok(())
        };
        restored.map_err(|rollback| format!("{error}; rollback file failed: {rollback}"))?;
        reload().map_err(|rollback| format!("{error}; rollback reload failed: {rollback}"))?;
        for _ in 0..20 {
            if delegate_present()? == expected_present {
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        if delegate_present()? != expected_present || snapshot_links()? != links {
            return Err(format!("{error}; rollback DNS state did not verify"));
        }
        command("/usr/bin/getent", &["ahosts", "example.org"])
            .map_err(|rollback| format!("{error}; rollback public DNS failed: {rollback}"))?;
        return Err(format!("{error}; restored previous DNS delegation"));
    }
    Ok(
        json!({"installed":!remove,"plan":plan,"verified_record":first,"default_dns_changed":false,"per_link_dns_unchanged":true,"negative_namespace_verified":!remove}),
    )
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn busctl_property_keeps_arrays_and_scalar_values() {
        assert_eq!(
            property_data(r#"{"type":"a(sb)","data":[["myc",true]]}"#).unwrap(),
            json!([["myc", true]])
        );
        assert_eq!(
            property_data(r#"{"type":"b","data":false}"#).unwrap(),
            json!(false)
        );
        assert!(property_data(r#"{"type":"b"}"#).is_err());
    }
    #[test]
    #[cfg(unix)]
    fn restored_delegation_stays_readable_to_resolved() {
        use std::os::unix::fs::PermissionsExt;
        let path =
            std::env::temp_dir().join(format!("mycelium-delegate-mode-{}", std::process::id()));
        write_delegate(&path, b"old").unwrap();
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o644
        );
        write_delegate(&path, b"restored").unwrap();
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o644
        );
        fs::remove_file(path).unwrap();
    }
    #[test]
    fn native_delegate_is_suffix_only() {
        let text = candidate("127.0.0.1:1053", "myc");
        assert!(text.contains("Domains=~myc\nDefaultRoute=no"));
        assert!(!text.contains("~."));
        assert!(!text.contains("[Resolve]"));
    }
    #[test]
    fn rejects_older_backend() {
        assert!(!supported("systemd 257 (257.9)"));
        assert!(supported("systemd 258 (258)"));
        assert!(supported("systemd 259 (259.5)"));
        assert!(!supported("invalid"));
    }
    #[test]
    fn rejects_nonlocal_or_multiple_listener() {
        let mut s = super::super::tests::settings();
        s.resolver.listen = vec!["192.0.2.1:1053".parse().unwrap()];
        assert!(parameters(&s).is_err());
        s.resolver.listen = vec![
            "127.0.0.1:1053".parse().unwrap(),
            "[::1]:1053".parse().unwrap(),
        ];
        assert!(parameters(&s).is_err());
    }
}
