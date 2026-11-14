//! Owner-built static Linux Mycelium Debian payload, with no maintainer scripts.
mod notices;
use std::os::unix::fs::PermissionsExt;
use std::{
    env, fs,
    path::{Path, PathBuf},
    process::Command,
};
type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
const SERVICE: &str = include_str!("../assets/mycelium.service");
const ADAPTER: &str = include_str!("../assets/first-contact");
const CONTACT_UNIT: &str = include_str!("../assets/first-contact.conf");
const MIT: &str = include_str!("../../../LICENSE");
const APACHE: &str = include_str!("../../../LICENSE-APACHE");
const WORKSPACE: &str = include_str!("../../../Cargo.toml");
const LOCK: &[u8] = include_bytes!("../../../Cargo.lock");

fn architecture(bytes: &[u8]) -> Result<&'static str> {
    if bytes.len() < 20 || &bytes[..4] != b"\x7fELF" || bytes[4] != 2 || bytes[5] != 1 {
        return Err("expected 64-bit little-endian Linux ELF executable".into());
    }
    if !matches!(u16::from_le_bytes([bytes[16], bytes[17]]), 2 | 3) {
        return Err("ELF must be an executable or position-independent executable".into());
    }
    match u16::from_le_bytes([bytes[18], bytes[19]]) {
        62 => Ok("amd64"),
        183 => Ok("arm64"),
        _ => Err("unsupported ELF architecture".into()),
    }
}

fn revision(value: &str) -> bool {
    value.len() == 40
        && value
            .bytes()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
}
fn version(value: &str) -> bool {
    value.len() <= 100
        && value.starts_with(|c: char| c.is_ascii_digit())
        && value
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b".+:~-".contains(&c))
}
fn binary_version() -> Result<&'static str> {
    let section = WORKSPACE
        .split_once("[workspace.package]")
        .ok_or("missing workspace package metadata")?
        .1;
    let field = section
        .split('[')
        .next()
        .ok_or("missing workspace package section")?
        .lines()
        .find_map(|line| line.strip_prefix("version = \""))
        .and_then(|value| value.strip_suffix('"'))
        .ok_or("missing workspace package version")?;
    Ok(field)
}
fn run(program: &str, arguments: &[&str]) -> Result<String> {
    let output = Command::new(program)
        .args(arguments)
        .env("LC_ALL", "C")
        .output()?;
    if !output.status.success() {
        return Err(format!(
            "{program} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    Ok(String::from_utf8(output.stdout)?)
}
fn write(root: &Path, relative: &str, bytes: &[u8], mode: u32) -> Result<()> {
    let destination = root.join(relative);
    fs::create_dir_all(destination.parent().ok_or("missing payload parent")?)?;
    fs::write(&destination, bytes)?;
    fs::set_permissions(destination, fs::Permissions::from_mode(mode))?;
    for directory in root.join(relative).ancestors().skip(1) {
        if !directory.starts_with(root) {
            break;
        }
        fs::set_permissions(directory, fs::Permissions::from_mode(0o755))?;
    }
    Ok(())
}
fn build(
    binary: &Path,
    directory: &Path,
    artifact_version: &str,
    source: &str,
    notice_root: Option<&Path>,
) -> Result<PathBuf> {
    if !version(artifact_version) || !revision(source) {
        return Err(
            "requires exact Debian artifact version and full lowercase source commit".into(),
        );
    }
    if !fs::symlink_metadata(binary)?.file_type().is_file() {
        return Err("binary must be a regular file, not a symlink".into());
    }
    let bytes = fs::read(binary)?;
    let architecture = architecture(&bytes)?;
    let path = binary.to_str().ok_or("non-UTF8 binary path")?;
    let dynamic = run("readelf", &["--dynamic", path])?;
    let program_headers = run("readelf", &["--program-headers", path])?;
    if dynamic.contains("(NEEDED)")
        || program_headers.contains("INTERP")
        || !program_headers.contains("LOAD")
    {
        return Err("initial owner package requires a static musl binary; dynamic ABI mapping is not qualified".into());
    }
    let digest = run("sha256sum", &[path])?
        .split_whitespace()
        .next()
        .ok_or("missing binary digest")?
        .to_owned();
    // Binary and packager revisions can differ for notice-only repackaging.
    // Release evidence must retain both clean source archives independently.
    let workspace_version = binary_version()?;
    let packager_source = option_env!("MYCELIUM_PACKAGER_SOURCE_COMMIT");
    let third_party = if let Some(notice_root) = notice_root {
        if !packager_source.is_some_and(revision) {
            return Err("notice package requires compiled MYCELIUM_PACKAGER_SOURCE_COMMIT from its clean archive".into());
        }
        Some(notices::load(
            notice_root,
            &digest,
            source,
            &notices::digest(LOCK)?,
        )?)
    } else {
        None
    };
    // Every supplied notice is validated and captured before output creation.
    fs::create_dir_all(directory)?;
    let name = format!("mycelium_{artifact_version}_{architecture}.deb");
    let destination = directory.join(name);
    if destination.exists() {
        return Err("refusing to overwrite an existing package".into());
    }
    let stage_text = run(
        "mktemp",
        &[
            "-d",
            &format!("{}/.mycelium-deb.XXXXXX", directory.display()),
        ],
    )?;
    let stage = PathBuf::from(stage_text.trim());
    let root = stage.join("root");
    let result = (|| {
        let control = format!("Package: mycelium\nVersion: {artifact_version}\nArchitecture: {architecture}\nMaintainer: Future Present Labs <hello@fpl.dev>\nSection: admin\nPriority: optional\nDepends: ca-certificates, openssl, openssh-client, iproute2, systemd, dpkg\nDescription: Mycelium enrolled system peer and management CLI\n Private enrollment state is created only by an explicit operator claim.\n");
        write(&root, "DEBIAN/control", control.as_bytes(), 0o644)?;
        write(&root, "usr/bin/mycelium", &bytes, 0o755)?;
        write(
            &root,
            "usr/lib/systemd/system/mycelium.service",
            SERVICE.as_bytes(),
            0o644,
        )?;
        write(
            &root,
            "usr/lib/fungos/first-contact.d/mycelium",
            ADAPTER.as_bytes(),
            0o755,
        )?;
        write(
            &root,
            "usr/lib/systemd/system/fungos-first-contact.service.d/20-mycelium-package.conf",
            CONTACT_UNIT.as_bytes(),
            0o644,
        )?;
        let copyright = format!("Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/\nUpstream-Name: Mycelium\nSource: https://github.com/mycelium-linux/mycelium/tree/{source}\n\nFiles: usr/lib/* usr/share/doc/mycelium/LICENSE* usr/share/doc/mycelium/build-inputs\nCopyright: Mycelium contributors\nLicense: MIT or Apache-2.0\n See LICENSE and LICENSE-APACHE in this directory.\n\nFiles: usr/bin/mycelium usr/share/doc/mycelium/third-party-notices/*\nCopyright: Mycelium contributors and respective dependency authors\nLicense: multiple\n First-party Mycelium code is MIT or Apache-2.0. Statically embedded\n dependencies retain their individual licenses; see third-party-notices.\n Missing third-party notices make this a qualification-only package.\n Corresponding source must accompany the complete release source bundle;\n this notice does not relicense dependencies or assert legal clearance.\n");
        write(
            &root,
            "usr/share/doc/mycelium/copyright",
            copyright.as_bytes(),
            0o644,
        )?;
        write(
            &root,
            "usr/share/doc/mycelium/LICENSE",
            MIT.as_bytes(),
            0o644,
        )?;
        write(
            &root,
            "usr/share/doc/mycelium/LICENSE-APACHE",
            APACHE.as_bytes(),
            0o644,
        )?;
        let mut provenance = format!("source_url=https://github.com/mycelium-linux/mycelium\nsource_commit={source}\npackager_source_commit={}\nartifact_version={artifact_version}\nworkspace_binary_version={workspace_version}\narchitecture={architecture}\nbinary_sha256={digest}\nupdate_owner=apt\nlegal_clearance=not-asserted\n", packager_source.unwrap_or("unrecorded"));
        if let Some(notices) = &third_party {
            provenance.push_str(&format!("third_party_coverage=reviewed-complete\nthird_party_inventory_sha256={}\ncargo_lock_sha256={}\n", notices.inventory_sha256, notices.lock_sha256));
            for (relative, bytes) in &notices.files {
                write(
                    &root,
                    &format!("usr/share/doc/mycelium/third-party-notices/{relative}"),
                    bytes,
                    0o644,
                )?;
            }
        } else {
            provenance.push_str("third_party_coverage=unknown\nrelease_use=qualification-only\n");
        }
        write(
            &root,
            "usr/share/doc/mycelium/build-inputs",
            provenance.as_bytes(),
            0o644,
        )?;
        if let Some(notices) = &third_party {
            // Rehash staged immutable captures, not mutable source paths.
            for (relative, bytes) in &notices.files {
                let staged = fs::read(
                    root.join("usr/share/doc/mycelium/third-party-notices")
                        .join(relative),
                )?;
                if notices::digest(&staged)? != notices::digest(bytes)? {
                    return Err("staged notice digest mismatch".into());
                }
            }
        }
        let archive = stage.join("package.deb");
        run(
            "dpkg-deb",
            &[
                "--root-owner-group",
                "--build",
                root.to_str().ok_or("non-UTF8 stage")?,
                archive.to_str().ok_or("non-UTF8 archive")?,
            ],
        )?;
        fs::set_permissions(&archive, fs::Permissions::from_mode(0o644))?;
        fs::hard_link(&archive, &destination)?; // Atomic publication, no overwrite.
        Ok(destination.clone())
    })();
    // Only the exact mktemp directory created by this invocation is removed.
    let cleanup = fs::remove_dir_all(&stage);
    if result.is_ok() {
        cleanup?;
    }
    result
}
fn main() -> Result<()> {
    let args: Vec<_> = env::args().skip(1).collect();
    if args.len() != 4 && !(args.len() == 6 && args[4] == "--third-party-notices") {
        return Err("usage: mycelium-debian-package STATIC_BINARY OUTPUT_DIRECTORY ARTIFACT_VERSION BINARY_SOURCE_COMMIT [--third-party-notices DIRECTORY]".into());
    }
    let path = build(
        Path::new(&args[0]),
        Path::new(&args[1]),
        &args[2],
        &args[3],
        args.get(5).map(Path::new),
    )?;
    println!("{}", path.display());
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn derives_supported_architectures() {
        let mut header = [0; 20];
        header[..4].copy_from_slice(b"\x7fELF");
        header[4] = 2;
        header[5] = 1;
        header[16] = 2;
        header[18] = 62;
        assert_eq!(architecture(&header).unwrap(), "amd64");
        header[18] = 183;
        assert_eq!(architecture(&header).unwrap(), "arm64");
        header[18] = 3;
        assert!(architecture(&header).is_err());
    }
    #[test]
    fn rejects_non_elf() {
        assert!(architecture(b"shell script").is_err());
    }
    #[test]
    fn validates_pins() {
        assert!(revision(&"a".repeat(40)));
        assert!(!revision("master"));
        assert!(!revision(&"A".repeat(40)));
        assert!(version("0.2.5+rc1"));
        assert!(!version("0.1.0\nDepends: bad"));
    }
    #[test]
    fn derives_workspace_version() {
        assert!(version(binary_version().unwrap()));
    }
    #[test]
    fn payload_has_no_implicit_activation_or_credentials() {
        assert!(SERVICE.contains("ConditionPathExists=/var/lib/mycelium/node.env"));
        assert!(
            CONTACT_UNIT.contains("[Unit]\nConditionPathExists=/run/fungos-first-contact/claim")
        );
        assert!(!SERVICE.contains("MYCELIUM_RELEASE_KEYS="));
        assert!(!ADAPTER.contains(". \"$1\""));
    }
}
