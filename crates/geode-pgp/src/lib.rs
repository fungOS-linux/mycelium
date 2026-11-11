//! Detached OpenPGP signatures over geode-owned private keys.
//!
//! Geode owns the armored secret key; this connector leases it for one
//! signature, imports it into an ephemeral GnuPG home, signs, and drops both.
//! The caller receives only the detached signature. The key is never written to
//! configuration, a record, or a log.
//!
//! This is a software signer. It does not make the key non-exportable; that
//! requires a hardware signing interface such as TPM or Secure Enclave, which
//! `geode-pgp` deliberately does not pretend to provide.
//!
//! The stored key must be unprotected. Geode's encrypted backend is the at-rest
//! boundary; a passphrase-protected key would need a second secret and is not
//! part of this slice.

use std::fmt;
use std::io::Write;
use std::path::Path;
use std::process::{Command, Output, Stdio};
use std::time::Duration;

use geode::{
    Backend, GeodeError, GeodeRef, NewCredential, Purpose, SecretBytes, SecretMeta, Store,
};

/// How long a key may be leased for one signature.
const LEASE_TTL: Duration = Duration::from_secs(5);

/// A defensive bound on the armored private key. Real keys are a few KiB.
const MAX_KEY_BYTES: usize = 256 * 1024;

/// A detached signature is small; anything larger is a tool error.
const MAX_SIGNATURE_BYTES: usize = 64 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum PgpError {
    #[error("invalid PGP key: {0}")]
    InvalidKey(String),
    #[error("invalid PGP fingerprint")]
    InvalidFingerprint,
    #[error("gpg is not available: {0}")]
    ToolUnavailable(String),
    #[error("gpg failed: {0}")]
    Tool(String),
    #[error("signature output is too large")]
    SignatureTooLarge,
    #[error(transparent)]
    Geode(#[from] GeodeError),
}

/// An armored OpenPGP private key plus the public fingerprint it signs with.
///
/// `Debug` is redacted through [`SecretBytes`]. The fingerprint is public and is
/// safe to record in configuration, a delegation, or a store source.
pub struct PgpKey {
    armored: SecretBytes,
    fingerprint: String,
}

impl fmt::Debug for PgpKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PgpKey")
            .field("armored", &self.armored)
            .field("fingerprint", &self.fingerprint)
            .finish()
    }
}

impl PgpKey {
    /// Build a key from an armored private-key block.
    ///
    /// Only armored secret keys are accepted. Binary key packets are not a
    /// configuration format and would make the boundary harder to audit.
    pub fn from_armored(
        armored: impl Into<Vec<u8>>,
        fingerprint: impl AsRef<str>,
    ) -> Result<Self, PgpError> {
        let armored = armored.into();
        if armored.is_empty() || armored.len() > MAX_KEY_BYTES {
            return Err(PgpError::InvalidKey(format!(
                "armored key must be 1..={MAX_KEY_BYTES} bytes"
            )));
        }
        let text = std::str::from_utf8(&armored)
            .map_err(|_| PgpError::InvalidKey("armored key is not UTF-8".into()))?;
        if !text.contains("-----BEGIN PGP PRIVATE KEY BLOCK-----")
            || !text.contains("-----END PGP PRIVATE KEY BLOCK-----")
        {
            return Err(PgpError::InvalidKey(
                "expected an armored PGP PRIVATE KEY BLOCK".into(),
            ));
        }
        Ok(Self {
            armored: SecretBytes::new(armored),
            fingerprint: normalize_fingerprint(fingerprint.as_ref())?,
        })
    }

    /// The public fingerprint this key signs with, normalized to uppercase hex.
    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }

    /// Read the primary secret-key fingerprint from an armored key.
    ///
    /// This is the bootstrap path for a caller that has a Geode reference and
    /// no fingerprint yet. The key is imported into an ephemeral GnuPG home and
    /// removed afterwards; only the public fingerprint is returned.
    pub fn detect_fingerprint(armored: &[u8]) -> Result<String, PgpError> {
        let home = GpgHome::new()?;
        home.import(armored)?;
        home.primary_fingerprint()
    }

    /// Store the key in geode under an explicit purpose allowlist.
    ///
    /// The caller keeps the fingerprint in non-secret configuration or in the
    /// delegation record. Geode metadata deliberately has no field for it.
    pub fn store<B: Backend>(
        &self,
        store: &Store<B>,
        reference: &GeodeRef,
        purposes: impl IntoIterator<Item = Purpose>,
        label: Option<&str>,
    ) -> Result<SecretMeta, PgpError> {
        let mut credential = NewCredential::pgp_key(self.armored.clone()).with_purposes(purposes);
        credential.label = label.map(str::to_owned);
        Ok(store.insert(reference, credential)?)
    }

    /// Lease and load a key from geode for one operation.
    ///
    /// The lease is short and drops before this function returns; the returned
    /// key owns its own zeroizing copy.
    pub fn load<B: Backend>(
        store: &Store<B>,
        reference: &GeodeRef,
        fingerprint: impl AsRef<str>,
        purpose: Purpose,
    ) -> Result<Self, PgpError> {
        let lease = store.lease(reference, &purpose, LEASE_TTL)?;
        let armored = lease.expose()?.to_vec();
        Self::from_armored(armored, fingerprint)
    }

    /// Produce an armored detached signature over `message`.
    ///
    /// The key is imported into a fresh temporary GnuPG home for this call and
    /// removed afterwards. A passphrase-protected key fails closed; it needs a
    /// passphrase source this connector does not have.
    pub fn sign_detached(&self, message: &[u8]) -> Result<String, PgpError> {
        let home = GpgHome::new()?;
        home.import(self.armored.expose())?;
        home.require_secret_key(&self.fingerprint)?;
        let output = home.run(
            &[
                "--pinentry-mode",
                "loopback",
                "--passphrase",
                "",
                "--armor",
                "--detach-sign",
                "--local-user",
                &self.fingerprint,
                "--output",
                "-",
            ],
            message,
        )?;
        signature_output(&output)
    }

    /// Sign a file without reading it into this process.
    ///
    /// GnuPG reads the path directly. This is the path package signing uses so
    /// a large `.spore` tar is not duplicated in memory.
    pub fn sign_detached_file(&self, path: &Path) -> Result<String, PgpError> {
        let path = path
            .to_str()
            .ok_or_else(|| PgpError::Tool("message path is not UTF-8".into()))?;
        let home = GpgHome::new()?;
        home.import(self.armored.expose())?;
        home.require_secret_key(&self.fingerprint)?;
        let output = home.run_without_stdin(&[
            "--pinentry-mode",
            "loopback",
            "--passphrase",
            "",
            "--armor",
            "--detach-sign",
            "--local-user",
            &self.fingerprint,
            "--output",
            "-",
            path,
        ])?;
        signature_output(&output)
    }

    /// Export the public key for a delegation or a keyring.
    pub fn public_key_armored(&self) -> Result<String, PgpError> {
        let home = GpgHome::new()?;
        home.import(self.armored.expose())?;
        let output = home.run(&["--armor", "--export", &self.fingerprint], b"")?;
        if !output.status.success() {
            return Err(tool_error(&output));
        }
        let public = String::from_utf8(output.stdout)
            .map_err(|_| PgpError::Tool("gpg returned a non-UTF-8 public key".into()))?;
        if !public.contains("-----BEGIN PGP PUBLIC KEY BLOCK-----") {
            return Err(PgpError::Tool(
                "gpg did not export the requested public key".into(),
            ));
        }
        Ok(public)
    }
}

/// Verify an armored detached signature against an armored public key.
///
/// A bad signature is `Ok(false)`; a missing or malformed key is an error.
/// This is the offline path a store uses after resolving a delegation.
pub fn verify_detached(
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<bool, PgpError> {
    let home = GpgHome::new()?;
    home.import(public_key)?;
    let signature_path = home.path().join("signature.asc");
    let message_path = home.path().join("message");
    std::fs::write(&signature_path, signature)
        .map_err(|error| PgpError::Tool(format!("write signature: {error}")))?;
    std::fs::write(&message_path, message)
        .map_err(|error| PgpError::Tool(format!("write message: {error}")))?;
    let output = home.run(
        &[
            "--verify",
            &signature_path.to_string_lossy(),
            &message_path.to_string_lossy(),
        ],
        b"",
    )?;
    match output.status.code() {
        Some(0) => Ok(true),
        // GnuPG uses 1 for a bad signature and 2 for a usage/key error.
        Some(1) => Ok(false),
        _ => Err(tool_error(&output)),
    }
}

fn normalize_fingerprint(value: &str) -> Result<String, PgpError> {
    let compact: String = value
        .chars()
        .filter(|character| !character.is_ascii_whitespace())
        .collect();
    let compact = compact
        .strip_prefix("0x")
        .or_else(|| compact.strip_prefix("0X"))
        .unwrap_or(&compact);
    if compact.len() != 40 && compact.len() != 64 {
        return Err(PgpError::InvalidFingerprint);
    }
    if !compact
        .chars()
        .all(|character| character.is_ascii_hexdigit())
    {
        return Err(PgpError::InvalidFingerprint);
    }
    Ok(compact.to_ascii_uppercase())
}

struct GpgHome {
    dir: tempfile::TempDir,
}

impl GpgHome {
    fn new() -> Result<Self, PgpError> {
        // GnuPG creates a Unix socket inside its home. Keep the path short:
        // the macOS per-user temporary directory can already exceed the
        // `sun_path` limit before GnuPG appends `S.gpg-agent`.
        let base = if Path::new("/tmp").is_dir() {
            std::path::PathBuf::from("/tmp")
        } else {
            std::env::temp_dir()
        };
        let dir = tempfile::Builder::new()
            .prefix("geode-gpg-")
            .tempdir_in(&base)
            .map_err(|error| PgpError::Tool(format!("create temporary GnuPG home: {error}")))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).map_err(
                |error| PgpError::Tool(format!("protect temporary GnuPG home: {error}")),
            )?;
        }
        Ok(Self { dir })
    }

    fn path(&self) -> &Path {
        self.dir.path()
    }

    fn command(&self) -> Command {
        let mut command = Command::new("gpg");
        command
            .arg("--homedir")
            .arg(self.path())
            .args(["--batch", "--no-tty", "--yes", "--quiet"]);
        command
    }

    fn run(&self, args: &[&str], stdin: &[u8]) -> Result<Output, PgpError> {
        let mut command = self.command();
        command
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = command
            .spawn()
            .map_err(|error| PgpError::ToolUnavailable(format!("could not start gpg: {error}")))?;
        if let Some(mut pipe) = child.stdin.take() {
            pipe.write_all(stdin)
                .map_err(|error| PgpError::Tool(format!("write to gpg: {error}")))?;
        }
        child
            .wait_with_output()
            .map_err(|error| PgpError::Tool(format!("wait for gpg: {error}")))
    }

    fn run_without_stdin(&self, args: &[&str]) -> Result<Output, PgpError> {
        let mut command = self.command();
        command
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        command
            .spawn()
            .map_err(|error| PgpError::ToolUnavailable(format!("could not start gpg: {error}")))?
            .wait_with_output()
            .map_err(|error| PgpError::Tool(format!("wait for gpg: {error}")))
    }

    fn import(&self, key: &[u8]) -> Result<(), PgpError> {
        let output = self.run(&["--import"], key)?;
        if !output.status.success() {
            return Err(tool_error(&output));
        }
        Ok(())
    }

    fn require_secret_key(&self, fingerprint: &str) -> Result<(), PgpError> {
        let output = self.run(&["--with-colons", "--list-secret-keys", fingerprint], b"")?;
        if !output.status.success() {
            return Err(PgpError::InvalidKey(
                "the armored key does not contain the requested fingerprint".into(),
            ));
        }
        Ok(())
    }

    fn primary_fingerprint(&self) -> Result<String, PgpError> {
        let output = self.run(&["--with-colons", "--list-secret-keys"], b"")?;
        if !output.status.success() {
            return Err(tool_error(&output));
        }
        let listing = String::from_utf8(output.stdout)
            .map_err(|_| PgpError::Tool("gpg returned a non-UTF-8 key listing".into()))?;
        let fingerprint = listing
            .lines()
            .find(|line| line.starts_with("fpr:"))
            .and_then(|line| line.split(':').nth(9))
            .ok_or_else(|| PgpError::InvalidKey("the armored key has no fingerprint".into()))?;
        normalize_fingerprint(fingerprint)
    }
}

impl Drop for GpgHome {
    fn drop(&mut self) {
        // A unique homedir means this cannot disturb the user's agent.
        let _ = Command::new("gpgconf")
            .arg("--homedir")
            .arg(self.path())
            .args(["--kill", "all"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
}

fn signature_output(output: &Output) -> Result<String, PgpError> {
    if !output.status.success() {
        return Err(tool_error(output));
    }
    if output.stdout.len() > MAX_SIGNATURE_BYTES {
        return Err(PgpError::SignatureTooLarge);
    }
    let signature = String::from_utf8(output.stdout.clone())
        .map_err(|_| PgpError::Tool("gpg returned a non-UTF-8 armored signature".into()))?;
    if !signature.contains("-----BEGIN PGP SIGNATURE-----") {
        return Err(PgpError::Tool(
            "gpg did not return an armored detached signature".into(),
        ));
    }
    Ok(signature)
}

fn tool_error(output: &Output) -> PgpError {
    let stderr = String::from_utf8_lossy(&output.stderr);
    let detail = stderr
        .lines()
        .find(|line| !line.trim().is_empty())
        .unwrap_or("gpg returned a non-zero status")
        .trim();
    let detail: String = detail.chars().take(240).collect();
    PgpError::Tool(detail)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gpg_available() -> bool {
        Command::new("gpg")
            .arg("--version")
            .output()
            .map(|output| output.status.success())
            .unwrap_or(false)
    }

    fn generate_test_key() -> Option<(String, Vec<u8>, Vec<u8>)> {
        if !gpg_available() {
            return None;
        }
        let home = tempfile::Builder::new()
            .prefix("geode-pgp-test-")
            .tempdir()
            .ok()?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(home.path(), std::fs::Permissions::from_mode(0o700)).ok()?;
        }
        let generated = Command::new("gpg")
            .arg("--homedir")
            .arg(home.path())
            .args([
                "--batch",
                "--pinentry-mode",
                "loopback",
                "--passphrase",
                "",
                "--quick-generate-key",
                "geode-pgp test <test@example.invalid>",
                "ed25519",
                "sign",
                "0",
            ])
            .status()
            .ok()?;
        if !generated.success() {
            return None;
        }
        let listing = Command::new("gpg")
            .arg("--homedir")
            .arg(home.path())
            .args(["--batch", "--with-colons", "--list-secret-keys"])
            .output()
            .ok()?;
        let listing = String::from_utf8(listing.stdout).ok()?;
        let fingerprint = listing
            .lines()
            .find(|line| line.starts_with("fpr:"))
            .and_then(|line| line.split(':').nth(9))
            .map(str::to_owned)?;
        let secret = Command::new("gpg")
            .arg("--homedir")
            .arg(home.path())
            .args(["--batch", "--armor", "--export-secret-keys", &fingerprint])
            .output()
            .ok()?;
        let public = Command::new("gpg")
            .arg("--homedir")
            .arg(home.path())
            .args(["--batch", "--armor", "--export", &fingerprint])
            .output()
            .ok()?;
        Some((fingerprint, secret.stdout, public.stdout))
    }

    #[test]
    fn rejects_a_public_key_block() {
        let error = PgpKey::from_armored(
            b"-----BEGIN PGP PUBLIC KEY BLOCK-----\n\n...\n-----END PGP PUBLIC KEY BLOCK-----\n",
            "0123456789ABCDEF0123456789ABCDEF01234567",
        )
        .expect_err("a public key is not a signing key");
        assert!(matches!(error, PgpError::InvalidKey(_)));
    }

    #[test]
    fn normalizes_fingerprints() {
        let key = PgpKey::from_armored(
            b"-----BEGIN PGP PRIVATE KEY BLOCK-----\n\n...\n-----END PGP PRIVATE KEY BLOCK-----\n",
            "0x0123 4567 89ab cdef 0123 4567 89ab cdef 0123 4567",
        )
        .expect("fingerprint with spaces and 0x");
        assert_eq!(
            key.fingerprint(),
            "0123456789ABCDEF0123456789ABCDEF01234567"
        );
    }

    #[test]
    fn signs_and_verifies() {
        let Some((fingerprint, secret, public)) = generate_test_key() else {
            eprintln!("gpg unavailable; skipping signature round-trip");
            return;
        };
        let key = PgpKey::from_armored(secret, &fingerprint).expect("parse secret key");
        let signature = key.sign_detached(b"geode-pgp round trip").expect("sign");
        assert!(verify_detached(&public, b"geode-pgp round trip", signature.as_bytes()).unwrap());
        assert!(!verify_detached(&public, b"tampered", signature.as_bytes()).unwrap());
        let exported = key.public_key_armored().expect("export public key");
        assert!(exported.contains("-----BEGIN PGP PUBLIC KEY BLOCK-----"));
    }

    #[test]
    fn stores_and_loads_from_geode() {
        let Some((fingerprint, secret, _public)) = generate_test_key() else {
            eprintln!("gpg unavailable; skipping geode round-trip");
            return;
        };
        let store = Store::new(geode::MemoryBackend::new());
        let reference = GeodeRef::parse("geode://principal/test/pgp").unwrap();
        let key = PgpKey::from_armored(secret, &fingerprint).expect("parse secret key");
        key.store(
            &store,
            &reference,
            [Purpose::spore_package_sign()],
            Some("test signing key"),
        )
        .expect("store key");

        let loaded = PgpKey::load(
            &store,
            &reference,
            &fingerprint,
            Purpose::spore_package_sign(),
        )
        .expect("load key");
        assert_eq!(loaded.fingerprint(), fingerprint);
        loaded
            .sign_detached(b"from geode")
            .expect("sign with loaded key");

        let denied = PgpKey::load(
            &store,
            &reference,
            &fingerprint,
            Purpose::store_delegation_sign(),
        );
        assert!(matches!(denied, Err(PgpError::Geode(_))));
    }
}
