//! One-way importer from a Bitwarden export into the [`geode`] credential store.
//!
//! This crate *translates* a Bitwarden export into a list of [`ImportedCredential`]
//! values: a [`GeodeRef`] (`geode://<realm>/<account>/<slot>`), an opaque
//! [`SecretBytes`], a purpose allowlist, a kind, and an optional label. It does
//! not touch any store — applying the list is the caller's job — and it performs
//! no sharing/team/organization handling. Only personal login and secure-note
//! items are mapped; card and identity items are skipped.
//!
//! Two export shapes are accepted:
//!
//! * **Raw (plaintext) JSON** — [`import_raw`]. No master password is needed.
//! * **Encrypted JSON** — [`import_encrypted`], decrypted with the master
//!   password and the account email's iteration count (see [`crypto`]).
//!
//! [`geode`]: https://crates.io/crates/geode
use std::collections::BTreeSet;

use geode::{CredentialKind, GeodeRef, Purpose, SecretBytes};

mod crypto;
mod export;

pub use export::CipherKind;

/// Longest [`GeodeRef`] component the importer will emit, matching geode's own
/// limit so every produced reference is valid.
pub const MAX_COMPONENT: usize = 64;

/// The mapped credentials plus a count of items that were skipped.
pub use export::ImportReport;

/// Something went wrong importing a Bitwarden export.
///
/// Messages carry no secret material: a failed decrypt reports only that the
/// password was wrong, never any vault bytes.
#[derive(Debug, thiserror::Error)]
pub enum BitwardenError {
    #[error("the master password does not appear to be correct")]
    BadPassword,
    #[error("could not parse the export: {0}")]
    Parse(String),
    #[error("could not decrypt the export: {0}")]
    Decrypt(String),
    #[error("the Bitwarden export is not supported: {0}")]
    Unsupported(String),
    #[error("a mapped reference is invalid: {0}")]
    Reference(String),
}

/// One credential translated from a Bitwarden export, ready to hand to a
/// [`geode::Store`].
///
/// The secret is opaque and redacts itself in `Debug`, exactly as it is in the
/// store; the importer adds no URL, subject, or item-count surface of its own.
#[derive(Clone, Debug)]
pub struct ImportedCredential {
    pub reference: GeodeRef,
    pub secret: SecretBytes,
    pub kind: CredentialKind,
    pub purposes: BTreeSet<Purpose>,
    pub label: Option<String>,
}

impl ImportedCredential {
    /// The reference this credential would be stored at.
    pub fn reference(&self) -> &GeodeRef {
        &self.reference
    }
}

/// Import a raw (unencrypted) Bitwarden export.
///
/// Useful for exports produced with "Export vault" (plaintext) and for testing,
/// since it needs no master password.
pub fn import_raw(json: &[u8]) -> Result<ImportReport, BitwardenError> {
    let ciphers = export::parse_vault(json)?;
    export::to_credentials(ciphers)
}

/// Import an encrypted Bitwarden export, decrypting it with `master_password`.
///
/// `iterations` is the account's KDF iteration count (the current default is
/// 600_001); it selects the export key derivation. The `email` argument is
/// accepted for interface parity with the Bitwarden CLI but is not required by
/// the export format, so it is currently unused beyond validation.
pub fn import_encrypted(
    json: &[u8],
    master_password: &str,
    email: &str,
    iterations: u32,
) -> Result<ImportReport, BitwardenError> {
    if master_password.is_empty() {
        return Err(BitwardenError::BadPassword);
    }
    if email.trim().is_empty() {
        return Err(BitwardenError::Unsupported(
            "an account email is required".into(),
        ));
    }

    let export_password = format!("{master_password}:{iterations}");
    let key = crypto::export_key(&export_password);

    let export: EncryptedExport = serde_json::from_slice(json)
        .map_err(|error| BitwardenError::Parse(format!("encrypted export: {error}")))?;
    let blob = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        export.encrypted.as_deref().unwrap_or_default(),
    )
    .map_err(|error| BitwardenError::Parse(format!("base64 encrypted field: {error}")))?;
    if blob.is_empty() {
        return Err(BitwardenError::Unsupported(
            "the export has no encrypted payload".into(),
        ));
    }

    let plaintext = match crypto::aes256_cbc_decrypt(&key, &blob) {
        Ok(plaintext) => plaintext,
        Err(_) => return Err(BitwardenError::BadPassword),
    };
    import_raw(&plaintext)
}

/// The encrypted export envelope: base64 ciphertext plus the RSA-wrapped key.
/// Only `encrypted` is read here.
#[derive(serde::Deserialize)]
struct EncryptedExport {
    #[serde(default)]
    encrypted: Option<String>,
}

#[cfg(test)]
mod test {
    use super::*;

    fn encrypted_envelope(plaintext: &[u8]) -> String {
        use aes::cipher::{block_padding::Pkcs7, BlockEncryptMut, KeyIvInit};
        type Aes256CbcEncryptor = cbc::Encryptor<aes::Aes256>;

        // Mirror the derivation in `crypto::export_key`.
        let export_password = "hunter2:600001";
        let key = crypto::export_key(export_password);
        let iv = [0u8; 16];
        let mut buffer = plaintext.to_vec();
        buffer.resize(plaintext.len() + 16, 0);
        let ciphertext = Aes256CbcEncryptor::new(&key.into(), &iv.into())
            .encrypt_padded_mut::<Pkcs7>(&mut buffer, plaintext.len())
            .expect("encrypt vault");
        let mut blob = iv.to_vec();
        blob.extend_from_slice(ciphertext);
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &blob)
    }

    #[test]
    fn encrypted_round_trip_maps_login_and_note() {
        let vault = serde_json::json!({
            "ciphers": [
                {
                    "type": 1,
                    "name": "GitHub",
                    "notes": "dev account",
                    "login": {
                        "username": "octocat",
                        "password": "p@ss word",
                        "uris": [{ "uri": "https://github.com/settings" }]
                    }
                },
                {
                    "type": 2,
                    "name": "Home wifi",
                    "notes": "guest: 1234"
                }
            ]
        });
        let envelope = serde_json::json!({
            "encrypted": encrypted_envelope(serde_json::to_string(&vault).unwrap().as_bytes()),
            "key": "ignored-in-this-import"
        });

        let report = import_encrypted(
            serde_json::to_vec(&envelope).unwrap().as_slice(),
            "hunter2",
            "user@example.com",
            600_001,
        )
        .expect("import encrypted");

        assert_eq!(report.skipped, 0);
        let passwords: Vec<_> = report
            .credentials
            .iter()
            .filter(|c| c.reference.slot() == "password")
            .collect();
        let notes: Vec<_> = report
            .credentials
            .iter()
            .filter(|c| c.reference.slot() == "note")
            .collect();

        assert_eq!(passwords.len(), 1);
        assert_eq!(passwords[0].reference.realm(), "github.com");
        assert_eq!(passwords[0].reference.account(), "octocat");
        assert_eq!(passwords[0].secret.expose_str().unwrap(), "p@ss word");

        assert_eq!(notes.len(), 1);
        assert_eq!(
            notes[0].reference.as_reference(),
            "geode://notes/Home_wifi/note"
        );
        assert_eq!(notes[0].kind, CredentialKind::SecureNote);
    }

    #[test]
    fn wrong_password_is_reported_without_leaking_vault_bytes() {
        let vault = serde_json::json!({
            "ciphers": [{ "type": 1, "name": "x", "login": { "username": "u", "password": "topsecret" } }]
        });
        let envelope = serde_json::json!({
            "encrypted": encrypted_envelope(serde_json::to_string(&vault).unwrap().as_bytes()),
            "key": "ignored"
        });
        let bytes = serde_json::to_vec(&envelope).unwrap();

        let err = import_encrypted(
            bytes.as_slice(),
            "wrong-password",
            "user@example.com",
            600_001,
        )
        .expect_err("wrong password should fail");
        assert!(matches!(err, BitwardenError::BadPassword));
    }

    #[test]
    fn raw_import_skips_card_and_identity() {
        let raw = serde_json::json!({
            "passwords": [{ "type": 1, "name": "site", "login": { "username": "a", "password": "b" } }],
            "cards": [{ "type": 3, "name": "visa" }],
            "identities": [{ "type": 4, "name": "id" }]
        });
        let report = import_raw(serde_json::to_string(&raw).unwrap().as_bytes()).unwrap();
        assert_eq!(report.credentials.len(), 1);
        assert_eq!(report.skipped, 2);
    }
}
