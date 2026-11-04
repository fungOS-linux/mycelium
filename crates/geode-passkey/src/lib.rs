//! Software WebAuthn passkeys owned by [`geode`].
//!
//! Geode is the credential owner, not the relying party. A passkey here is a
//! *client* credential: a P-256 private key plus the public metadata a relying
//! party needs. The private key lives in geode under `passkey.assert`; the
//! public metadata (`rp_id`, credential id, user handle, origin, counter) is
//! non-secret and belongs in configuration.
//!
//! Scope is deliberately a software authenticator:
//!
//! - ES256 (COSE algorithm `-7`), `fmt: "none"` attestation.
//! - User presence and user verification flags are asserted, because this
//!   authenticator only runs when the owner invokes it.
//! - Platform passkeys (iCloud Keychain, Google Password Manager) are bound to
//!   the platform app identity and cannot be used by a headless daemon. They are
//!   a separate signer, not a different storage format.
//!
//! This crate does not verify assertions. Relying-party verification belongs to
//! a server library such as `passkey-auth` or `webauthn-rs`, including origin and
//! RP-ID checks, challenge binding, and counter policy.

use std::fmt;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ciborium::value::{Integer, Value};
use geode::{
    Backend, GeodeError, GeodeRef, NewCredential, Purpose, SecretBytes, SecretMeta, Store,
};
use p256::ecdsa::signature::Signer;
use p256::ecdsa::{SigningKey, VerifyingKey};
use p256::pkcs8::{DecodePrivateKey, EncodePrivateKey};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// COSE algorithm identifier for ECDSA w/ SHA-256.
pub const COSE_ALG_ES256: i64 = -7;

/// COSE curve identifier for P-256.
pub const COSE_CRV_P256: i64 = 1;

/// Authenticator data flag: user present.
const FLAG_UP: u8 = 0x01;
/// Authenticator data flag: user verified.
const FLAG_UV: u8 = 0x04;
/// Authenticator data flag: backup eligible.
const FLAG_BE: u8 = 0x08;
/// Authenticator data flag: backed up.
const FLAG_BS: u8 = 0x10;
/// Authenticator data flag: attested credential data included.
const FLAG_AT: u8 = 0x40;

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum PasskeyError {
    #[error("invalid passkey metadata: {0}")]
    InvalidMetadata(String),
    #[error("private key is not a valid P-256 PKCS#8 document")]
    InvalidKey,
    #[error("failed to encode WebAuthn data: {0}")]
    Encoding(String),
    #[error(transparent)]
    Geode(#[from] GeodeError),
}

/// Non-secret passkey metadata.
///
/// Safe to serialize into configuration or publish to a relying party. The
/// private key is never part of this struct.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PasskeyCredential {
    /// Relying-party identifier (a domain, e.g. `sso.fpl.dev`).
    pub rp_id: String,
    /// WebAuthn credential id, raw bytes.
    pub credential_id: Vec<u8>,
    /// Opaque user handle chosen by the relying party.
    #[serde(default)]
    pub user_handle: Vec<u8>,
    /// Origin that will appear in `clientDataJSON`.
    pub origin: String,
    #[serde(default = "default_algorithm")]
    pub algorithm: i64,
    #[serde(default)]
    pub sign_count: u32,
    #[serde(default)]
    pub backup_eligible: bool,
    #[serde(default)]
    pub backup_state: bool,
    #[serde(default)]
    pub transports: Vec<String>,
}

fn default_algorithm() -> i64 {
    COSE_ALG_ES256
}

impl PasskeyCredential {
    pub fn new(
        rp_id: impl Into<String>,
        origin: impl Into<String>,
        credential_id: Vec<u8>,
        user_handle: Vec<u8>,
    ) -> Result<Self, PasskeyError> {
        let credential = Self {
            rp_id: rp_id.into(),
            credential_id,
            user_handle,
            origin: origin.into(),
            algorithm: COSE_ALG_ES256,
            sign_count: 0,
            backup_eligible: false,
            backup_state: false,
            transports: Vec::new(),
        };
        credential.validate()?;
        Ok(credential)
    }

    pub fn validate(&self) -> Result<(), PasskeyError> {
        if self.rp_id.is_empty()
            || self.rp_id.len() > 253
            || self
                .rp_id
                .chars()
                .any(|c| c.is_control() || c.is_whitespace())
        {
            return Err(PasskeyError::InvalidMetadata(
                "rp_id must be a bounded domain without whitespace".into(),
            ));
        }
        if !self.origin.starts_with("https://") {
            return Err(PasskeyError::InvalidMetadata(
                "origin must use https".into(),
            ));
        }
        if self.credential_id.is_empty() || self.credential_id.len() > 1023 {
            return Err(PasskeyError::InvalidMetadata(
                "credential_id must be 1..=1023 bytes".into(),
            ));
        }
        if self.user_handle.len() > 64 {
            return Err(PasskeyError::InvalidMetadata(
                "user_handle must be at most 64 bytes".into(),
            ));
        }
        if self.algorithm != COSE_ALG_ES256 {
            return Err(PasskeyError::InvalidMetadata(
                "only ES256 (COSE -7) is supported".into(),
            ));
        }
        Ok(())
    }

    pub fn credential_id_base64url(&self) -> String {
        URL_SAFE_NO_PAD.encode(&self.credential_id)
    }

    pub fn user_handle_base64url(&self) -> Option<String> {
        (!self.user_handle.is_empty()).then(|| URL_SAFE_NO_PAD.encode(&self.user_handle))
    }
}

/// A software authenticator backed by a P-256 key.
///
/// Debug is redacted; the key itself is not printable and zeroizes on drop.
pub struct SoftwarePasskey {
    credential: PasskeyCredential,
    key: SigningKey,
}

impl fmt::Debug for SoftwarePasskey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SoftwarePasskey")
            .field("rp_id", &self.credential.rp_id)
            .field("credential_id", &self.credential.credential_id_base64url())
            .field("sign_count", &self.credential.sign_count)
            .field("key", &"***redacted***")
            .finish()
    }
}

impl SoftwarePasskey {
    /// Generate a new credential with a random 32-byte credential id.
    pub fn generate(
        rp_id: impl Into<String>,
        origin: impl Into<String>,
        user_handle: Vec<u8>,
    ) -> Result<Self, PasskeyError> {
        let mut credential_id = vec![0u8; 32];
        OsRng.fill_bytes(&mut credential_id);
        let credential = PasskeyCredential::new(rp_id, origin, credential_id, user_handle)?;
        let key = SigningKey::random(&mut OsRng);
        Ok(Self { credential, key })
    }

    /// Load a credential previously persisted in geode.
    pub fn from_pkcs8(pkcs8: &[u8], credential: PasskeyCredential) -> Result<Self, PasskeyError> {
        credential.validate()?;
        let key = SigningKey::from_pkcs8_der(pkcs8).map_err(|_| PasskeyError::InvalidKey)?;
        Ok(Self { credential, key })
    }

    pub fn credential(&self) -> &PasskeyCredential {
        &self.credential
    }

    pub fn credential_mut(&mut self) -> &mut PasskeyCredential {
        &mut self.credential
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        *self.key.verifying_key()
    }

    /// Uncompressed SEC1 public key, for tests and diagnostics.
    pub fn public_key_sec1(&self) -> Vec<u8> {
        self.key
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec()
    }

    /// COSE_Key for the public key, as required in attested credential data.
    pub fn public_key_cose(&self) -> Result<Vec<u8>, PasskeyError> {
        let point = self.key.verifying_key().to_encoded_point(false);
        let x = point
            .x()
            .ok_or_else(|| PasskeyError::Encoding("missing x coordinate".into()))?;
        let y = point
            .y()
            .ok_or_else(|| PasskeyError::Encoding("missing y coordinate".into()))?;
        let cose = Value::Map(vec![
            (
                Value::Integer(Integer::from(1)),
                Value::Integer(Integer::from(2)),
            ),
            (
                Value::Integer(Integer::from(3)),
                Value::Integer(Integer::from(COSE_ALG_ES256)),
            ),
            (
                Value::Integer(Integer::from(-1)),
                Value::Integer(Integer::from(COSE_CRV_P256)),
            ),
            (Value::Integer(Integer::from(-2)), Value::Bytes(x.to_vec())),
            (Value::Integer(Integer::from(-3)), Value::Bytes(y.to_vec())),
        ]);
        let mut out = Vec::new();
        ciborium::ser::into_writer(&cose, &mut out)
            .map_err(|error| PasskeyError::Encoding(error.to_string()))?;
        Ok(out)
    }

    /// PKCS#8 private key document for storage in geode.
    pub fn to_pkcs8(&self) -> Result<SecretBytes, PasskeyError> {
        let document = self
            .key
            .to_pkcs8_der()
            .map_err(|error| PasskeyError::Encoding(error.to_string()))?;
        Ok(SecretBytes::new(document.as_bytes().to_vec()))
    }

    /// Persist the private key in geode under `passkey.assert`.
    ///
    /// Public metadata stays in the caller's configuration. The reference must
    /// be unique per credential.
    pub fn store<B: Backend>(
        &self,
        store: &Store<B>,
        reference: &GeodeRef,
        label: Option<&str>,
    ) -> Result<SecretMeta, PasskeyError> {
        let mut credential =
            NewCredential::passkey(self.to_pkcs8()?).with_purpose(Purpose::passkey_assert());
        credential.label = label.map(str::to_owned);
        Ok(store.insert(reference, credential)?)
    }

    /// Load the private key from geode using a short lease.
    pub fn load<B: Backend>(
        store: &Store<B>,
        reference: &GeodeRef,
        credential: PasskeyCredential,
    ) -> Result<Self, PasskeyError> {
        let lease = store.lease(
            reference,
            &Purpose::passkey_assert(),
            std::time::Duration::from_secs(5),
        )?;
        Self::from_pkcs8(lease.expose()?, credential)
    }

    /// Produce a WebAuthn registration response (`webauthn.create`).
    ///
    /// `challenge_b64url` is the challenge exactly as the relying party sent it.
    pub fn registration(&self, challenge_b64url: &str) -> Result<Registration, PasskeyError> {
        let client_data_json = self.client_data_json("webauthn.create", challenge_b64url)?;

        let mut auth_data = self.rp_id_hash().to_vec();
        auth_data.push(
            FLAG_UP
                | FLAG_UV
                | FLAG_AT
                | if self.credential.backup_eligible {
                    FLAG_BE
                } else {
                    0
                }
                | if self.credential.backup_state {
                    FLAG_BS
                } else {
                    0
                },
        );
        auth_data.extend_from_slice(&self.credential.sign_count.to_be_bytes());
        auth_data.extend_from_slice(&[0u8; 16]); // AAGUID: none
        let credential_id = &self.credential.credential_id;
        let credential_id_len = u16::try_from(credential_id.len())
            .map_err(|_| PasskeyError::Encoding("credential id is too long".into()))?;
        auth_data.extend_from_slice(&credential_id_len.to_be_bytes());
        auth_data.extend_from_slice(credential_id);
        auth_data.extend_from_slice(&self.public_key_cose()?);

        let attestation = Value::Map(vec![
            (Value::Text("fmt".into()), Value::Text("none".into())),
            (Value::Text("attStmt".into()), Value::Map(Vec::new())),
            (
                Value::Text("authData".into()),
                Value::Bytes(auth_data.clone()),
            ),
        ]);
        let mut attestation_object = Vec::new();
        ciborium::ser::into_writer(&attestation, &mut attestation_object)
            .map_err(|error| PasskeyError::Encoding(error.to_string()))?;

        Ok(Registration {
            credential_id: self.credential.credential_id_base64url(),
            attestation_object: URL_SAFE_NO_PAD.encode(attestation_object),
            client_data_json: URL_SAFE_NO_PAD.encode(client_data_json),
        })
    }

    /// Produce a WebAuthn assertion response (`webauthn.get`).
    ///
    /// The signature counter advances on every assertion and is part of the
    /// signed authenticator data, so a relying party can detect clones.
    pub fn assertion(&mut self, challenge_b64url: &str) -> Result<Assertion, PasskeyError> {
        self.credential.sign_count = self.credential.sign_count.wrapping_add(1);
        let client_data_json = self.client_data_json("webauthn.get", challenge_b64url)?;

        let mut auth_data = self.rp_id_hash().to_vec();
        auth_data.push(
            FLAG_UP
                | FLAG_UV
                | if self.credential.backup_eligible {
                    FLAG_BE
                } else {
                    0
                }
                | if self.credential.backup_state {
                    FLAG_BS
                } else {
                    0
                },
        );
        auth_data.extend_from_slice(&self.credential.sign_count.to_be_bytes());

        let mut signed = auth_data.clone();
        signed.extend_from_slice(&Sha256::digest(&client_data_json));
        let signature: p256::ecdsa::Signature = self.key.sign(&signed);
        let signature = signature.to_der();

        Ok(Assertion {
            credential_id: self.credential.credential_id_base64url(),
            authenticator_data: URL_SAFE_NO_PAD.encode(auth_data),
            client_data_json: URL_SAFE_NO_PAD.encode(client_data_json),
            signature: URL_SAFE_NO_PAD.encode(signature.as_bytes()),
            user_handle: self.credential.user_handle_base64url(),
        })
    }

    fn rp_id_hash(&self) -> [u8; 32] {
        Sha256::digest(self.credential.rp_id.as_bytes()).into()
    }

    fn client_data_json(
        &self,
        ceremony: &str,
        challenge_b64url: &str,
    ) -> Result<Vec<u8>, PasskeyError> {
        serde_json::to_vec(&serde_json::json!({
            "type": ceremony,
            "challenge": challenge_b64url,
            "origin": self.credential.origin,
            "crossOrigin": false,
        }))
        .map_err(|error| PasskeyError::Encoding(error.to_string()))
    }
}

/// Registration response (public values only).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Registration {
    pub credential_id: String,
    pub attestation_object: String,
    pub client_data_json: String,
}

/// Assertion response (public values only).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Assertion {
    pub credential_id: String,
    pub authenticator_data: String,
    pub client_data_json: String,
    pub signature: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_handle: Option<String>,
}
