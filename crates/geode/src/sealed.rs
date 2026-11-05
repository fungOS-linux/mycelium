//! Sealed-envelope group encryption.
//!
//! A sealed envelope is an AES-256-GCM ciphertext encrypted to a recipient key.
//! Only the matching private key can open it, so the plaintext never leaves the
//! encrypting process and never appears in the serialized envelope.
//!
//! This is the crypto primitive behind sharing: an owner seals a passphrase to
//! a group key and gossips the resulting envelope; a device opens it with its
//! own copy of the key. The envelope carries no plaintext, so gossip never
//! transports a secret in the clear.
//!
//! The group model here is a shared secret: the owner and every device that
//! should read the record are provisioned the same [`GroupKey`] offline. The
//! owner seals with it, each device opens with its copy. An asymmetric variant
//! (owner keypair, device private keys) is the natural next step.

use aes_gcm::aead::{generic_array::GenericArray, Aead, KeyInit, Payload};
use aes_gcm::Aes256Gcm;
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};

pub const IV_LEN: usize = 12;
pub const TAG_LEN: usize = 16;
pub const KEY_LEN: usize = 32;

type Cipher = Aes256Gcm;

/// The 32-byte AES-256 key for a group key. Derived deterministically from the
/// key material so a device can derive the same key from its copy alone.
fn key_from_group(group: &GroupKey) -> [u8; KEY_LEN] {
    let mut hasher = Sha256::new();
    hasher.update(group.as_slice());
    let digest = hasher.finalize();
    let mut key = [0u8; KEY_LEN];
    key.copy_from_slice(&digest);
    key
}

/// A group shared secret. The owner and each device hold the same bytes; the
/// owner seals to it, a device opens with its copy.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct GroupKey([u8; KEY_LEN]);

impl GroupKey {
    /// Build a group key from raw bytes.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, SealedError> {
        let mut key = [0u8; KEY_LEN];
        key.copy_from_slice(bytes);
        Ok(Self(key))
    }

    fn as_slice(&self) -> &[u8] {
        &self.0
    }

    /// The raw key bytes.
    pub fn as_key_bytes(&self) -> [u8; KEY_LEN] {
        self.0
    }
}

/// Why a sealed envelope could not be produced or consumed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SealedError {
    /// The key was the wrong length.
    Key,
    /// The blob was shorter than an IV plus a GCM tag.
    Short,
    /// Encryption failed.
    Encrypt,
    /// The ciphertext failed authentication and was not decrypted.
    Decrypt,
}

impl std::fmt::Display for SealedError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SealedError::Key => write!(f, "invalid group key length"),
            SealedError::Short => write!(f, "sealed envelope is too short"),
            SealedError::Decrypt => write!(f, "sealed envelope failed authentication"),
            SealedError::Encrypt => write!(f, "sealed envelope encryption failed"),
        }
    }
}
impl std::error::Error for SealedError {}

/// An AES-256-GCM encryption failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SealedEncryptError {
    Encrypt,
}

impl std::fmt::Display for SealedEncryptError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SealedEncryptError::Encrypt => write!(f, "sealed envelope encryption failed"),
        }
    }
}

impl std::error::Error for SealedEncryptError {}

/// An IV-prefixed AES-256-GCM envelope. The IV precedes the ciphertext so the
/// whole blob is self-describing and needs no side channel. This is exactly
/// what gossips: a ciphertext plus metadata, no plaintext.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SealedEnvelope {
    iv: [u8; IV_LEN],
    body: Vec<u8>,
}

impl SealedEnvelope {
    /// Seal `plaintext` to `key`. Returns the IV-prefixed blob.
    pub fn seal(key: &GroupKey, plaintext: &[u8]) -> Result<Self, SealedError> {
        let cipher =
            Aes256Gcm::new_from_slice(&key_from_group(key)).map_err(|_| SealedError::Key)?;
        let mut iv = [0u8; IV_LEN];
        OsRng.fill_bytes(&mut iv);
        let nonce = GenericArray::clone_from_slice(&iv);
        let sealed = cipher
            .encrypt(
                &nonce,
                Payload {
                    msg: plaintext,
                    aad: &[],
                },
            )
            .map_err(|_| SealedError::Encrypt)?;
        let mut body = Vec::with_capacity(IV_LEN + sealed.len());
        body.extend_from_slice(&iv);
        body.extend_from_slice(&sealed);
        Ok(Self { iv, body })
    }

    /// Decrypt an IV-prefixed blob produced by [`Self::seal`].
    ///
    /// A wrong key or a tampered blob fails authentication and returns an error
    /// rather than revealing any bytes.
    pub fn open(key: &GroupKey, blob: &[u8]) -> Result<Vec<u8>, SealedError> {
        let cipher =
            Aes256Gcm::new_from_slice(&key_from_group(key)).map_err(|_| SealedError::Key)?;
        let (iv, body) = blob.split_at(IV_LEN);
        if body.len() < TAG_LEN {
            return Err(SealedError::Short);
        }
        cipher
            .decrypt(&GenericArray::clone_from_slice(iv), body)
            .map_err(|_| SealedError::Decrypt)
    }

    /// The IV that precedes the ciphertext.
    pub fn iv(&self) -> &[u8] {
        &self.iv
    }

    /// The ciphertext that follows the IV.
    pub fn ciphertext(&self) -> &[u8] {
        &self.body
    }
}
