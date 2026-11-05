use serde::{Deserialize, Serialize};

use security_framework::passwords::{
    delete_generic_password, get_generic_password, set_generic_password,
};

use crate::backend::{Backend, StoredRecord};
use crate::reference::GeodeRef;
use crate::secret::{SecretBytes, SecretMeta};
use crate::GeodeError;

/// Keychain service attribute that namespaces every geode item.
///
/// A single fixed service keeps all geode items in one searchable group and
/// makes it obvious in Keychain Access which entries belong to the store. The
/// per-entry identity is the [`GeodeRef`] carried in the account attribute, so
/// no secret material ever lands in a keychain attribute.
const SERVICE: &str = "geode.credential-store";

/// Status returned by `SecItemCopyMatching`/`SecItemDelete` when nothing
/// matched. `security-framework-sys` exposes the constant; this crate only
/// re-exports the safe wrapper, so the value is named locally.
const SEC_ITEM_NOT_FOUND: i32 = -25300;

/// Durable backend backed by the macOS login keychain.
///
/// Each [`GeodeRef`] becomes one generic-password item under [`SERVICE`]; the
/// reference is the account name and the payload is a small JSON document (a
/// hex-encoded secret plus its non-secret [`SecretMeta`]). This mirrors
/// [`crate::DiskBackend`] so a read reconstructs the full record, but the
/// secret rests in the keychain's encrypted store instead of a file.
///
/// The keychain is the platform backend on macOS, so secrets gain the OS's
/// protection (hardware-bound key, unlock-on-login) rather than `0600` file
/// permissions. Writes go through the same owner-local path, and access control
/// stays in [`crate::Store`]: this backend only stores and retrieves bytes.
#[derive(Clone, Debug, Default)]
pub struct KeychainBackend;

impl KeychainBackend {
    fn account(reference: &GeodeRef) -> String {
        reference.as_reference()
    }
}

impl Backend for KeychainBackend {
    fn read(&self, reference: &GeodeRef) -> Result<Option<StoredRecord>, GeodeError> {
        match get_generic_password(SERVICE, &Self::account(reference)) {
            Ok(bytes) => {
                let blob: Blob = serde_json::from_slice(&bytes).map_err(|error| {
                    GeodeError::Backend(format!("invalid keychain item: {error}"))
                })?;
                let secret =
                    SecretBytes::from(hex_decode(&blob.secret_hex).ok_or_else(|| {
                        GeodeError::Backend("stored secret is not valid hex".into())
                    })?);
                Ok(Some(StoredRecord::new(secret, blob.meta)))
            }
            Err(error) if error.code() == SEC_ITEM_NOT_FOUND => Ok(None),
            Err(error) => Err(GeodeError::Backend(format!(
                "keychain read failed: {error}"
            ))),
        }
    }

    fn write(&self, reference: &GeodeRef, record: StoredRecord) -> Result<(), GeodeError> {
        let blob = Blob {
            secret_hex: hex_encode(record.secret.expose()),
            meta: record.meta,
        };
        let bytes = serde_json::to_vec(&blob).map_err(|error| {
            GeodeError::Backend(format!("cannot encode keychain item: {error}"))
        })?;
        set_generic_password(SERVICE, &Self::account(reference), &bytes)
            .map_err(|error| GeodeError::Backend(format!("keychain write failed: {error}")))?;
        Ok(())
    }

    fn delete(&self, reference: &GeodeRef) -> Result<bool, GeodeError> {
        match delete_generic_password(SERVICE, &Self::account(reference)) {
            Ok(()) => Ok(true),
            Err(error) if error.code() == SEC_ITEM_NOT_FOUND => Ok(false),
            Err(error) => Err(GeodeError::Backend(format!(
                "keychain delete failed: {error}"
            ))),
        }
    }

    fn writable(&self) -> bool {
        true
    }

    fn kind(&self) -> &'static str {
        "keychain"
    }
}

/// On-disk shape of one keychain item: opaque secret plus its metadata.
///
/// The secret is hex-encoded so the JSON never carries raw bytes that could be
/// mistaken for UTF-8, matching the discipline of [`crate::DiskBackend`]. The
/// whole document lives inside a single encrypted keychain item, so nothing here
/// is exposed beyond a successful lease.
#[derive(Serialize, Deserialize)]
struct Blob {
    secret_hex: String,
    meta: SecretMeta,
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from_digit(((byte >> 4) as u32) % 16, 16).unwrap());
        out.push(char::from_digit(((byte & 0x0f) as u32) % 16, 16).unwrap());
    }
    out
}

fn hex_decode(text: &str) -> Option<Vec<u8>> {
    if text.len() % 2 != 0 {
        return None;
    }
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() / 2);
    let mut i = 0;
    while i < bytes.len() {
        let hi = hex_val(bytes[i])?;
        let lo = hex_val(bytes[i + 1])?;
        out.push((hi << 4) | lo);
        i += 2;
    }
    Some(out)
}

fn hex_val(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}
