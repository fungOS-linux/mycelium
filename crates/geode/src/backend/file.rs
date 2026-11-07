//! Encrypted file backend for owner-local hosts without a platform key store.
//!
//! The file contains non-secret metadata in the clear and one AES-256-GCM
//! ciphertext per secret, bound to its reference as associated data. The key is
//! supplied by the host (geoded reads a 0600 key file); the file itself is
//! written 0600 and replaced atomically.
//!
//! This is a deliberate, explicit backend. It is not a substitute for Keychain,
//! Secret Service, or TPM sealing: the key file sits next to the store, so a
//! copied disk still contains both pieces. It exists so `geoded` can be useful
//! on a headless host before a platform backend lands.

use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::RwLock;

use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};

use crate::backend::{Backend, StoredRecord};
use crate::reference::GeodeRef;
use crate::secret::SecretMeta;
use crate::GeodeError;

const FILE_VERSION: u32 = 1;
const NONCE_BYTES: usize = 12;

#[derive(Serialize, Deserialize)]
struct DiskFile {
    version: u32,
    entries: BTreeMap<String, DiskEntry>,
}

#[derive(Serialize, Deserialize)]
struct DiskEntry {
    meta: SecretMeta,
    nonce: String,
    ciphertext: String,
}

/// An encrypted, atomically rewritten credential file.
pub struct FileBackend {
    path: PathBuf,
    cipher: Aes256Gcm,
    entries: RwLock<BTreeMap<GeodeRef, StoredRecord>>,
}

impl std::fmt::Debug for FileBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FileBackend")
            .field("path", &self.path)
            .field(
                "entries",
                &self.entries.read().map(|e| e.len()).unwrap_or(0),
            )
            .finish()
    }
}

impl FileBackend {
    /// Open or create the store. The key must be exactly 32 bytes.
    pub fn open(path: impl Into<PathBuf>, key: [u8; 32]) -> Result<Self, GeodeError> {
        let path = path.into();
        let cipher = Aes256Gcm::new_from_slice(&key)
            .map_err(|_| GeodeError::Backend("file backend: invalid key length".into()))?;
        let entries = if path.exists() {
            let bytes = fs::read(&path)
                .map_err(|error| GeodeError::Backend(format!("file backend: read {error}")))?;
            let disk: DiskFile = serde_json::from_slice(&bytes)
                .map_err(|error| GeodeError::Backend(format!("file backend: parse {error}")))?;
            if disk.version != FILE_VERSION {
                return Err(GeodeError::Backend(
                    "file backend: unsupported store version".into(),
                ));
            }
            let mut entries = BTreeMap::new();
            for (reference, entry) in disk.entries {
                let reference = GeodeRef::parse(&reference)
                    .map_err(|error| GeodeError::Backend(format!("file backend: {error}")))?;
                let nonce = STANDARD
                    .decode(entry.nonce)
                    .map_err(|_| GeodeError::Backend("file backend: invalid nonce".into()))?;
                let ciphertext = STANDARD
                    .decode(entry.ciphertext)
                    .map_err(|_| GeodeError::Backend("file backend: invalid ciphertext".into()))?;
                let plaintext = cipher
                    .decrypt(
                        Nonce::from_slice(&nonce),
                        Payload {
                            msg: &ciphertext,
                            aad: reference.as_reference().as_bytes(),
                        },
                    )
                    .map_err(|_| {
                        GeodeError::Backend(format!(
                            "file backend: cannot decrypt {reference} (wrong key or corruption)"
                        ))
                    })?;
                entries.insert(
                    reference,
                    StoredRecord::new(crate::secret::SecretBytes::new(plaintext), entry.meta),
                );
            }
            entries
        } else {
            BTreeMap::new()
        };
        Ok(Self {
            path,
            cipher,
            entries: RwLock::new(entries),
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    fn flush(&self, entries: &BTreeMap<GeodeRef, StoredRecord>) -> Result<(), GeodeError> {
        let mut disk_entries = BTreeMap::new();
        for (reference, record) in entries {
            record
                .meta
                .validate()
                .map_err(|error| GeodeError::Backend(format!("file backend: {error}")))?;
            let mut nonce = [0u8; NONCE_BYTES];
            OsRng.fill_bytes(&mut nonce);
            let ciphertext = self
                .cipher
                .encrypt(
                    Nonce::from_slice(&nonce),
                    Payload {
                        msg: record.secret.expose(),
                        aad: reference.as_reference().as_bytes(),
                    },
                )
                .map_err(|_| GeodeError::Backend("file backend: encryption failed".into()))?;
            disk_entries.insert(
                reference.as_reference(),
                DiskEntry {
                    meta: record.meta.clone(),
                    nonce: STANDARD.encode(nonce),
                    ciphertext: STANDARD.encode(ciphertext),
                },
            );
        }
        let disk = DiskFile {
            version: FILE_VERSION,
            entries: disk_entries,
        };
        let bytes = serde_json::to_vec(&disk)
            .map_err(|error| GeodeError::Backend(format!("file backend: encode {error}")))?;
        let temporary = self
            .path
            .with_extension(format!("tmp.{}", std::process::id()));
        {
            let mut file = fs::OpenOptions::new()
                .create(true)
                .truncate(true)
                .write(true)
                .open(&temporary)
                .map_err(|error| GeodeError::Backend(format!("file backend: write {error}")))?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                file.set_permissions(fs::Permissions::from_mode(0o600))
                    .map_err(|error| GeodeError::Backend(format!("file backend: chmod {error}")))?;
            }
            file.write_all(&bytes)
                .map_err(|error| GeodeError::Backend(format!("file backend: write {error}")))?;
            file.sync_all()
                .map_err(|error| GeodeError::Backend(format!("file backend: sync {error}")))?;
        }
        fs::rename(&temporary, &self.path)
            .map_err(|error| GeodeError::Backend(format!("file backend: rename {error}")))?;
        Ok(())
    }
}

impl Backend for FileBackend {
    fn read(&self, reference: &GeodeRef) -> Result<Option<StoredRecord>, GeodeError> {
        Ok(self
            .entries
            .read()
            .map_err(|_| GeodeError::Backend("file backend: lock poisoned".into()))?
            .get(reference)
            .map(|record| StoredRecord::new(record.secret.clone(), record.meta.clone())))
    }

    fn write(&self, reference: &GeodeRef, record: StoredRecord) -> Result<(), GeodeError> {
        let mut guard = self
            .entries
            .write()
            .map_err(|_| GeodeError::Backend("file backend: lock poisoned".into()))?;
        let mut candidate = guard.clone();
        candidate.insert(reference.clone(), record);
        self.flush(&candidate)?;
        *guard = candidate;
        Ok(())
    }

    fn delete(&self, reference: &GeodeRef) -> Result<bool, GeodeError> {
        let mut guard = self
            .entries
            .write()
            .map_err(|_| GeodeError::Backend("file backend: lock poisoned".into()))?;
        if !guard.contains_key(reference) {
            return Ok(false);
        }
        let mut candidate = guard.clone();
        candidate.remove(reference);
        self.flush(&candidate)?;
        *guard = candidate;
        Ok(true)
    }

    fn kind(&self) -> &'static str {
        "file"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secret::{CredentialKind, Purpose, SecretBytes};
    use std::collections::BTreeSet;

    fn record(body: &str) -> StoredRecord {
        StoredRecord::new(
            SecretBytes::from(body),
            SecretMeta {
                kind: CredentialKind::Opaque,
                label: Some("test".into()),
                created_at: 1,
                rotated_at: 1,
                last_used_at: None,
                expires_at: None,
                purposes: BTreeSet::from([Purpose::test()]),
            },
        )
    }

    #[test]
    fn persists_across_reopen_and_rejects_a_wrong_key() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("geode.db");
        let reference = GeodeRef::parse("geode://test/unit/secret").unwrap();
        {
            let backend = FileBackend::open(&path, [7u8; 32]).unwrap();
            backend.write(&reference, record("hunter2")).unwrap();
            assert_eq!(
                backend.read(&reference).unwrap().unwrap().secret.expose(),
                b"hunter2"
            );
        }
        let backend = FileBackend::open(&path, [7u8; 32]).unwrap();
        assert_eq!(
            backend.read(&reference).unwrap().unwrap().secret.expose(),
            b"hunter2"
        );
        drop(backend);
        assert!(FileBackend::open(&path, [8u8; 32]).is_err());
    }

    #[test]
    fn delete_rewrites_the_store() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("geode.db");
        let reference = GeodeRef::parse("geode://test/unit/secret").unwrap();
        let backend = FileBackend::open(&path, [1u8; 32]).unwrap();
        backend.write(&reference, record("x")).unwrap();
        assert!(backend.delete(&reference).unwrap());
        assert!(!backend.delete(&reference).unwrap());
        drop(backend);
        let backend = FileBackend::open(&path, [1u8; 32]).unwrap();
        assert!(backend.read(&reference).unwrap().is_none());
    }
}
