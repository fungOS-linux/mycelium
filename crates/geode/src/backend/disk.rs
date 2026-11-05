use std::collections::BTreeMap;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

use serde::{Deserialize, Serialize};

use crate::backend::{Backend, StoredRecord};
use crate::reference::GeodeRef;
use crate::secret::{CredentialKind, SecretBytes, SecretMeta};
use crate::GeodeError;

/// Persistent, owner-local credential storage.
///
/// A backend that survives restarts is what makes a credential store usable for
/// anything the daemon must remember between boots: network-appliance
/// credentials, plugin secrets, and the audit trail. Entries live in a single
/// JSON document; writes are atomic so a reader never observes a half-written
/// file, and a stale reader still sees the previous complete document.
///
/// The document is owner-readable only (`0600`), because it holds opaque
/// secret bytes. The secret itself is hex-encoded inside the JSON so the value
/// cannot be mistaken for UTF-8 metadata; the reference is the only human
/// surface, and it is public.
#[derive(Clone, Debug)]
pub struct DiskBackend {
    path: PathBuf,
}

impl DiskBackend {
    /// Open an existing store at `path`.
    ///
    /// The file must already exist and be a regular file; callers that want to
    /// seed the store use [`Self::create`]. Opening an existing directory or a
    /// missing file is a construction error, so the daemon boots against a
    /// known-good location.
    pub fn new(path: impl Into<PathBuf>) -> Result<Self, GeodeError> {
        let path = path.into();
        let meta = std::fs::metadata(&path).map_err(|error| {
            GeodeError::Backend(format!("cannot open {path:?}: {error}"))
        })?;
        if !meta.is_file() {
            return Err(GeodeError::Backend(format!("{path:?} is not a regular file")));
        }
        Ok(Self { path })
    }

    /// Create the store at `path`, seeding an empty document if absent.
    ///
    /// The file is written with `0600` permissions so its opaque secrets stay
    /// owner-only. A caller may pass a path whose parent does not yet exist; the
    /// directory is created.
    pub fn create(path: impl Into<PathBuf>) -> Result<Self, GeodeError> {
        let path = path.into();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|error| {
                GeodeError::Backend(format!("cannot create {parent:?}: {error}"))
            })?;
        }
        let file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&path)
            .map_err(|error| GeodeError::Backend(format!("cannot create {path:?}: {error}")))?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .map_err(|error| GeodeError::Backend(format!("cannot lock {path:?}: {error}")))?;
        // An empty file is a valid (empty) document.
        Ok(Self { path })
    }

    /// Open the store for read/write, creating it (`0600`) if absent.
    ///
    /// Unlike [`Self::new`], this never truncates an existing file, so the
    /// daemon can boot against a store it did not create and never wipe its own
    /// entries on restart.
    pub fn open(path: impl Into<PathBuf>) -> Result<Self, GeodeError> {
        let path = path.into();
        match std::fs::OpenOptions::new().read(true).write(true).open(&path) {
            Ok(file) => Ok(Self { path }),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Self::create(path),
            Err(error) => Err(GeodeError::Backend(format!("cannot open {path:?}: {error}"))),
        }
    }

    /// The on-disk location. Public so an operator can audit where the store
    /// lives.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Backend for DiskBackend {
    fn read(&self, reference: &GeodeRef) -> Result<Option<StoredRecord>, GeodeError> {
        let mut doc = load_document(&self.path)?;
        let key = reference.as_reference();
        match doc.secrets.remove(&key) {
            Some(hex) => {
                let secret = SecretBytes::from(hex_decode(&hex).ok_or_else(|| {
                    GeodeError::InvalidReference(format!("{key}: not valid hex"))
                })?);
                let meta = doc
                    .meta
                    .remove(&key)
                    .ok_or_else(|| GeodeError::NotFound(key))?;
                Ok(Some(StoredRecord::new(secret, meta)))
            }
            None => Ok(None),
        }
    }

    fn write(&self, reference: &GeodeRef, record: StoredRecord) -> Result<(), GeodeError> {
        let mut doc = load_document(&self.path)?;
        let key = reference.as_reference();
        doc.secrets.insert(key.clone(), hex_encode(record.secret.expose()));
        doc.meta.insert(key, record.meta);
        commit_document(&self.path, &doc)?;
        Ok(())
    }

    fn delete(&self, reference: &GeodeRef) -> Result<bool, GeodeError> {
        let mut doc = load_document(&self.path)?;
        let key = reference.as_reference();
        let existed = doc.secrets.remove(&key).is_some();
        doc.meta.remove(&key);
        if existed {
            commit_document(&self.path, &doc)?;
        }
        Ok(existed)
    }

    fn writable(&self) -> bool {
        true
    }

    fn kind(&self) -> &'static str {
        "disk"
    }
}

/// A single store document: opaque secrets plus their non-secret descriptions.
#[derive(Default, Serialize, Deserialize)]
struct Document {
    secrets: BTreeMap<String, String>,
    meta: BTreeMap<String, SecretMeta>,
}

/// Load the document, tolerating a missing file (an empty store). A corrupt
/// document is an error so the caller can decide whether to rebuild.
fn load_document(path: &Path) -> Result<Document, GeodeError> {
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(Document::default());
        }
        Err(error) => {
            return Err(GeodeError::Backend(format!("cannot read {path:?}: {error}")));
        }
    };
    if text.trim().is_empty() {
        return Ok(Document::default());
    }
    serde_json::from_str(&text).map_err(|error| GeodeError::Backend(format!("invalid {path:?}: {error}")))
}

/// Persist the document with an atomic rename so a concurrent reader never sees
/// a partial write. The lock serializes writers within a process.
fn commit_document(path: &Path, doc: &Document) -> Result<(), GeodeError> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()));
    let _guard = LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .expect("disk backend lock poisoned");

    let text = serde_json::to_string_pretty(doc).map_err(|error| {
        GeodeError::Backend(format!("cannot encode store: {error}"))
    })?;
    let temporary = path.with_extension(format!("tmp-{}", std::process::id()));
    std::fs::write(&temporary, text).map_err(|error| {
        GeodeError::Backend(format!("cannot write {temporary:?}: {error}"))
    })?;
    std::fs::rename(&temporary, path).map_err(|error| {
        GeodeError::Backend(format!("cannot persist {path:?}: {error}"))
    })?;
    Ok(())
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from_digit(((byte >> 4) as u32) + (b'0' as u32), 16).unwrap());
        out.push(char::from_digit(((byte & 0x0f) as u32) + (b'0' as u32), 16).unwrap());
    }
    out
}

fn hex_decode(text: &str) -> Option<Vec<u8>> {
    if text.len() % 2 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(text.len() / 2);
    let bytes = text.as_bytes();
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
