mod disk;
mod env;
#[cfg(target_os = "macos")]
mod keychain;
mod memory;

use std::fmt;

use crate::reference::GeodeRef;
use crate::secret::{SecretBytes, SecretMeta};
use crate::GeodeError;

pub use disk::DiskBackend;
pub use env::EnvBackend;
#[cfg(target_os = "macos")]
pub use keychain::KeychainBackend;
pub use memory::MemoryBackend;

/// One stored item: the secret plus its non-secret description.
pub struct StoredRecord {
    pub secret: SecretBytes,
    pub meta: SecretMeta,
}

impl StoredRecord {
    pub fn new(secret: SecretBytes, meta: SecretMeta) -> Self {
        Self { secret, meta }
    }
}

impl fmt::Debug for StoredRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StoredRecord")
            .field("secret", &self.secret)
            .field("meta", &self.meta)
            .finish()
    }
}

/// Raw, owner-local storage.
///
/// A backend stores and returns records; it does not decide whether a caller
/// may have a lease. Policy lives in [`crate::Store`] so every backend inherits
/// the same rules. A backend that cannot store writes must report
/// [`Backend::writable`] as `false` rather than silently dropping writes.
pub trait Backend: Send + Sync {
    fn read(&self, reference: &GeodeRef) -> Result<Option<StoredRecord>, GeodeError>;

    fn write(&self, reference: &GeodeRef, record: StoredRecord) -> Result<(), GeodeError>;

    /// Returns whether an entry existed.
    fn delete(&self, reference: &GeodeRef) -> Result<bool, GeodeError>;

    fn writable(&self) -> bool {
        true
    }

    /// Stable backend name for diagnostics. Must not include a path or secret.
    fn kind(&self) -> &'static str;
}

/// A backend that exists only to fail closed on a platform without an
/// implementation.
///
/// Using this explicitly is better than an `auto` mode that might silently
/// select a weaker store.
#[derive(Clone, Debug)]
pub struct UnsupportedBackend {
    reason: &'static str,
}

impl UnsupportedBackend {
    pub fn new(reason: &'static str) -> Self {
        Self { reason }
    }
}

impl Backend for UnsupportedBackend {
    fn read(&self, _reference: &GeodeRef) -> Result<Option<StoredRecord>, GeodeError> {
        Err(GeodeError::Backend(self.reason.into()))
    }

    fn write(&self, _reference: &GeodeRef, _record: StoredRecord) -> Result<(), GeodeError> {
        Err(GeodeError::Backend(self.reason.into()))
    }

    fn delete(&self, _reference: &GeodeRef) -> Result<bool, GeodeError> {
        Err(GeodeError::Backend(self.reason.into()))
    }

    fn writable(&self) -> bool {
        false
    }

    fn kind(&self) -> &'static str {
        "unsupported"
    }
}
