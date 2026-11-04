use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};

use crate::backend::{Backend, StoredRecord};
use crate::reference::GeodeRef;
use crate::GeodeError;

/// In-process backend for tests and for composing a store before a platform
/// backend exists.
///
/// Entries vanish with the process, which is the point: this backend must never
/// be selected as a durable production store.
#[derive(Clone, Debug, Default)]
pub struct MemoryBackend {
    entries: Arc<RwLock<BTreeMap<GeodeRef, StoredRecord>>>,
}

impl MemoryBackend {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.entries
            .read()
            .expect("memory backend lock poisoned")
            .len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Backend for MemoryBackend {
    fn read(&self, reference: &GeodeRef) -> Result<Option<StoredRecord>, GeodeError> {
        let entries = self
            .entries
            .read()
            .map_err(|_| GeodeError::Backend("memory backend lock poisoned".into()))?;
        let Some(record) = entries.get(reference) else {
            return Ok(None);
        };
        Ok(Some(StoredRecord::new(
            record.secret.clone(),
            record.meta.clone(),
        )))
    }

    fn write(&self, reference: &GeodeRef, record: StoredRecord) -> Result<(), GeodeError> {
        self.entries
            .write()
            .map_err(|_| GeodeError::Backend("memory backend lock poisoned".into()))?
            .insert(reference.clone(), record);
        Ok(())
    }

    fn delete(&self, reference: &GeodeRef) -> Result<bool, GeodeError> {
        Ok(self
            .entries
            .write()
            .map_err(|_| GeodeError::Backend("memory backend lock poisoned".into()))?
            .remove(reference)
            .is_some())
    }

    fn kind(&self) -> &'static str {
        "memory"
    }
}
