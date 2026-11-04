use std::collections::BTreeSet;

use crate::backend::{Backend, StoredRecord};
use crate::reference::GeodeRef;
use crate::secret::{Purpose, SecretBytes, SecretMeta};
use crate::GeodeError;

/// Read-only developer backend.
///
/// A reference resolves to an environment variable named from the reference:
///
/// ```text
/// geode://mail/work/imap  ->  GEODE_MAIL_WORK_IMAP
/// ```
///
/// The backend cannot store metadata, so it applies one explicit, fixed purpose
/// allowlist to every entry. It never has an implicit "all purposes" mode, and it
/// never writes. Intended for tests and local development only.
#[derive(Clone, Debug)]
pub struct EnvBackend {
    prefix: String,
    purposes: BTreeSet<Purpose>,
}

impl EnvBackend {
    pub fn new(purposes: impl IntoIterator<Item = Purpose>) -> Result<Self, GeodeError> {
        Self::with_prefix("GEODE_", purposes)
    }

    pub fn with_prefix(
        prefix: impl Into<String>,
        purposes: impl IntoIterator<Item = Purpose>,
    ) -> Result<Self, GeodeError> {
        let prefix = prefix.into();
        if prefix.is_empty()
            || !prefix
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_')
        {
            return Err(GeodeError::Backend(
                "env backend prefix must be non-empty ASCII alphanumeric or `_`".into(),
            ));
        }
        let purposes = purposes.into_iter().collect::<BTreeSet<_>>();
        if purposes.is_empty() {
            return Err(GeodeError::EmptyPurposeSet);
        }
        Ok(Self { prefix, purposes })
    }

    /// The variable name used for a reference. Public so an operator can see
    /// exactly which variable the daemon will read.
    pub fn variable(&self, reference: &GeodeRef) -> String {
        let raw = format!(
            "{}{}_{}_{}",
            self.prefix,
            reference.realm(),
            reference.account(),
            reference.slot()
        );
        raw.chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() {
                    c.to_ascii_uppercase()
                } else {
                    '_'
                }
            })
            .collect()
    }
}

impl Backend for EnvBackend {
    fn read(&self, reference: &GeodeRef) -> Result<Option<StoredRecord>, GeodeError> {
        let variable = self.variable(reference);
        match std::env::var_os(&variable) {
            None => Ok(None),
            Some(value) => {
                let bytes = value.into_encoded_bytes();
                Ok(Some(StoredRecord::new(
                    SecretBytes::new(bytes),
                    SecretMeta {
                        label: None,
                        created_at: 0,
                        rotated_at: 0,
                        last_used_at: None,
                        purposes: self.purposes.clone(),
                    },
                )))
            }
        }
    }

    fn write(&self, _reference: &GeodeRef, _record: StoredRecord) -> Result<(), GeodeError> {
        Err(GeodeError::ReadOnly)
    }

    fn delete(&self, _reference: &GeodeRef) -> Result<bool, GeodeError> {
        Err(GeodeError::ReadOnly)
    }

    fn writable(&self) -> bool {
        false
    }

    fn kind(&self) -> &'static str {
        "env"
    }
}
