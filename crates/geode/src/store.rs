use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::audit::{AuditEvent, AuditLog, AuditOutcome, DenyReason};
use crate::backend::{Backend, StoredRecord};
use crate::clock::{SharedClock, SystemClock};
use crate::lease::Lease;
use crate::reference::GeodeRef;
use crate::secret::{CredentialKind, Purpose, SecretBytes, SecretMeta};
use crate::GeodeError;

/// Shortest lease the store will issue. A zero-length lease is a bug, not a
/// clever way to avoid holding a secret.
pub const MIN_LEASE: Duration = Duration::from_secs(1);

/// Longest lease the store will issue. Long-lived secrets belong to a supervisor
/// or a platform backend, not to an adapter that forgot to release.
pub const MAX_LEASE: Duration = Duration::from_secs(60 * 60);

/// Builder for a new credential entry.
///
/// A builder keeps call sites readable and makes the metadata surface explicit
/// rather than positional.
#[derive(Clone, Debug)]
pub struct NewCredential {
    pub secret: SecretBytes,
    pub kind: CredentialKind,
    pub purposes: BTreeSet<Purpose>,
    pub label: Option<String>,
    pub expires_at: Option<u64>,
}

impl NewCredential {
    pub fn new(kind: CredentialKind, secret: impl Into<SecretBytes>) -> Self {
        Self {
            secret: secret.into(),
            kind,
            purposes: BTreeSet::new(),
            label: None,
            expires_at: None,
        }
    }

    pub fn opaque(secret: impl Into<SecretBytes>) -> Self {
        Self::new(CredentialKind::Opaque, secret)
    }

    pub fn api_key(secret: impl Into<SecretBytes>) -> Self {
        Self::new(CredentialKind::ApiKey, secret)
    }

    pub fn oauth2_refresh(secret: impl Into<SecretBytes>) -> Self {
        Self::new(CredentialKind::OAuth2RefreshToken, secret)
    }

    pub fn oauth2_access(secret: impl Into<SecretBytes>, expires_at: u64) -> Self {
        Self::new(CredentialKind::OAuth2AccessToken, secret).expires_at(expires_at)
    }

    pub fn oauth2_id(secret: impl Into<SecretBytes>, expires_at: Option<u64>) -> Self {
        let credential = Self::new(CredentialKind::OAuth2IdToken, secret);
        match expires_at {
            Some(expires_at) => credential.expires_at(expires_at),
            None => credential,
        }
    }

    pub fn passkey(secret: impl Into<SecretBytes>) -> Self {
        Self::new(CredentialKind::Passkey, secret)
    }

    pub fn otp_secret(secret: impl Into<SecretBytes>) -> Self {
        Self::new(CredentialKind::OtpSecret, secret)
    }

    /// Create a free-form secure note. The body is the opaque secret; the
    /// `label` is its title. A note carries no credential expiry and is read
    /// through [`Purpose::secure_note`].
    pub fn secure_note(secret: impl Into<SecretBytes>) -> Self {
        Self::new(CredentialKind::SecureNote, secret)
    }

    pub fn with_purpose(mut self, purpose: Purpose) -> Self {
        self.purposes.insert(purpose);
        self
    }

    pub fn with_purposes(mut self, purposes: impl IntoIterator<Item = Purpose>) -> Self {
        self.purposes.extend(purposes);
        self
    }

    pub fn with_label(mut self, label: impl Into<String>) -> Self {
        self.label = Some(label.into());
        self
    }

    pub fn expires_at(mut self, expires_at: u64) -> Self {
        self.expires_at = Some(expires_at);
        self
    }
}

/// Owner-local store: a backend plus the policy every access passes through.
pub struct Store<B: Backend> {
    backend: B,
    clock: SharedClock,
    audit: Mutex<AuditLog>,
}

impl<B: Backend> Store<B> {
    pub fn new(backend: B) -> Self {
        Self::with_clock(backend, Arc::new(SystemClock))
    }

    pub fn with_clock(backend: B, clock: SharedClock) -> Self {
        Self::with_audit_capacity(backend, clock, 256)
    }

    pub fn with_audit_capacity(backend: B, clock: SharedClock, capacity: usize) -> Self {
        Self {
            backend,
            clock,
            audit: Mutex::new(AuditLog::new(capacity)),
        }
    }

    pub fn backend(&self) -> &B {
        &self.backend
    }

    pub fn backend_kind(&self) -> &'static str {
        self.backend.kind()
    }

    /// Create or replace an opaque entry.
    ///
    /// An existing entry keeps its `created_at`; the replacement is recorded as
    /// a rotation. The caller must supply at least one purpose.
    pub fn store(
        &self,
        reference: &GeodeRef,
        secret: SecretBytes,
        purposes: impl IntoIterator<Item = Purpose>,
        label: Option<&str>,
    ) -> Result<SecretMeta, GeodeError> {
        let mut credential = NewCredential::opaque(secret).with_purposes(purposes);
        credential.label = label.map(str::to_owned);
        self.insert(reference, credential)
    }

    /// Insert a typed credential.
    pub fn insert(
        &self,
        reference: &GeodeRef,
        credential: NewCredential,
    ) -> Result<SecretMeta, GeodeError> {
        let now = self.clock.now();
        let existing = self.backend.read(reference)?;
        let created_at = existing
            .as_ref()
            .map(|record| record.meta.created_at)
            .unwrap_or(now);
        let meta = SecretMeta {
            kind: credential.kind,
            label: credential.label,
            created_at,
            rotated_at: now,
            last_used_at: existing.as_ref().and_then(|r| r.meta.last_used_at),
            expires_at: credential.expires_at,
            purposes: credential.purposes,
        };
        meta.validate()?;

        self.require_writable()?;
        self.backend.write(
            reference,
            StoredRecord::new(credential.secret, meta.clone()),
        )?;
        self.record(reference, None, AuditOutcome::Stored);
        Ok(meta)
    }

    /// Replace the secret while preserving the entry's identity and allowlist.
    pub fn rotate(
        &self,
        reference: &GeodeRef,
        secret: SecretBytes,
    ) -> Result<SecretMeta, GeodeError> {
        self.renew(reference, secret, None)
    }

    /// Replace the secret and optionally set a new credential expiry.
    ///
    /// This is the token-rotation path: kind, purposes, label, and `created_at`
    /// are preserved; `expires_at` is replaced with the supplied value.
    pub fn renew(
        &self,
        reference: &GeodeRef,
        secret: SecretBytes,
        expires_at: Option<u64>,
    ) -> Result<SecretMeta, GeodeError> {
        let existing = self
            .backend
            .read(reference)?
            .ok_or_else(|| GeodeError::NotFound(reference.to_string()))?;
        self.require_writable()?;

        let meta = SecretMeta {
            kind: existing.meta.kind,
            label: existing.meta.label.clone(),
            created_at: existing.meta.created_at,
            rotated_at: self.clock.now(),
            last_used_at: existing.meta.last_used_at,
            expires_at,
            purposes: existing.meta.purposes.clone(),
        };
        meta.validate()?;
        self.backend
            .write(reference, StoredRecord::new(secret, meta.clone()))?;
        self.record(reference, None, AuditOutcome::Rotated);
        Ok(meta)
    }

    /// Issue a bounded, purpose-scoped lease.
    pub fn lease(
        &self,
        reference: &GeodeRef,
        purpose: &Purpose,
        ttl: Duration,
    ) -> Result<Lease, GeodeError> {
        if ttl < MIN_LEASE || ttl > MAX_LEASE {
            self.record(
                reference,
                Some(purpose.clone()),
                AuditOutcome::Denied(DenyReason::InvalidTtl),
            );
            return Err(GeodeError::InvalidTtl {
                requested: ttl,
                min: MIN_LEASE,
                max: MAX_LEASE,
            });
        }

        let record = match self.backend.read(reference) {
            Ok(record) => record,
            Err(error) => {
                self.record(
                    reference,
                    Some(purpose.clone()),
                    AuditOutcome::Denied(DenyReason::Backend),
                );
                return Err(error);
            }
        };
        let Some(mut record) = record else {
            self.record(
                reference,
                Some(purpose.clone()),
                AuditOutcome::Denied(DenyReason::NotFound),
            );
            return Err(GeodeError::NotFound(reference.to_string()));
        };

        if !record.meta.purposes.contains(purpose) {
            self.record(
                reference,
                Some(purpose.clone()),
                AuditOutcome::Denied(DenyReason::PurposeNotAllowed),
            );
            return Err(GeodeError::PurposeNotAllowed {
                reference: reference.to_string(),
                purpose: purpose.to_string(),
            });
        }

        let now = self.clock.now();
        if record.meta.is_expired(now) {
            let expired_at = record.meta.expires_at.unwrap_or(now);
            self.record(
                reference,
                Some(purpose.clone()),
                AuditOutcome::Denied(DenyReason::CredentialExpired),
            );
            return Err(GeodeError::CredentialExpired {
                reference: reference.to_string(),
                expired_at,
            });
        }

        record.meta.last_used_at = Some(now);
        // Bookkeeping must not deny an otherwise valid lease. A read-only
        // backend simply cannot persist `last_used_at`.
        if self.backend.writable() {
            let _ = self.backend.write(
                reference,
                StoredRecord::new(record.secret.clone(), record.meta.clone()),
            );
        }

        let expires_at = now.saturating_add(ttl.as_secs());
        self.record(
            reference,
            Some(purpose.clone()),
            AuditOutcome::Issued {
                ttl_secs: ttl.as_secs(),
            },
        );
        Ok(Lease::new(
            reference.clone(),
            purpose.clone(),
            ttl,
            expires_at,
            Arc::clone(&self.clock),
            record.secret,
        ))
    }

    /// Remove an entry. Returns whether it existed.
    pub fn delete(&self, reference: &GeodeRef) -> Result<bool, GeodeError> {
        self.require_writable()?;
        let deleted = self.backend.delete(reference)?;
        if deleted {
            self.record(reference, None, AuditOutcome::Deleted);
        }
        Ok(deleted)
    }

    /// Read non-secret metadata without issuing a lease.
    ///
    /// Deliberately not audited: no secret is revealed, and metadata reads are
    /// the normal way a caller decides whether to request a purpose at all.
    pub fn describe(&self, reference: &GeodeRef) -> Result<Option<SecretMeta>, GeodeError> {
        Ok(self.backend.read(reference)?.map(|record| record.meta))
    }

    pub fn audit(&self) -> Vec<AuditEvent> {
        self.audit
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .events()
            .cloned()
            .collect()
    }

    pub fn audit_len(&self) -> usize {
        self.audit
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .len()
    }

    fn require_writable(&self) -> Result<(), GeodeError> {
        if self.backend.writable() {
            Ok(())
        } else {
            Err(GeodeError::ReadOnly)
        }
    }

    fn record(&self, reference: &GeodeRef, purpose: Option<Purpose>, outcome: AuditOutcome) {
        let event = AuditEvent {
            at: self.clock.now(),
            reference: reference.clone(),
            purpose,
            outcome,
        };
        self.audit
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .record(event);
    }
}

impl<B: Backend> std::fmt::Debug for Store<B> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Store")
            .field("backend", &self.backend.kind())
            .field("audit_len", &self.audit_len())
            .finish()
    }
}
