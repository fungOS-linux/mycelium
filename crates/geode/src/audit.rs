use std::collections::VecDeque;
use std::fmt;

use crate::reference::GeodeRef;
use crate::secret::Purpose;

/// Why a read was refused. Reasons are closed so an audit record cannot become
/// a channel for secret-adjacent text.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DenyReason {
    NotFound,
    PurposeNotAllowed,
    CredentialExpired,
    InvalidTtl,
    Backend,
}

/// One owner-local decision.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuditOutcome {
    Stored,
    Rotated,
    Deleted,
    Issued {
        ttl_secs: u64,
    },
    Denied(DenyReason),
    /// The credential at a reference was revoked (tombstoned), or a read was
    /// refused because the entry had been revoked.
    Revoked,
}

/// A non-secret record of a store decision.
///
/// Audit events name the reference and purpose only. They never carry the
/// secret, its length, or any part of its value.
#[derive(Clone, PartialEq, Eq)]
pub struct AuditEvent {
    pub at: u64,
    pub reference: GeodeRef,
    pub purpose: Option<Purpose>,
    pub outcome: AuditOutcome,
}

impl fmt::Debug for AuditEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuditEvent")
            .field("at", &self.at)
            .field("reference", &self.reference)
            .field("purpose", &self.purpose)
            .field("outcome", &self.outcome)
            .finish()
    }
}

/// Fixed-capacity ring of recent decisions.
///
/// The log is bounded on purpose: an unbounded credential audit trail is an
/// availability problem waiting to happen. Long-term retention belongs to the
/// host's journal, not this process.
#[derive(Debug)]
pub struct AuditLog {
    capacity: usize,
    events: VecDeque<AuditEvent>,
}

impl AuditLog {
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity: capacity.max(1),
            events: VecDeque::new(),
        }
    }

    pub fn record(&mut self, event: AuditEvent) {
        if self.events.len() == self.capacity {
            self.events.pop_front();
        }
        self.events.push_back(event);
    }

    pub fn len(&self) -> usize {
        self.events.len()
    }

    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    pub fn events(&self) -> impl DoubleEndedIterator<Item = &AuditEvent> {
        self.events.iter()
    }

    pub fn latest(&self) -> Option<&AuditEvent> {
        self.events.back()
    }
}

impl Default for AuditLog {
    fn default() -> Self {
        Self::new(256)
    }
}
