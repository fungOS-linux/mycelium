//! `geode` — an owner-local credential store.
//!
//! A geode is a rock with a secret interior. This crate keeps that split
//! structural: [`GeodeRef`] is the durable, non-secret address; [`SecretBytes`]
//! is the interior, which has no `Serialize` implementation, redacts itself in
//! `Debug`, and zeroizes on drop.
//!
//! The store enforces policy around every backend: a read must name a
//! [`Purpose`] listed on the entry, a lease is time-bounded, and each decision
//! lands in a bounded [`AuditLog`]. A backend can therefore be simple (or
//! platform-specific) without being able to widen access on its own.
//!
//! This is not a vault. `geode` stores opaque secrets and minimal non-secret
//! metadata (`label`, timestamps, purpose allowlist). It does not interpret the
//! secret, and it deliberately has no URL, subject, or item-count surface.
#![forbid(unsafe_code)]

mod audit;
mod backend;
mod clock;
mod error;
mod lease;
mod passwords;
mod reference;
mod secret;
mod store;

pub use audit::{AuditEvent, AuditLog, AuditOutcome, DenyReason};
#[cfg(target_os = "macos")]
pub use backend::KeychainBackend;
pub use backend::{Backend, EnvBackend, MemoryBackend, StoredRecord, UnsupportedBackend};
pub use clock::{Clock, ManualClock, SharedClock, SystemClock};
pub use error::GeodeError;
pub use lease::Lease;
pub use passwords::{built_in_wordlist, PasswordGenerator, PhraseGenerator, Requirements};
pub use reference::GeodeRef;
pub use secret::{CredentialKind, Purpose, SecretBytes, SecretMeta};
pub use store::{NewCredential, Store, MAX_LEASE, MIN_LEASE};
