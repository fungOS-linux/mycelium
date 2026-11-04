use std::time::Duration;

/// Something went wrong inside the owner-local store.
///
/// Variants carry no secret material: messages are safe to log alongside the
/// non-secret reference that produced them.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum GeodeError {
    #[error("invalid geode reference: {0}")]
    InvalidReference(String),
    #[error("invalid purpose: {0}")]
    InvalidPurpose(String),
    #[error("an entry needs at least one purpose")]
    EmptyPurposeSet,
    #[error("no secret stored at {0}")]
    NotFound(String),
    #[error("purpose `{purpose}` is not allowed for {reference}")]
    PurposeNotAllowed { reference: String, purpose: String },
    #[error("the lease on {0} has expired")]
    Expired(String),
    #[error("lease ttl must be between {min:?} and {max:?}, got {requested:?}")]
    InvalidTtl {
        requested: Duration,
        min: Duration,
        max: Duration,
    },
    #[error("the backend is read-only")]
    ReadOnly,
    #[error("metadata is invalid: {0}")]
    InvalidMetadata(String),
    #[error("the secret is not valid UTF-8")]
    NotUtf8,
    #[error("backend refused the operation: {0}")]
    Backend(String),
}
