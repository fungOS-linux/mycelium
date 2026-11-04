use std::collections::BTreeSet;
use std::fmt;

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::GeodeError;

/// Bytes revealed by a lease.
///
/// There is deliberately no `Serialize` implementation: a secret cannot be
/// written to gossip, JSON, or an audit record by accident. `Debug` is redacted,
/// and the buffer is zeroized when the value is dropped.
#[derive(Clone)]
pub struct SecretBytes(Zeroizing<Vec<u8>>);

impl SecretBytes {
    pub fn new(bytes: impl Into<Vec<u8>>) -> Self {
        Self(Zeroizing::new(bytes.into()))
    }

    pub fn expose(&self) -> &[u8] {
        &self.0
    }

    pub fn expose_str(&self) -> Result<&str, GeodeError> {
        std::str::from_utf8(&self.0).map_err(|_| GeodeError::NotUtf8)
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl From<&str> for SecretBytes {
    fn from(value: &str) -> Self {
        Self::new(value.as_bytes())
    }
}

impl From<String> for SecretBytes {
    fn from(value: String) -> Self {
        Self::new(value.into_bytes())
    }
}

impl From<Vec<u8>> for SecretBytes {
    fn from(value: Vec<u8>) -> Self {
        Self::new(value)
    }
}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The length is metadata; the bytes are not.
        write!(f, "SecretBytes(***redacted***, {} bytes)", self.len())
    }
}

/// What a caller intends to do with a secret.
///
/// Allowlisting is per purpose rather than per caller, so a mail adapter that
/// may connect to IMAP does not thereby gain the SMTP submission secret just
/// because both live under the same account.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Purpose(String);

const MAX_PURPOSE: usize = 64;

impl Purpose {
    pub fn parse(value: impl Into<String>) -> Result<Self, GeodeError> {
        let value = value.into();
        if value.is_empty() || value.len() > MAX_PURPOSE {
            return Err(GeodeError::InvalidPurpose(format!(
                "must be 1..={MAX_PURPOSE} bytes"
            )));
        }
        let mut chars = value.chars();
        let starts_well = chars.next().is_some_and(|c| c.is_ascii_alphabetic());
        let rest_well = chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'));
        if !starts_well || !rest_well {
            return Err(GeodeError::InvalidPurpose(
                "must start with an ASCII letter and contain only letters, digits, `.`, `_`, or `-`"
                    .into(),
            ));
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Convention: `<subsystem>.<operation>`.
    pub fn mail_connect() -> Self {
        Self("mail.connect".into())
    }

    pub fn mail_submit() -> Self {
        Self("mail.submit".into())
    }

    pub fn http_basic() -> Self {
        Self("http.basic".into())
    }

    pub fn ssh_key() -> Self {
        Self("ssh.key".into())
    }

    pub fn test() -> Self {
        Self("test.read".into())
    }

    pub fn passkey_assert() -> Self {
        Self("passkey.assert".into())
    }

    pub fn oauth2_access() -> Self {
        Self("oauth2.access".into())
    }

    pub fn oauth2_refresh() -> Self {
        Self("oauth2.refresh".into())
    }

    pub fn oauth2_id() -> Self {
        Self("oauth2.id".into())
    }

    pub fn otp_generate() -> Self {
        Self("otp.generate".into())
    }

    pub fn mcp_invoke() -> Self {
        Self("mcp.invoke".into())
    }
}

impl fmt::Display for Purpose {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Debug for Purpose {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Purpose({})", self.0)
    }
}

impl TryFrom<String> for Purpose {
    type Error = GeodeError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::parse(value)
    }
}

impl From<Purpose> for String {
    fn from(value: Purpose) -> Self {
        value.0
    }
}

/// What kind of credential an entry holds.
///
/// The kind is descriptive metadata for operators and connector preflight; the
/// store still treats the bytes as opaque. A connector may require a kind before
/// it will use an entry, but it must never rely on the kind label for secrecy.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialKind {
    #[default]
    Opaque,
    ApiKey,
    OAuth2AccessToken,
    OAuth2RefreshToken,
    OAuth2IdToken,
    OtpSecret,
    Passkey,
    Certificate,
}

impl CredentialKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Opaque => "opaque",
            Self::ApiKey => "api_key",
            Self::OAuth2AccessToken => "oauth2_access_token",
            Self::OAuth2RefreshToken => "oauth2_refresh_token",
            Self::OAuth2IdToken => "oauth2_id_token",
            Self::OtpSecret => "otp_secret",
            Self::Passkey => "passkey",
            Self::Certificate => "certificate",
        }
    }
}

impl fmt::Display for CredentialKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Non-secret description of a stored secret.
///
/// This is the entire metadata surface in v1. Adding fields is a deliberate act:
/// a field that describes the secret's contents is a leak, not an improvement.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretMeta {
    #[serde(default)]
    pub kind: CredentialKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    pub created_at: u64,
    pub rotated_at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_used_at: Option<u64>,
    /// Absolute credential expiry, distinct from a lease's expiry. Access tokens
    /// and certificates carry one; a password usually does not.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
    pub purposes: BTreeSet<Purpose>,
}

const MAX_LABEL: usize = 96;

impl SecretMeta {
    pub fn validate(&self) -> Result<(), GeodeError> {
        if self.purposes.is_empty() {
            return Err(GeodeError::EmptyPurposeSet);
        }
        if let Some(label) = &self.label {
            if label.is_empty() || label.len() > MAX_LABEL {
                return Err(GeodeError::InvalidMetadata(format!(
                    "label must be 1..={MAX_LABEL} bytes"
                )));
            }
            if label.chars().any(|c| c.is_control()) {
                return Err(GeodeError::InvalidMetadata(
                    "label must not contain control characters".into(),
                ));
            }
        }
        Ok(())
    }

    /// Whether the credential itself has expired. Lease expiry is separate and
    /// is enforced by [`crate::Lease`].
    pub fn is_expired(&self, now: u64) -> bool {
        self.expires_at.is_some_and(|expires_at| now >= expires_at)
    }
}
