//! TOTP (RFC 6238) and HOTP (RFC 4226) over geode-owned shared secrets.
//!
//! A 2FA shared secret is long-lived credential material. Geode keeps it behind
//! `otp.generate`; this connector leases it for one derivation and returns only
//! the short-lived code. The secret is never part of the enrollment record the
//! caller persists.
//!
//! HOTP is stateful. Geode has no compare-and-swap, so an HOTP counter must have
//! a single owner (or live in a backend that provides atomic increment). TOTP is
//! stateless and is the default for host and agent logins.

use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

use data_encoding::BASE32_NOPAD;
use geode::{
    Backend, GeodeError, GeodeRef, NewCredential, Purpose, SecretBytes, SecretMeta, Store,
};
use hmac::{Hmac, Mac};
use percent_encoding::percent_decode_str;
use sha1::Sha1;
use sha2::{Sha256, Sha512};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

/// Digits accepted from an `otpauth://` URI. Six and eight are the interoperable
/// choices; seven is legal in HOTP but not emitted by common authenticators.
const MIN_DIGITS: u32 = 6;
const MAX_DIGITS: u32 = 8;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OtpAlgorithm {
    Sha1,
    Sha256,
    Sha512,
}

impl OtpAlgorithm {
    pub fn parse(value: &str) -> Option<Self> {
        match value.to_ascii_uppercase().as_str() {
            "SHA1" => Some(Self::Sha1),
            "SHA256" => Some(Self::Sha256),
            "SHA512" => Some(Self::Sha512),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sha1 => "SHA1",
            Self::Sha256 => "SHA256",
            Self::Sha512 => "SHA512",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OtpKind {
    Totp,
    Hotp,
}

/// Non-secret OTP parameters. Safe to persist in configuration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OtpConfig {
    pub kind: OtpKind,
    pub digits: u32,
    pub period: u64,
    pub algorithm: OtpAlgorithm,
    pub issuer: Option<String>,
    pub account: Option<String>,
}

impl Default for OtpConfig {
    fn default() -> Self {
        Self {
            kind: OtpKind::Totp,
            digits: 6,
            period: 30,
            algorithm: OtpAlgorithm::Sha1,
            issuer: None,
            account: None,
        }
    }
}

impl OtpConfig {
    pub fn validate(&self) -> Result<(), OtpError> {
        if !(MIN_DIGITS..=MAX_DIGITS).contains(&self.digits) {
            return Err(OtpError::InvalidConfig(format!(
                "digits must be {MIN_DIGITS}..={MAX_DIGITS}"
            )));
        }
        if self.kind == OtpKind::Totp && self.period == 0 {
            return Err(OtpError::InvalidConfig("period must be non-zero".into()));
        }
        if self.issuer.as_ref().is_some_and(|v| v.len() > 128) {
            return Err(OtpError::InvalidConfig("issuer is too long".into()));
        }
        if self.account.as_ref().is_some_and(|v| v.len() > 256) {
            return Err(OtpError::InvalidConfig("account is too long".into()));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum OtpError {
    #[error("invalid config: {0}")]
    InvalidConfig(String),
    #[error("invalid otpauth URI: {0}")]
    InvalidUri(String),
    #[error("secret is not valid base32")]
    InvalidBase32,
    #[error("HMAC key was rejected")]
    InvalidKey,
    #[error(transparent)]
    Geode(#[from] GeodeError),
}

/// The shared secret. Debug is redacted through [`SecretBytes`].
pub struct OtpSecret {
    key: SecretBytes,
}

impl fmt::Debug for OtpSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("OtpSecret").field(&self.key).finish()
    }
}

impl OtpSecret {
    pub fn from_bytes(key: impl Into<Vec<u8>>) -> Result<Self, OtpError> {
        let key = SecretBytes::new(key.into());
        if key.is_empty() {
            return Err(OtpError::InvalidBase32);
        }
        Ok(Self { key })
    }

    pub fn from_base32(value: &str) -> Result<Self, OtpError> {
        let normalized: String = value
            .chars()
            .filter(|c| !c.is_ascii_whitespace() && *c != '-' && *c != '=')
            .collect::<String>()
            .to_ascii_uppercase();
        if normalized.is_empty() {
            return Err(OtpError::InvalidBase32);
        }
        let bytes = BASE32_NOPAD
            .decode(normalized.as_bytes())
            .map_err(|_| OtpError::InvalidBase32)?;
        Self::from_bytes(bytes)
    }

    /// Export for enrollment. The caller must display it once and drop it;
    /// the returned string zeroizes.
    pub fn to_base32(&self) -> Zeroizing<String> {
        Zeroizing::new(BASE32_NOPAD.encode(self.key.expose()))
    }

    pub fn code_now(&self, config: &OtpConfig) -> Result<String, OtpError> {
        self.code_at(config, unix_now())
    }

    pub fn code_at(&self, config: &OtpConfig, unix_secs: u64) -> Result<String, OtpError> {
        config.validate()?;
        if config.kind != OtpKind::Totp {
            return Err(OtpError::InvalidConfig(
                "HOTP needs an explicit counter; use `hotp`".into(),
            ));
        }
        self.code_for_counter(config, unix_secs / config.period)
    }

    pub fn hotp(&self, config: &OtpConfig, counter: u64) -> Result<String, OtpError> {
        config.validate()?;
        self.code_for_counter(config, counter)
    }

    /// Accept the current step plus `skew` steps in either direction.
    ///
    /// Returns whether any step matched. Use a small skew (1) for clock drift.
    pub fn verify_now(&self, config: &OtpConfig, code: &str, skew: u32) -> Result<bool, OtpError> {
        self.verify_at(config, code, unix_now(), skew)
    }

    pub fn verify_at(
        &self,
        config: &OtpConfig,
        code: &str,
        unix_secs: u64,
        skew: u32,
    ) -> Result<bool, OtpError> {
        config.validate()?;
        if config.kind != OtpKind::Totp {
            return Err(OtpError::InvalidConfig(
                "HOTP needs an explicit counter; use `verify_hotp`".into(),
            ));
        }
        let step = unix_secs / config.period;
        let mut matched = false;
        for offset in 0..=skew as u64 {
            for candidate in [step.checked_sub(offset), step.checked_add(offset)] {
                let Some(candidate) = candidate else { continue };
                let expected = self.code_for_counter(config, candidate)?;
                matched |= bool::from(expected.as_bytes().ct_eq(code.as_bytes()));
            }
        }
        Ok(matched)
    }

    pub fn verify_hotp(
        &self,
        config: &OtpConfig,
        code: &str,
        counter: u64,
        lookahead: u64,
    ) -> Result<Option<u64>, OtpError> {
        config.validate()?;
        for candidate in counter..=counter.saturating_add(lookahead) {
            let expected = self.code_for_counter(config, candidate)?;
            if bool::from(expected.as_bytes().ct_eq(code.as_bytes())) {
                return Ok(Some(candidate + 1));
            }
        }
        Ok(None)
    }

    /// Persist the shared secret in geode under `otp.generate`.
    pub fn store<B: Backend>(
        &self,
        store: &Store<B>,
        reference: &GeodeRef,
        label: Option<&str>,
    ) -> Result<SecretMeta, OtpError> {
        let mut credential =
            NewCredential::otp_secret(SecretBytes::new(self.key.expose().to_vec()))
                .with_purpose(Purpose::otp_generate());
        credential.label = label.map(str::to_owned);
        Ok(store.insert(reference, credential)?)
    }

    /// Load the shared secret from geode using a short lease.
    pub fn load<B: Backend>(store: &Store<B>, reference: &GeodeRef) -> Result<Self, OtpError> {
        let lease = store.lease(
            reference,
            &Purpose::otp_generate(),
            std::time::Duration::from_secs(5),
        )?;
        Self::from_bytes(lease.expose()?.to_vec())
    }

    fn code_for_counter(&self, config: &OtpConfig, counter: u64) -> Result<String, OtpError> {
        let message = counter.to_be_bytes();
        let mac = match config.algorithm {
            OtpAlgorithm::Sha1 => {
                let mut mac = Hmac::<Sha1>::new_from_slice(self.key.expose())
                    .map_err(|_| OtpError::InvalidKey)?;
                mac.update(&message);
                mac.finalize().into_bytes().to_vec()
            }
            OtpAlgorithm::Sha256 => {
                let mut mac = Hmac::<Sha256>::new_from_slice(self.key.expose())
                    .map_err(|_| OtpError::InvalidKey)?;
                mac.update(&message);
                mac.finalize().into_bytes().to_vec()
            }
            OtpAlgorithm::Sha512 => {
                let mut mac = Hmac::<Sha512>::new_from_slice(self.key.expose())
                    .map_err(|_| OtpError::InvalidKey)?;
                mac.update(&message);
                mac.finalize().into_bytes().to_vec()
            }
        };
        let offset = usize::from(mac[mac.len() - 1] & 0x0f);
        let binary = (u32::from(mac[offset] & 0x7f) << 24)
            | (u32::from(mac[offset + 1]) << 16)
            | (u32::from(mac[offset + 2]) << 8)
            | u32::from(mac[offset + 3]);
        let modulus = 10u32.pow(config.digits);
        Ok(format!(
            "{:0width$}",
            binary % modulus,
            width = config.digits as usize
        ))
    }
}

/// A parsed `otpauth://` enrollment.
pub struct Enrollment {
    pub config: OtpConfig,
    pub secret: OtpSecret,
    /// Initial HOTP counter, when present.
    pub counter: Option<u64>,
}

impl fmt::Debug for Enrollment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Enrollment")
            .field("config", &self.config)
            .field("secret", &self.secret)
            .field("counter", &self.counter)
            .finish()
    }
}

/// Parse an `otpauth://` URI (the format authenticator apps import).
///
/// Unknown parameters are ignored, as the specification requires. A missing
/// secret is an error; a missing issuer or account becomes `None`.
pub fn parse_otpauth(uri: &str) -> Result<Enrollment, OtpError> {
    let rest = uri
        .strip_prefix("otpauth://")
        .ok_or_else(|| OtpError::InvalidUri("must start with `otpauth://`".into()))?;
    let (head, query) = rest
        .split_once('?')
        .ok_or_else(|| OtpError::InvalidUri("missing query".into()))?;
    let (kind, label) = head
        .split_once('/')
        .ok_or_else(|| OtpError::InvalidUri("missing label".into()))?;
    let kind = match kind.to_ascii_lowercase().as_str() {
        "totp" => OtpKind::Totp,
        "hotp" => OtpKind::Hotp,
        other => {
            return Err(OtpError::InvalidUri(format!(
                "unsupported OTP kind `{other}`"
            )))
        }
    };

    let mut config = OtpConfig {
        kind,
        ..OtpConfig::default()
    };
    let decoded_label = percent_decode_str(label)
        .decode_utf8()
        .map_err(|_| OtpError::InvalidUri("label is not UTF-8".into()))?;
    if let Some((issuer, account)) = decoded_label.split_once(':') {
        config.issuer = Some(issuer.trim().to_owned());
        config.account = Some(account.trim().to_owned());
    } else {
        config.account = Some(decoded_label.trim().to_owned());
    }

    let mut secret = None;
    let mut counter = None;
    for pair in query.split('&') {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        let value = percent_decode_str(value)
            .decode_utf8()
            .map_err(|_| OtpError::InvalidUri("parameter is not UTF-8".into()))?;
        match key {
            "secret" => secret = Some(OtpSecret::from_base32(&value)?),
            "issuer" if !value.is_empty() => config.issuer = Some(value.into_owned()),
            "algorithm" => {
                config.algorithm = OtpAlgorithm::parse(&value).ok_or_else(|| {
                    OtpError::InvalidUri(format!("unsupported algorithm `{value}`"))
                })?;
            }
            "digits" => {
                config.digits = value
                    .parse()
                    .map_err(|_| OtpError::InvalidUri("digits is not a number".into()))?;
            }
            "period" => {
                config.period = value
                    .parse()
                    .map_err(|_| OtpError::InvalidUri("period is not a number".into()))?;
            }
            "counter" => {
                counter = Some(
                    value
                        .parse()
                        .map_err(|_| OtpError::InvalidUri("counter is not a number".into()))?,
                );
            }
            _ => {}
        }
    }
    config.validate()?;
    let secret = secret.ok_or_else(|| OtpError::InvalidUri("missing secret".into()))?;
    Ok(Enrollment {
        config,
        secret,
        counter,
    })
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0)
}
