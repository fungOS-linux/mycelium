use std::fmt;
use std::time::Duration;

use crate::clock::SharedClock;
use crate::reference::GeodeRef;
use crate::secret::{Purpose, SecretBytes};
use crate::GeodeError;

/// A bounded, purpose-scoped reveal.
///
/// A lease exists so a caller cannot hold a secret indefinitely after the
/// decision that authorized it. Expiry is enforced on every [`Lease::expose`],
/// not only checked once at issue time. The secret zeroizes when the lease drops.
///
/// Leases are intentionally not `Clone` or `Serialize`: copying or persisting
/// one defeats the bound.
pub struct Lease {
    reference: GeodeRef,
    purpose: Purpose,
    ttl: Duration,
    expires_at: u64,
    clock: SharedClock,
    secret: SecretBytes,
}

impl Lease {
    pub(crate) fn new(
        reference: GeodeRef,
        purpose: Purpose,
        ttl: Duration,
        expires_at: u64,
        clock: SharedClock,
        secret: SecretBytes,
    ) -> Self {
        Self {
            reference,
            purpose,
            ttl,
            expires_at,
            clock,
            secret,
        }
    }

    /// Reveal the secret if the lease is still live.
    pub fn expose(&self) -> Result<&[u8], GeodeError> {
        if self.is_expired() {
            return Err(GeodeError::expired(&self.reference));
        }
        Ok(self.secret.expose())
    }

    /// Reveal the secret as UTF-8 if the lease is still live.
    pub fn expose_str(&self) -> Result<&str, GeodeError> {
        let bytes = self.expose()?;
        std::str::from_utf8(bytes).map_err(|_| GeodeError::NotUtf8)
    }

    pub fn is_expired(&self) -> bool {
        self.clock.now() >= self.expires_at
    }

    pub fn remaining(&self) -> Duration {
        let now = self.clock.now();
        if now >= self.expires_at {
            Duration::ZERO
        } else {
            Duration::from_secs(self.expires_at - now)
        }
    }

    pub fn reference(&self) -> &GeodeRef {
        &self.reference
    }

    pub fn purpose(&self) -> &Purpose {
        &self.purpose
    }

    /// Requested lease duration, before clamping to the absolute expiry.
    pub fn ttl(&self) -> Duration {
        self.ttl
    }

    pub fn expires_at(&self) -> u64 {
        self.expires_at
    }
}

impl fmt::Debug for Lease {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Lease")
            .field("reference", &self.reference)
            .field("purpose", &self.purpose)
            .field("ttl", &self.ttl)
            .field("expires_at", &self.expires_at)
            .field("secret", &self.secret)
            .finish()
    }
}
