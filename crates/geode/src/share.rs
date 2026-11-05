//! WiFi sharing records.
//!
//! A WiFi record is a shared entry. Its plaintext-safe metadata — the SSID, the
//! security class, the roles, and the group public key — may be carried in the
//! clear. Its secret field, the passphrase, is always a [`SealedEnvelope`]:
//! ciphertext sealed to the owning group key, never a [`SecretBytes`], never a
//! free-form vault field.
//!
//! This mirrors the sharing contract in `application-services`: applications
//! keep credentials and secrets out of attributes, and gossip carries only
//! signed metadata, ACL directory entries, and ciphertext.

use crate::sealed::{GroupKey, SealedEnvelope, SealedError};
use serde::{Deserialize, Serialize};

/// The security class of a WiFi network.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Security {
    Open,
    Wpa,
    Wpa2,
    Wpa3,
}

impl Security {
    fn as_str(&self) -> &'static str {
        match self {
            Security::Open => "open",
            Security::Wpa => "wpa",
            Security::Wpa2 => "wpa2",
            Security::Wpa3 => "wpa3",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            "open" | "nopassword" | "none" | "no-password" | "wpa" | "wpa-passphrase" => {
                Some(Security::Open)
            }
            "wpa2" | "WPA2" => Some(Security::Wpa2),
            "wpa3" | "WPA3" => Some(Security::Wpa3),
            _ => None,
        }
    }
}

impl std::fmt::Display for Security {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A shared WiFi network.
///
/// The secret field is always ciphertext. `passphrase` is sealed to the group
/// key that the owner and every sharing device hold. Building the record with a
/// plaintext passphrase is rejected, so the invariant holds at the type level.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WifiNetwork {
    /// The network name. Plaintext-safe ACL directory metadata.
    pub ssid: String,
    /// The security class. Plaintext-safe ACL directory metadata.
    pub security: Security,
    /// Team ids this network is shared with. Plaintext-safe ACL directory
    /// metadata; a device reads the record only if it holds the group key for
    /// one of these teams.
    pub roles: Vec<String>,
    /// The group public key material used to seal the passphrase. Plaintext
    /// safe: it is the key every sharing device needs to open the envelope.
    pub group_key: GroupKey,
    /// The passphrase, sealed to [`Self::group_key`]. Ciphertext only.
    pub passphrase: SealedEnvelope,
}

impl WifiNetwork {
    /// Build a WiFi record from plaintext metadata and a sealed passphrase.
    ///
    /// The passphrase is sealed to `group_key` here, so the caller never holds
    /// a plaintext passphrase alongside the record.
    pub fn new(
        ssid: impl Into<String>,
        security: Security,
        roles: Vec<String>,
        group_key: GroupKey,
        passphrase: &[u8],
    ) -> Result<Self, SealedError> {
        Ok(Self {
            ssid: ssid.into(),
            security,
            roles,
            group_key,
            passphrase: SealedEnvelope::seal(&group_key, passphrase)?,
        })
    }

    /// Re-seal a passphrase to a new group key (key rotation).
    pub fn reseal(&mut self, group_key: &GroupKey, passphrase: &[u8]) -> Result<(), SealedError> {
        self.passphrase = SealedEnvelope::seal(group_key, passphrase)?;
        Ok(())
    }

    /// Open the sealed passphrase with a device's copy of the group key.
    pub fn open(&self, key: &GroupKey) -> Result<Vec<u8>, SealedError> {
        SealedEnvelope::open(key, &self.passphrase.ciphertext())
    }

    /// Whether `key` can open this record's passphrase.
    pub fn device_can_read(&self, key: &GroupKey) -> bool {
        self.open(key).is_ok()
    }

    /// The security class as a lowercase string.
    pub fn security_label(&self) -> &'static str {
        self.security.as_str()
    }
}

/// A device's group keys, keyed by team id.
///
/// The ACL gate: a device may read a shared WiFi record only if it holds the
/// group key for at least one team the record names in `roles`.
pub type DeviceGroupKeys = std::collections::BTreeMap<String, GroupKey>;

/// Whether a device with `keys` may read the record.
///
/// This is a pure ACL gate over the ACL directory entry ([`WifiNetwork::roles`])
/// and the device's provisioned group keys. It does not read the passphrase, so
/// it never handles a secret.
pub fn device_has_access(keys: &DeviceGroupKeys, record: &WifiNetwork) -> bool {
    record
        .roles
        .iter()
        .filter_map(|role| keys.get(role))
        .any(|key| record.device_can_read(key))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(seed: u8) -> GroupKey {
        GroupKey::from_slice(&[seed; crate::sealed::KEY_LEN].to_vec()).unwrap()
    }

    #[test]
    fn seals_and_opens_the_passphrase_with_the_matching_key() {
        let group_key = key(7);
        let record = WifiNetwork::new(
            "Home_wifi",
            Security::Wpa2,
            vec!["team-alpha".into()],
            group_key,
            b"correct horse battery staple",
        )
        .unwrap();

        assert!(record.device_can_read(&group_key));
        assert_eq!(
            record.open(&group_key).unwrap(),
            b"correct horse battery staple"
        );

        // A different key cannot open the envelope.
        let other = key(8);
        assert!(!record.device_can_read(&other));
        assert!(record.open(&other).is_err());
    }

    #[test]
    fn acl_gate_allows_a_matching_team_key_and_rejects_missing_teams() {
        let group_key = key(42);
        let ssid = "Office";
        let record = WifiNetwork::new(
            ssid,
            Security::Wpa3,
            vec!["team-alpha".into()],
            group_key,
            b"pw",
        )
        .unwrap();

        // A device that holds the group key for the named team can read it.
        let mut keys = DeviceGroupKeys::new();
        keys.insert("team-alpha".into(), group_key);
        assert!(device_has_access(&keys, &record));

        // A device that has the key but is not named in roles is denied.
        let mut keys = DeviceGroupKeys::new();
        keys.insert("team-beta".into(), group_key);
        assert!(!device_has_access(&keys, &record));

        // A device missing the key for the named team is denied.
        let mut keys = DeviceGroupKeys::new();
        keys.insert("team-alpha".into(), key(0));
        assert!(!device_has_access(&keys, &record));

        // A record named for two teams is readable by a device holding either team's key.
        let multi = WifiNetwork::new(
            "Multi",
            Security::Wpa2,
            vec!["team-gamma".into(), "team-alpha".into()],
            group_key,
            b"pw",
        )
        .unwrap();
        let mut keys = DeviceGroupKeys::new();
        keys.insert("team-gamma".into(), key(1));
        keys.insert("team-alpha".into(), group_key);
        assert!(device_has_access(&keys, &multi));
    }

    #[test]
    fn re_sealing_rotates_the_passphrase_for_a_new_group_key() {
        let old_key = key(1);
        let mut record = WifiNetwork::new(
            "Rotate",
            Security::Wpa2,
            vec!["team".into()],
            old_key,
            b"v1",
        )
        .unwrap();
        assert_eq!(record.open(&old_key).unwrap(), b"v1");

        let new_key = key(2);
        record.reseal(&new_key, b"v2").unwrap();
        assert!(record.device_can_read(&new_key));
        assert!(!record.device_can_read(&old_key));
        assert_eq!(record.open(&new_key).unwrap(), b"v2");
    }

    #[test]
    fn security_serializes_to_lowercase_labels() {
        assert_eq!(Security::Wpa2.to_string(), "wpa2");
        assert_eq!(Security::parse("WPA2"), Some(Security::Wpa2));
        assert_eq!(Security::parse("wired"), None);
    }
}
