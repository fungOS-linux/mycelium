//! The anycast DNS service address a fleet publishes.
//!
//! Every node that answers DNS for the fleet can bind the same
//! `<fleet-prefix>::53` address. A client that only knows the address (an
//! ESP32, a container, a rescue shell) therefore has one stable resolver URL
//! regardless of which node answers it.
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use std::net::Ipv6Addr;
use std::str::FromStr;

/// A ULA prefix plus the derived `<prefix>::53` service address.
///
/// Generate one random `/48` per fleet and keep it in the enrollment CA. Do
/// not reuse Tailscale's `fd7a:115c:a1e0::/48`; both planes may coexist on the
/// same host.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FleetDnsAddress {
    prefix: Ipv6Addr,
    prefix_len: u8,
    address: Ipv6Addr,
}

impl FleetDnsAddress {
    pub fn parse(value: &str) -> Result<Self, String> {
        value.parse()
    }

    pub fn prefix(&self) -> Ipv6Addr {
        self.prefix
    }

    pub fn prefix_len(&self) -> u8 {
        self.prefix_len
    }

    pub fn address(&self) -> Ipv6Addr {
        self.address
    }
}

impl FromStr for FleetDnsAddress {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let (prefix, length) = value
            .split_once('/')
            .ok_or("fleet DNS prefix must be an IPv6 ULA CIDR")?;
        let prefix: Ipv6Addr = prefix
            .parse()
            .map_err(|_| "fleet DNS prefix must be IPv6")?;
        let length: u8 = length
            .parse()
            .map_err(|_| "fleet DNS prefix length must be 48..=64")?;
        if !(48..=64).contains(&length) {
            return Err("fleet DNS prefix length must be 48..=64".into());
        }
        let first_byte = (u128::from(prefix) >> 120) as u8;
        if first_byte & 0xfe != 0xfc {
            return Err("fleet DNS prefix must be a ULA (fc00::/7)".into());
        }
        let mask = u128::MAX << (128 - u32::from(length));
        if u128::from(prefix) & !mask != 0 {
            return Err("fleet DNS prefix has host bits set".into());
        }
        let address = Ipv6Addr::from(u128::from(prefix) | 0x53);
        Ok(Self {
            prefix,
            prefix_len: length,
            address,
        })
    }
}

impl fmt::Display for FleetDnsAddress {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}/{}", self.prefix, self.prefix_len)
    }
}

impl Serialize for FleetDnsAddress {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for FleetDnsAddress {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        String::deserialize(deserializer)?
            .parse()
            .map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derives_the_service_address_from_a_ula_prefix() {
        let service: FleetDnsAddress = "fd42:6d79:6365::/48".parse().unwrap();
        assert_eq!(service.address().to_string(), "fd42:6d79:6365::53");
        assert_eq!(service.prefix().to_string(), "fd42:6d79:6365::");
        assert_eq!(service.prefix_len(), 48);
        assert_eq!(service.to_string(), "fd42:6d79:6365::/48");
    }

    #[test]
    fn supports_site_scoped_64_bit_prefixes() {
        let service: FleetDnsAddress = "fd42:6d79:6365:12::/64".parse().unwrap();
        assert_eq!(service.address().to_string(), "fd42:6d79:6365:12::53");
    }

    #[test]
    fn rejects_non_ula_lengths_and_host_bits() {
        assert!("2001:db8::/48".parse::<FleetDnsAddress>().is_err());
        assert!("fd00::/32".parse::<FleetDnsAddress>().is_err());
        assert!("fd00::/65".parse::<FleetDnsAddress>().is_err());
        assert!("fd00::1/48".parse::<FleetDnsAddress>().is_err());
        assert!("fd00::".parse::<FleetDnsAddress>().is_err());
        assert!("not-a-prefix/48".parse::<FleetDnsAddress>().is_err());
    }

    #[test]
    fn serializes_as_a_cidr_string() {
        let service: FleetDnsAddress = "fd42:6d79:6365::/48".parse().unwrap();
        let encoded = serde_json::to_string(&service).unwrap();
        assert_eq!(encoded, "\"fd42:6d79:6365::/48\"");
        let decoded: FleetDnsAddress = serde_json::from_str(&encoded).unwrap();
        assert_eq!(decoded, service);
    }
}
