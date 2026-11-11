//! Which node addresses a `.myc` name may publish.
//!
//! Every adapter builds its host records from its own view of the fleet — the
//! CLI from the topology, the resolver from authenticated peers — so the
//! decision of *which addresses are publishable* cannot live in either of them.
//! One rule: the overlay's own address space always publishes, because those
//! addresses derive from the node identity and are stable across networks and
//! restarts; everything else must fall inside a scope the operator declared
//! reachable. Without this, the two adapters publish different records for the
//! same machine and a service name points at an address only one of them knows.

use crate::resolver::usable_address;
use std::net::IpAddr;

/// IPv6 unique-local (`fc00::/7`): Mycelium's overlay lives here, and an address
/// in this range belongs to the node by identity rather than by whatever network
/// it happens to be attached to.
pub fn is_unique_local(address: IpAddr) -> bool {
    matches!(address, IpAddr::V6(v6) if (v6.segments()[0] & 0xfe00) == 0xfc00)
}

/// Whether `address` falls inside a `network/length` scope. A malformed scope
/// contains nothing: configuration is validated before anyone asks.
pub fn in_prefix(address: IpAddr, prefix: &str) -> bool {
    let Some((network, length)) = prefix.split_once('/') else {
        return false;
    };
    let (Ok(network), Ok(length)) = (network.parse::<IpAddr>(), length.parse::<u8>()) else {
        return false;
    };
    match (network, address) {
        (IpAddr::V4(network), IpAddr::V4(candidate)) if length <= 32 => {
            let mask = if length == 0 {
                0
            } else {
                u32::MAX << (32 - length)
            };
            u32::from(network) & mask == u32::from(candidate) & mask
        }
        (IpAddr::V6(network), IpAddr::V6(candidate)) if length <= 128 => {
            let mask = if length == 0 {
                0
            } else {
                u128::MAX << (128 - length)
            };
            u128::from(network) & mask == u128::from(candidate) & mask
        }
        _ => false,
    }
}

/// The publishable-address rule shared by every adapter that builds a zone.
///
/// Loopback, unspecified, multicast and link-local addresses never publish, no
/// matter what scope they sit in: a name for one of them either points a client
/// at itself or at nothing.
pub fn publishable_address(address: IpAddr, reachable_prefixes: &[String]) -> bool {
    usable_address(address)
        && (is_unique_local(address)
            || reachable_prefixes
                .iter()
                .any(|prefix| in_prefix(address, prefix)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn prefixes(scopes: &[&str]) -> Vec<String> {
        scopes.iter().map(|scope| (*scope).to_owned()).collect()
    }

    #[test]
    fn the_overlay_space_publishes_without_a_declared_scope() {
        assert!(publishable_address(
            "fd7a:115c:a1e0::6".parse().unwrap(),
            &[]
        ));
    }

    #[test]
    fn other_addresses_need_an_explicit_reachable_scope() {
        let lan = "192.168.10.30".parse().unwrap();
        assert!(!publishable_address(lan, &[]));
        assert!(!publishable_address(lan, &prefixes(&["192.168.11.0/24"])));
        assert!(publishable_address(lan, &prefixes(&["192.168.10.0/24"])));
        let v6 = "2001:db8::30".parse().unwrap();
        assert!(publishable_address(v6, &prefixes(&["2001:db8::/64"])));
        assert!(!publishable_address(v6, &prefixes(&["2001:db8:1::/64"])));
        // A scope of the other family cannot publish an address.
        assert!(!publishable_address(v6, &prefixes(&["192.168.10.0/24"])));
    }

    #[test]
    fn unusable_addresses_never_publish_even_inside_a_scope() {
        for address in [
            "127.0.0.1",
            "0.0.0.0",
            "169.254.1.1",
            "224.0.0.1",
            "::1",
            "::",
            "fe80::1",
            "ff02::1",
        ] {
            let address = address.parse().unwrap();
            assert!(
                !publishable_address(
                    address,
                    &prefixes(&["0.0.0.0/0", "::/0", "fe80::/10", "127.0.0.0/8"])
                ),
                "{address} must never be published"
            );
        }
    }

    #[test]
    fn malformed_scopes_contain_nothing() {
        let lan = "192.168.10.30".parse().unwrap();
        assert!(!in_prefix(lan, "192.168.10.0"));
        assert!(!in_prefix(lan, "192.168.10.0/é"));
        assert!(!in_prefix(lan, "192.168.10.0/33"));
    }
}
