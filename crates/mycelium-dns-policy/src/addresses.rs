//! Which node addresses a `.myc` name may publish.
//!
//! Every adapter builds its host records from its own view of the fleet — the
//! CLI from the topology, the resolver from authenticated peers — so the
//! decision of *which addresses are publishable* cannot live in either of them.
//! One rule: an address inside Mycelium's own overlay prefix always publishes,
//! because those addresses derive from the node identity and are stable across
//! networks and restarts; everything else must fall inside a scope the operator
//! declared reachable. Without this, the two adapters publish different records
//! for the same machine and a service name points at an address only one of
//! them knows.
//!
//! The prefix is Mycelium's, not "any unique-local address". Another mesh
//! (Tailscale uses `fd7a:115c:a1e0::/48`) also hands its nodes unique-local
//! addresses, and publishing those as if they were ours made the fleet's DNS
//! depend on that mesh being installed and running.

use crate::resolver::usable_address;
use std::net::IpAddr;

/// Mycelium's overlay prefix (`fc00::/7` unique-local, 40 random bits per RFC
/// 4193). A node's address in this prefix derives from its identity; the
/// tunnel interface that carries it is `mycelium0`.
pub const OVERLAY_PREFIX: &str = "fd7a:115c:a1f0::/48";

/// Whether `address` is inside Mycelium's own overlay prefix. Only these are
/// identity addresses; other unique-local space belongs to other meshes.
pub fn is_overlay(address: IpAddr) -> bool {
    in_prefix(address, OVERLAY_PREFIX)
}

/// The overlay address a node owns, derived from its node identity: same
/// identity, same address, on any network and after any reinstall.
///
/// Node ids are 32 random bytes (64 hex characters), so their last eight bytes
/// are already uniform; the address needs no hash of its own.
pub fn overlay_address(node_id: &str) -> Option<std::net::Ipv6Addr> {
    let node_id = node_id.trim();
    let low = u64::from_str_radix(node_id.get(node_id.len().checked_sub(16)?..)?, 16).ok()?;
    let mut octets = [0u8; 16];
    octets[..6].copy_from_slice(&[0xfd, 0x7a, 0x11, 0x5c, 0xa1, 0xf0]);
    octets[8..].copy_from_slice(&low.to_be_bytes());
    Some(std::net::Ipv6Addr::from(octets))
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
        && (is_overlay(address)
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
            "fd7a:115c:a1f0::6".parse().unwrap(),
            &[]
        ));
    }

    #[test]
    fn another_meshs_unique_local_space_is_not_ours() {
        // Tailscale's prefix is unique-local too. Publishing it made `.myc`
        // records depend on Tailscale being installed on every host.
        let tailscale = "fd7a:115c:a1e0::6".parse().unwrap();
        assert!(!publishable_address(tailscale, &[]));
        assert!(publishable_address(
            tailscale,
            &prefixes(&["fd7a:115c:a1e0::/48"])
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

    #[test]
    fn a_node_owns_one_stable_overlay_address() {
        let node = "87a7134985e83ac40cbb0e3e3d4d889093f9c8564db4f3ec5aab28eeebe3a67f";
        let address = overlay_address(node).unwrap();
        assert_eq!(address.to_string(), "fd7a:115c:a1f0:0:5aab:28ee:ebe3:a67f");
        assert_eq!(
            overlay_address(node),
            Some(address),
            "identity is the input"
        );
        assert!(is_overlay(IpAddr::V6(address)));
        let other =
            overlay_address("045205116ed9a9fb8902524f33afd0120481879864f909b1d6b5c9af92aa1404")
                .unwrap();
        assert_ne!(other, address);
    }

    #[test]
    fn an_address_needs_a_real_node_id() {
        assert!(overlay_address("").is_none());
        assert!(overlay_address("abcd").is_none());
        assert!(overlay_address("zzzzzzzzzzzzzzzz").is_none());
    }
}
