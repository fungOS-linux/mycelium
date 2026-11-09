//! The fleet DNS service address, assigned to loopback.
//!
//! `<prefix>::53` is the one resolver address a client has to know, but
//! dnsmasq can only answer on an address the host actually owns. Owning it is
//! a privileged operation, so `system-install` performs it and `apply`
//! refuses to start without it rather than binding a listener dnsmasq cannot
//! use.
use mycelium_dns_policy::FleetDnsAddress;
use serde_json::{json, Value};
use std::net::Ipv6Addr;
use std::process::Command;

const MACOS_LOOPBACK: &str = "lo0";

/// `ip -6 addr show dev lo` prints the address with its prefix length.
fn addr_listing_owns(text: &str, address: Ipv6Addr) -> bool {
    text.lines().any(|line| {
        line.split_whitespace()
            .any(|field| field == format!("{address}/128"))
    })
}

/// `ifconfig lo0` prints one `inet6 <address> prefixlen <n>` line per alias.
fn ifconfig_owns(text: &str, address: Ipv6Addr) -> bool {
    text.lines().any(|line| {
        let line = line.trim();
        line.starts_with(&format!("inet6 {address} ")) && line.contains("prefixlen 128")
    })
}

pub(super) fn installed(service: &FleetDnsAddress) -> Result<bool, String> {
    let address = service.address();
    if cfg!(target_os = "macos") {
        let text = output("/sbin/ifconfig", &[MACOS_LOOPBACK])?;
        Ok(ifconfig_owns(&text, address))
    } else if cfg!(target_os = "linux") {
        let text = output("ip", &["-6", "addr", "show", "dev", "lo"])?;
        Ok(addr_listing_owns(&text, address))
    } else {
        Err("fleet DNS service address is supported on macOS and Linux only".into())
    }
}

/// Assign the address if it is missing. Idempotent: a second install reports
/// `changed: false` instead of touching the interface.
pub(super) fn ensure(service: &FleetDnsAddress) -> Result<Value, String> {
    let address = service.address();
    if installed(service)? {
        return Ok(json!({"service_address": address, "changed": false}));
    }
    let host = format!("{address}/128");
    if cfg!(target_os = "macos") {
        run("/sbin/ifconfig", &[MACOS_LOOPBACK, "inet6", &host, "alias"])?;
    } else if cfg!(target_os = "linux") {
        // `addr replace` is the idempotent form; the kernel installs the
        // local route for a /128 on loopback itself.
        run("ip", &["-6", "addr", "replace", &host, "dev", "lo"])?;
    } else {
        return Err("fleet DNS service address is supported on macOS and Linux only".into());
    }
    if !installed(service)? {
        return Err(format!(
            "service address {address} did not appear after assignment"
        ));
    }
    Ok(json!({"service_address": address, "changed": true}))
}

/// Remove the address, and only the address: other loopback aliases belong to
/// whoever created them.
pub(super) fn remove(service: &FleetDnsAddress) -> Result<Value, String> {
    let address = service.address();
    if !installed(service)? {
        return Ok(json!({"service_address": address, "changed": false}));
    }
    if cfg!(target_os = "macos") {
        run(
            "/sbin/ifconfig",
            &[MACOS_LOOPBACK, "inet6", &address.to_string(), "delete"],
        )?;
    } else if cfg!(target_os = "linux") {
        run(
            "ip",
            &["-6", "addr", "del", &format!("{address}/128"), "dev", "lo"],
        )?;
    } else {
        return Err("fleet DNS service address is supported on macOS and Linux only".into());
    }
    if installed(service)? {
        return Err(format!("service address {address} is still assigned"));
    }
    Ok(json!({"service_address": address, "changed": true}))
}

fn output(program: &str, args: &[&str]) -> Result<String, String> {
    let result = Command::new(program)
        .args(args)
        .output()
        .map_err(|error| format!("run {program}: {error}"))?;
    if !result.status.success() {
        return Err(format!(
            "{program} {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&result.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&result.stdout).into_owned())
}

fn run(program: &str, args: &[&str]) -> Result<(), String> {
    output(program, args).map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    const ADDRESS: Ipv6Addr = Ipv6Addr::new(0xfd42, 0x6d79, 0x6365, 0, 0, 0, 0, 0x53);

    #[test]
    fn recognises_the_alias_in_ifconfig_output() {
        let text = "lo0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST> mtu 16384\n\tinet6 ::1 prefixlen 128\n\tinet6 fe80::1%lo0 prefixlen 64 scopeid 0x1\n\tinet6 fd42:6d79:6365::53 prefixlen 128\n\tinet 127.0.0.1 netmask 0xff000000\n";
        assert!(ifconfig_owns(text, ADDRESS));
        // A peer alias with a wider prefix is not the service address.
        assert!(!ifconfig_owns(
            "\tinet6 fd42:6d79:6365::53 prefixlen 64\n",
            ADDRESS
        ));
        assert!(!ifconfig_owns("\tinet6 ::1 prefixlen 128\n", ADDRESS));
    }

    #[test]
    fn recognises_the_alias_in_ip_addr_output() {
        let text = "2: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 state UNKNOWN qlen 1000\n    inet6 ::1/128 scope host\n    inet6 fd42:6d79:6365::53/128 scope global\n       valid_lft forever preferred_lft forever\n";
        assert!(addr_listing_owns(text, ADDRESS));
        assert!(!addr_listing_owns(
            "    inet6 ::1/128 scope host\n",
            ADDRESS
        ));
        // A /64 assignment does not answer on the derived /128.
        assert!(!addr_listing_owns(
            "    inet6 fd42:6d79:6365::/64 scope global\n",
            ADDRESS
        ));
    }
}
