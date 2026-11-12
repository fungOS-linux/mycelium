use std::collections::BTreeSet;

use mycelium_core::topology::Topology;
pub(crate) use mycelium_dns_policy::{canonical_domain, plan, Delegation};
use mycelium_dns_policy::{BlockAction, Blocklist, BlocklistSource};
use mycelium_peer_protocol::WireGuardBinding;
use myceliumd::protocol::Request;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

/// `mycelium dns blocklist plan|check`: review local lists before the resolver
/// reads them. Fetching is a separate explicit step, so nothing here reaches
/// the network and the same files always produce the same lines.
pub(crate) fn blocklist(args: &[String]) -> Result<Vec<String>, String> {
    let action_name = args
        .first()
        .map(String::as_str)
        .ok_or("blocklist needs `plan` or `check`")?;
    if !matches!(action_name, "plan" | "check") {
        return Err("blocklist supports `plan` and `check`".into());
    }
    let mut sources = Vec::new();
    let mut allow = Vec::new();
    let mut suffix = String::from("myc");
    let mut action = BlockAction::default();
    let mut subject = None;
    let mut json = false;
    let mut dnsmasq = false;
    let mut seen = BTreeSet::new();
    let mut rest = args[1..].iter();
    while let Some(flag) = rest.next() {
        if !seen.insert(flag.as_str()) {
            return Err("duplicate blocklist option".into());
        }
        match flag.as_str() {
            "--json" => json = true,
            "--dnsmasq" if action_name == "plan" => dnsmasq = true,
            "--source" => sources.push(BlocklistSource {
                path: PathBuf::from(rest.next().ok_or("--source needs a file")?),
            }),
            "--allow" => allow.push(rest.next().ok_or("--allow needs a domain")?.to_string()),
            "--suffix" => suffix = rest.next().ok_or("--suffix needs a domain")?.to_string(),
            "--action" => {
                action = BlockAction::parse(rest.next().ok_or("--action needs an action")?)?
            }
            other if action_name == "check" && !other.starts_with("--") && subject.is_none() => {
                subject = Some(other.to_string())
            }
            _ => return Err("unknown blocklist option".into()),
        }
    }
    if sources.is_empty() {
        return Err("blocklist needs at least one --source".into());
    }
    if action_name == "check" && json && dnsmasq {
        return Err("choose --json or --dnsmasq".into());
    }
    let blocks = Blocklist::load(&sources, &suffix, &allow)?;
    if action_name == "check" {
        let name = canonical_domain(&subject.ok_or("blocklist check needs a name")?)?;
        let zone = blocks.matched(&name);
        if json {
            return Ok(vec![serde_json::json!({
                "name": name,
                "blocked": zone.is_some(),
                "zone": zone,
                "action": action.as_str(),
            })
            .to_string()]);
        }
        return Ok(vec![match zone {
            Some(zone) => format!("blocked by {zone} ({})", action.as_str()),
            None => format!("{name} is not on any configured list"),
        }]);
    }
    if dnsmasq {
        return Ok(vec![blocks.render(action)]);
    }
    if json {
        return Ok(vec![serde_json::json!({
            "suffix": canonical_domain(&suffix)?,
            "action": action.as_str(),
            "zones": blocks.len(),
            "skipped": blocks.skipped(),
            "allowlist": blocks.allowlist(),
            "sources": blocks.sources(),
        })
        .to_string()]);
    }
    let mut lines = vec![format!(
        "{} zones from {} source(s), {} line(s) skipped; action {}",
        blocks.len(),
        blocks.sources().len(),
        blocks.skipped(),
        action.as_str()
    )];
    lines.extend(blocks.zones().take(20).map(str::to_string));
    if blocks.len() > 20 {
        lines.push(format!("... {} more", blocks.len() - 20));
    }
    Ok(lines)
}

/// Address scopes this site occupies, so the resolver publishes peer
/// addresses it can actually reach and nothing else.
///
/// Signed bindings describe routed prefixes, which are per-host `/32`s on
/// most sites and would publish nothing. A site's nodes also report the
/// addresses they hold, and the covering `/24` (or `/64`) of those is the
/// subnet the peer is on — that is the scope a site-local resolver answers
/// from, and it never widens beyond names in the site's own namespace.
pub(crate) async fn live_prefixes(site: &str) -> Result<Vec<String>, String> {
    let mut client = crate::connect()
        .await
        .map_err(|error| format!("connect to the daemon: {error}"))?;
    let value = client
        .call(&Request::WireGuardBindingList)
        .await
        .map_err(|error| format!("read routed prefixes: {error}"))?;
    let bindings: Vec<WireGuardBinding> =
        serde_json::from_value(value).map_err(|error| format!("invalid bindings: {error}"))?;
    let topology: Topology = serde_json::from_value(
        client
            .call(&Request::Topology)
            .await
            .map_err(|error| format!("read topology: {error}"))?,
    )
    .map_err(|error| format!("invalid topology: {error}"))?;
    let mut prefixes = BTreeSet::new();
    for binding in bindings.iter().filter(|binding| binding.site == site) {
        for prefix in &binding.advertised_prefixes {
            if mycelium_core::parse_cidr(prefix).is_none() {
                return Err(format!(
                    "daemon advertised invalid routed prefix `{prefix}`"
                ));
            }
            prefixes.insert(prefix.clone());
        }
    }
    // Only nodes this site has a signed route to: an address nobody routed to
    // is not a scope a site-local resolver should answer from.
    let routed = bindings
        .iter()
        .filter(|binding| binding.site == site)
        .map(|binding| binding.credential.node_id.as_str())
        .collect::<BTreeSet<_>>();
    for node in topology.nodes.values() {
        if !node.sites.contains(site) || !routed.contains(node.id.as_str()) {
            continue;
        }
        for address in node.ips.keys() {
            if let Some(prefix) = covering_prefix(*address) {
                prefixes.insert(prefix);
            }
        }
    }
    if prefixes.is_empty() {
        return Err(format!(
            "no signed routes or site addresses for `{site}`; pass --reachable to `mycelium dns resolver init`"
        ));
    }
    if prefixes.len() > 64 {
        return Err(format!(
            "site `{site}` spans {} scopes; review them and pass --reachable",
            prefixes.len()
        ));
    }
    Ok(prefixes.into_iter().collect())
}

/// Container bridges and hypervisor NAT ranges are reported by every host that
/// runs a workload, and no fleet name is ever published from them. A site that
/// genuinely uses `172.16/12` passes `--reachable` explicitly instead.
fn is_container_scope(address: std::net::Ipv4Addr) -> bool {
    let octets = address.octets();
    matches!(
        octets,
        [172, 16..=31, _, _]
            | [10, 0, 2, _]
            | [192, 0, 2, _]
            | [198, 51, 100, _]
            | [203, 0, 113, _]
    )
}

/// The subnet a peer address sits on. Never wider than a `/24` or `/64`, so
/// one reported address cannot claim an entire private range.
fn covering_prefix(address: IpAddr) -> Option<String> {
    match address {
        IpAddr::V4(address)
            if !address.is_loopback()
                && !address.is_link_local()
                && !address.is_unspecified()
                && !is_container_scope(address) =>
        {
            let network = u32::from(address) & 0xffff_ff00;
            Some(format!("{}/24", std::net::Ipv4Addr::from(network)))
        }
        IpAddr::V6(address)
            if !address.is_loopback()
                && !address.is_unspecified()
                && !address.is_unicast_link_local() =>
        {
            let network = u128::from(address) & (u128::MAX << 64);
            Some(format!("{}/64", std::net::Ipv6Addr::from(network)))
        }
        _ => None,
    }
}

/// `mycelium dns resolver init` from a node's own point of view: fill in the
/// site, namespace and routed prefixes that can be derived here, so a rollout
/// never hand-copies site data. Anything given explicitly wins.
fn given(values: &[String], name: &str) -> bool {
    values.iter().any(|value| value == name)
}

pub(crate) async fn resolver_init(args: &[String]) -> Result<Vec<String>, String> {
    let mut forward = Vec::new();
    let mut rest = args.iter();
    while let Some(flag) = rest.next() {
        match flag.as_str() {
            "--site" | "--suffix" | "--reachable" | "--config" | "--doh" | "--doh-listen"
            | "--dnsmasq" | "--mycelium" => {
                let value = rest.next().ok_or_else(|| format!("{flag} needs a value"))?;
                forward.push(flag.clone());
                forward.push(value.clone());
            }
            "--write" | "--dry-run" | "--force" => forward.push(flag.clone()),
            _ => return Err(format!("unknown resolver init option `{flag}`")),
        }
    }
    if !given(&forward, "--config") {
        return Err("resolver init needs --config".into());
    }
    let home = myceliumd::home_dir();
    let (site, suffix) = crate::enroll::identity(&home)?;
    if !given(&forward, "--site") {
        forward.push("--site".to_string());
        forward.push(site.clone());
    }
    if !given(&forward, "--suffix") {
        forward.push("--suffix".to_string());
        forward.push(suffix);
    }
    if !given(&forward, "--reachable") {
        for prefix in live_prefixes(&site).await? {
            forward.push("--reachable".to_string());
            forward.push(prefix);
        }
    }
    let mut command = vec!["init".to_string()];
    command.extend(forward);
    Ok(vec![mycelium_driver_dnsmasq::command(&command).await?])
}

/// Make this node serve `.myc` locally: create the policy file from its own
/// identity and live routes when it is missing, then apply it. Records are
/// observed at apply time, so the configuration holds policy, not data.
pub(crate) async fn ensure(home: &Path) -> Result<Vec<String>, String> {
    let (site, suffix) = crate::enroll::identity(home)?;
    let config = home.join("dns/resolver.json");
    let mut lines = Vec::new();
    if !config.is_file() {
        let prefixes = live_prefixes(&site).await?;
        let managed = home.join("bin/mycelium");
        let mycelium = if managed.is_file() {
            managed
        } else {
            std::env::current_exe()
                .map_err(|error| format!("locate the Mycelium binary: {error}"))?
        };
        mycelium_driver_dnsmasq::init(
            &config,
            mycelium_driver_dnsmasq::InitOptions {
                site: site.clone(),
                suffix: suffix.clone(),
                reachable_prefixes: prefixes,
                service_address: None,
                listen: vec![],
                dnsmasq: None,
                mycelium: Some(mycelium),
                // Which encrypted endpoint to trust is a policy decision, so a
                // repair never invents one; `dns resolver init --doh` sets it.
                doh: None,
            },
            false,
        )?;
        lines.push(format!(
            "initialized DNS policy for {site} at {}",
            config.display()
        ));
    }
    let command = [
        "apply".to_string(),
        "--config".to_string(),
        config.display().to_string(),
        "--write".to_string(),
    ];
    // A repair restarts the daemon, so the first apply can land before gossip
    // has repopulated. Retry only that condition, and only for a minute.
    let mut last = String::new();
    for attempt in 0..12 {
        match mycelium_driver_dnsmasq::command(&command).await {
            Ok(applied) => {
                lines.push(format!("DNS resolver: {applied}"));
                return Ok(lines);
            }
            Err(error) if error.contains("no fresh reachable records") && attempt < 11 => {
                last = error;
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            }
            Err(error) => return Err(error),
        }
    }
    Err(last)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocklist_cli_reports_counts_and_refuses_namespace_entries() {
        let path = std::env::temp_dir().join(format!("cli-block-{}", std::process::id()));
        std::fs::write(&path, "0.0.0.0 ads.example.com\n").unwrap();
        let source = path.to_string_lossy().to_string();
        let args = |list: &[&str]| {
            list.iter()
                .map(|value| value.to_string())
                .collect::<Vec<_>>()
        };
        let plan = blocklist(&args(&["plan", "--source", &source, "--json"])).unwrap();
        assert!(plan[0].contains("\"zones\":1"), "{}", plan[0]);
        let hit = blocklist(&args(&["check", "x.ads.example.com", "--source", &source])).unwrap();
        assert!(hit[0].contains("blocked by ads.example.com"), "{}", hit[0]);
        std::fs::write(&path, "node.myc\n").unwrap();
        assert!(blocklist(&args(&["plan", "--source", &source])).is_err());
        let _ = std::fs::remove_file(&path);
    }
}
