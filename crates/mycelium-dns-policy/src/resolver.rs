//! Optional resolver policy. Names, reachability scopes and grants are read
//! from one installed document, but only naming and scope reach the zone.
use crate::blocklist::{BlockAction, Blocklist, BlocklistSource};
use crate::{canonical_domain, plan, Delegation, DnsRecord, FleetDnsAddress};
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ResolverMode {
    #[default]
    Off,
    LocalhostOnly,
    LanServing,
    /// The fleet resolver: binds `<prefix>::53` so every node answers the same
    /// address locally. Requires a service address and port 53.
    Fleet,
}

/// A DoH endpoint the local resolver forwards non-`.myc` names to.
///
/// dnsmasq cannot speak DoH, so a bounded forwarder owns the encrypted hop
/// and dnsmasq points at it. Plaintext `upstreams` are refused alongside it:
/// fail-closed means there is no path that silently drops back to port 53.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DohUpstream {
    pub endpoint: String,
    pub listen: SocketAddr,
    #[serde(default = "doh_timeout_default")]
    pub timeout_seconds: u32,
    #[serde(default = "doh_inflight_default")]
    pub max_inflight: u16,
}

fn doh_timeout_default() -> u32 {
    5
}

fn doh_inflight_default() -> u16 {
    8
}

impl DohUpstream {
    pub fn validate(&self) -> Result<(), String> {
        let endpoint = self.endpoint.trim();
        if !endpoint.starts_with("https://")
            || endpoint.len() > 2048
            || endpoint[8..].trim_end_matches('/').is_empty()
            || endpoint
                .chars()
                .any(|character| character.is_control() || character.is_whitespace())
        {
            return Err("DoH endpoint must be an https:// URL".into());
        }
        if !self.listen.ip().is_loopback() || self.listen.port() == 0 {
            return Err("DoH forwarder must listen on a nonzero loopback address".into());
        }
        if !(1..=10).contains(&self.timeout_seconds) || !(1..=64).contains(&self.max_inflight) {
            return Err("DoH timeout must be 1..=10s and in-flight limit 1..=64".into());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResolverConfig {
    #[serde(default)]
    pub mode: ResolverMode,
    pub site: String,
    pub suffix: String,
    pub listen: Vec<SocketAddr>,
    /// Explicit upstreams, never inferred from a resolver pointing at ourselves.
    pub upstreams: Vec<SocketAddr>,
    /// Anycast DNS service address (`<fleet-prefix>::53`) this resolver answers too.
    #[serde(default)]
    pub service_address: Option<FleetDnsAddress>,
    #[serde(default)]
    pub delegations: Vec<Delegation>,
    /// Explicit child namespace owner; addresses derive from fresh reachable records.
    /// This authorizes catch-all DNS, not TLS issuance or application access.
    #[serde(default)]
    pub namespace_owners: std::collections::BTreeMap<String, String>,
    /// Local, already-fetched blocking sources; empty disables blocking.
    /// Fetching is a separate explicit step, so rendering stays deterministic.
    #[serde(default)]
    pub blocklists: Vec<BlocklistSource>,
    #[serde(default)]
    pub block_action: BlockAction,
    /// Domains that must never be blocked, including their whole subtree.
    #[serde(default)]
    pub allowlist: Vec<String>,
    /// Forward non-`.myc` names over DoH through a local bounded forwarder
    /// (dnsmasq points at `server=<listen ip>#<listen port>`).
    #[serde(default)]
    pub doh: Option<DohUpstream>,
}

impl ResolverConfig {
    /// Produces only DNS configuration: never DHCP or an OS default DNS change.
    pub fn render(&self, records: Vec<DnsRecord>) -> Result<String, String> {
        self.render_for_sites(records, &[])
    }

    /// Project reviewed peer sites without renaming the observed site identities.
    pub fn render_for_sites(
        &self,
        records: Vec<DnsRecord>,
        additional_sites: &[String],
    ) -> Result<String, String> {
        self.render_with(records, additional_sites, &Blocklist::default())
    }

    /// Load the configured local lists against this resolver's namespace.
    pub fn blocks(&self) -> Result<Blocklist, String> {
        Blocklist::load(&self.blocklists, &self.suffix, &self.allowlist)
    }

    /// Render with an already-loaded blocklist so `apply` and `plan` share one
    /// parse, and so a caller can report counts without rendering twice.
    pub fn render_with(
        &self,
        records: Vec<DnsRecord>,
        additional_sites: &[String],
        blocks: &Blocklist,
    ) -> Result<String, String> {
        // A fleet resolver without an address would serve a localhost listener
        // while claiming to be the fleet's resolver.
        if self.mode == ResolverMode::Fleet && self.service_address.is_none() {
            return Err("fleet resolver mode requires resolver.service_address".into());
        }
        let mut sites = std::collections::BTreeSet::new();
        if additional_sites.len() > 32 {
            return Err("too many additional DNS sites".into());
        }
        for site in additional_sites {
            if canonical_domain(site)? != *site
                || site.contains('.')
                || site == &self.site
                || !sites.insert(site)
            {
                return Err("additional sites need unique canonical labels".into());
            }
            let zone = format!("{site}.{}", self.suffix);
            if self
                .delegations
                .iter()
                .any(|d| d.zone == zone || d.zone.ends_with(&format!(".{zone}")))
            {
                return Err("additional site overlaps delegated namespace".into());
            }
        }
        let remote_records = records.clone();
        let zone = plan(&self.site, &self.suffix, records, self.delegations.clone())?;
        if self.mode == ResolverMode::Off {
            return Ok(String::new());
        }
        // Each admitted site's existing plan is the validation boundary. Raw
        // observations from unadmitted sites must never supply namespace owners.
        let additional_zones = additional_sites
            .iter()
            .map(|site| plan(site, &self.suffix, remote_records.clone(), vec![]))
            .collect::<Result<Vec<_>, _>>()?;
        let admitted_records: Vec<_> = zone
            .records
            .iter()
            .chain(additional_zones.iter().flat_map(|zone| zone.records.iter()))
            .collect();
        let mut record_owners = std::collections::BTreeMap::new();
        for record in &admitted_records {
            if record_owners
                .insert(&record.name, &record.node)
                .is_some_and(|owner| owner != &record.node)
            {
                return Err("DNS name has competing owners across admitted sites".into());
            }
        }
        if self.listen.is_empty() || self.listen.len() > 8 || self.upstreams.len() > 8 {
            return Err("resolver needs 1..8 explicit listeners and at most 8 upstreams".into());
        }
        let port = self.listen[0].port();
        if port == 0 || self.listen.iter().any(|s| s.port() != port) {
            return Err("listeners must use the same nonzero port".into());
        }
        if self.doh.is_some() && !self.upstreams.is_empty() {
            return Err(
                "DoH and plaintext upstreams cannot coexist; the resolver fails closed".into(),
            );
        }
        if let Some(doh) = &self.doh {
            doh.validate()?;
            if self.listen.contains(&doh.listen) {
                return Err("DoH forwarder cannot share the resolver's own socket".into());
            }
        }
        for listener in &self.listen {
            let address = listener.ip();
            if address.is_unspecified() || address.is_multicast() {
                return Err("wildcard and multicast DNS listeners are forbidden".into());
            }
            if self.mode == ResolverMode::LocalhostOnly && !address.is_loopback() {
                return Err("localhost-only requires loopback listeners".into());
            }
        }
        for server in self.upstreams.iter().copied().chain(
            self.delegations
                .iter()
                .map(|d| SocketAddr::new(d.server, d.port)),
        ) {
            if server.port() == 0
                || server.ip().is_unspecified()
                || server.ip().is_multicast()
                || server.ip().is_loopback()
                || self.listen.contains(&server)
            {
                return Err("invalid upstream or forwarding loop".into());
            }
        }
        let mut config = format!(
            "# Managed by Mycelium; DNS only.\nport={port}\nbind-interfaces\nno-resolv\nno-hosts\ncache-size=256\nlocal-ttl=30\n"
        );
        for address in &self.listen {
            config.push_str(&format!("listen-address={}\n", address.ip()));
        }
        if let Some(service) = self.service_address {
            if port != 53 {
                return Err("fleet DNS service address requires port 53".into());
            }
            let service_ip = IpAddr::V6(service.address());
            if self
                .listen
                .iter()
                .any(|listener| listener.ip() == service_ip)
                || self
                    .upstreams
                    .iter()
                    .any(|upstream| upstream.ip() == service_ip)
                || admitted_records
                    .iter()
                    .any(|record| record.address == service_ip)
            {
                return Err(
                    "fleet DNS service address conflicts with a listener, upstream, or record"
                        .into(),
                );
            }
            config.push_str(&format!("listen-address={service_ip}\n"));
        }
        // A block entry at or below a delegated or owned namespace is shadowed
        // by that namespace's more specific directive, so the operator would
        // see a rule that never fires. Fail instead of serving a half policy.
        for delegation in &self.delegations {
            if let Some(entry) = blocks.covers(&delegation.zone) {
                return Err(format!(
                    "blocklist entry `{entry}` is shadowed by delegated namespace {}",
                    delegation.zone
                ));
            }
        }
        for namespace in self.namespace_owners.keys() {
            if let Some(entry) = blocks.covers(namespace) {
                return Err(format!(
                    "blocklist entry `{entry}` is shadowed by owned namespace {namespace}"
                ));
            }
        }
        if !blocks.is_empty() {
            config.push_str(&blocks.render(self.block_action));
        }
        for server in &self.upstreams {
            config.push_str(&format!("server={}#{}\n", server.ip(), server.port()));
        }
        // A localhost-only resolver is the bootstrap for local capability
        // gateways: an unknown `.myc` name means "use the local gateway", while
        // explicit host records stay more specific. A LAN or fleet resolver must
        // never hand its own loopback to a client.
        if self.mode == ResolverMode::LocalhostOnly {
            config.push_str(&format!("address=/.{}/127.0.0.1\n", self.suffix));
        }
        // The forwarder is the only default upstream when it is configured.
        if let Some(doh) = &self.doh {
            config.push_str(&format!(
                "server={}#{}\n",
                doh.listen.ip(),
                doh.listen.port()
            ));
        }
        // A localhost-only resolver is the bootstrap for local capability
        // gateways: unknown `.myc` names mean "use the local gateway", while
        // explicit host records (including discovered node and service names)
        // remain more specific. A LAN-serving resolver must not return its own
        // loopback to clients.
        if self.mode == ResolverMode::LocalhostOnly {
            config.push_str(&format!("address=/.{}/127.0.0.1\n", zone.suffix));
        }
        config.push_str(&zone.dnsmasq);
        if self.namespace_owners.len() > 8 {
            return Err("too many owned DNS namespaces".into());
        }
        for (namespace, owner) in &self.namespace_owners {
            let canonical = canonical_domain(namespace)?;
            if canonical != *namespace
                || !namespace.ends_with(&format!(".{}", zone.suffix))
                || owner.is_empty()
                || owner.len() > 128
                || owner.chars().any(char::is_control)
                || zone.delegations.iter().any(|d| {
                    namespace == &d.zone
                        || namespace.ends_with(&format!(".{}", d.zone))
                        || d.zone.ends_with(&format!(".{namespace}"))
                })
                || self
                    .namespace_owners
                    .keys()
                    .any(|other| other != namespace && other.ends_with(&format!(".{namespace}")))
                || admitted_records
                    .iter()
                    .any(|r| r.name == *namespace || r.name.ends_with(&format!(".{namespace}")))
            {
                return Err("invalid or conflicting child namespace ownership".into());
            }
            // No owner evidence means no answer; never choose another gateway.
            let addresses: std::collections::BTreeSet<_> = admitted_records
                .iter()
                .filter(|r| &r.node == owner)
                .map(|r| r.address)
                .collect();
            for address in addresses {
                config.push_str(&format!("address=/{namespace}/{address}\n"));
            }
        }
        for additional_zone in additional_zones {
            config.push_str(&additional_zone.dnsmasq);
        }
        Ok(config)
    }

    /// macOS supplemental resolver: this zone only, never replaces uplink DNS.
    pub fn macos_namespace(&self) -> Result<(String, String), String> {
        self.render(Vec::new())?;
        if self.mode == ResolverMode::Off {
            return Err("off mode has no supplemental resolver".into());
        }
        let listener = self
            .listen
            .iter()
            .find(|s| s.ip().is_loopback())
            .ok_or("macOS namespace routing needs a loopback listener")?;
        let suffix = canonical_domain(&self.suffix)?;
        Ok((
            suffix.clone(),
            format!(
                "# Managed by Mycelium DNS resolver\ndomain {suffix}\nnameserver {}\nport {}\ntimeout 2\n",
                listener.ip(),
                listener.port()
            ),
        ))
    }
}

/// Only usable unicast records may be published by a local observation adapter.
pub fn usable_address(address: IpAddr) -> bool {
    !address.is_loopback()
        && !address.is_unspecified()
        && !address.is_multicast()
        && match address {
            IpAddr::V4(a) => !a.is_link_local() && !a.is_broadcast(),
            IpAddr::V6(a) => a.segments()[0] & 0xffc0 != 0xfe80,
        }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn remote_record(site: &str, name: &str, owner: &str) -> DnsRecord {
        DnsRecord {
            name: name.into(),
            site: site.into(),
            node: owner.into(),
            address: "192.0.2.20".parse().unwrap(),
        }
    }
    #[test]
    fn owned_namespace_uses_only_validated_admitted_remote_site() {
        let mut c = config();
        c.namespace_owners
            .insert("invoker.myc".into(), "gateway".into());
        let records = vec![remote_record("cloud", "gateway.cloud.myc", "gateway")];
        assert!(!c
            .render(records.clone())
            .unwrap()
            .contains("address=/invoker.myc/"));
        let text = c.render_for_sites(records, &["cloud".into()]).unwrap();
        assert!(text.contains("address=/invoker.myc/192.0.2.20\n"));
        assert!(text.contains("host-record=gateway.cloud.myc,192.0.2.20\n"));
    }
    #[test]
    fn remote_site_namespace_collision_is_not_hidden_by_render_order() {
        let mut c = config();
        c.namespace_owners
            .insert("invoker.myc".into(), "gateway".into());
        let records = vec![remote_record("cloud", "service.invoker.myc", "other")];
        assert!(c.render(records.clone()).is_ok());
        assert!(c
            .render_for_sites(records, &["cloud".into()])
            .unwrap_err()
            .contains("conflicting"));
    }
    #[test]
    fn rejects_competing_names_across_admitted_sites() {
        let c = config();
        let records = vec![
            remote_record("lab", "same.myc", "one"),
            remote_record("cloud", "same.myc", "two"),
        ];
        assert!(c.render(records.clone()).is_ok());
        assert!(c
            .render_for_sites(records, &["cloud".into()])
            .unwrap_err()
            .contains("competing owners"));
    }
    #[test]
    fn admitted_remote_owner_must_pass_existing_plan_guards() {
        let mut c = config();
        c.namespace_owners
            .insert("invoker.myc".into(), "gateway".into());
        let record = remote_record("cloud", "gateway.external.example", "gateway");
        assert!(c.render(vec![record.clone()]).is_ok());
        assert!(c.render_for_sites(vec![record], &["cloud".into()]).is_err());
        assert!(!c
            .render_for_sites(vec![], &["cloud".into()])
            .unwrap()
            .contains("address=/invoker.myc/"));
    }
    #[test]
    fn namespace_answers_follow_explicit_fresh_owner_records() {
        let mut c = config();
        c.namespace_owners
            .insert("ipfs.myc".into(), "gateway".into());
        assert!(!c.render(vec![]).unwrap().contains("address=/ipfs.myc/"));
        let record = DnsRecord {
            name: "agora.lab.myc".into(),
            site: "lab".into(),
            node: "gateway".into(),
            address: "192.168.1.20".parse().unwrap(),
        };
        assert!(c
            .render(vec![record])
            .unwrap()
            .contains("address=/ipfs.myc/192.168.1.20"));
        for invalid in ["myc", "external.example", "*.ipfs.myc"] {
            c.namespace_owners.clear();
            c.namespace_owners.insert(invalid.into(), "gateway".into());
            assert!(c.render(vec![]).is_err());
        }
    }
    #[test]
    fn fleet_service_address_renders_and_requires_port_53() {
        let mut config = config();
        config.mode = ResolverMode::LanServing;
        config.listen = vec!["127.0.0.1:53".parse().unwrap()];
        config.service_address = Some("fd42:6d79:6365::/48".parse().unwrap());
        let rendered = config.render(Vec::new()).unwrap();
        assert!(rendered.contains("listen-address=fd42:6d79:6365::53"));
        config.listen = vec!["127.0.0.1:1053".parse().unwrap()];
        assert!(config.render(Vec::new()).is_err());
        config.listen = vec!["[fd42:6d79:6365::53]:53".parse().unwrap()];
        assert!(config.render(Vec::new()).is_err());
    }

    #[test]
    fn fleet_mode_requires_a_service_address_and_answers_it_on_port_53() {
        let mut config = config();
        config.mode = ResolverMode::Fleet;
        assert!(
            config.render(Vec::new()).is_err(),
            "fleet mode without an address is a localhost listener with a title"
        );

        config.listen = vec!["127.0.0.1:53".parse().unwrap()];
        config.service_address = Some("fd42:6d79:6365::/48".parse().unwrap());
        let rendered = config.render(Vec::new()).unwrap();
        assert!(rendered.contains("listen-address=fd42:6d79:6365::53"));

        let mut value = serde_json::to_value(&config).unwrap();
        value["mode"] = serde_json::json!("fleet");
        let parsed: ResolverConfig = serde_json::from_value(value).unwrap();
        assert_eq!(parsed.mode, ResolverMode::Fleet);
    }

    #[test]
    fn localhost_only_bootstraps_unknown_names_to_the_local_gateway() {
        let text = config().render(Vec::new()).unwrap();
        assert!(text.contains("address=/.myc/127.0.0.1\n"), "{text}");

        // A resolver that serves other machines must not answer with its own
        // loopback, and the fleet resolver answers a real address.
        let mut lan = config();
        lan.mode = ResolverMode::LanServing;
        lan.listen = vec!["192.0.2.10:1053".parse().unwrap()];
        assert!(!lan.render(Vec::new()).unwrap().contains("address=/.myc/"));

        let mut fleet = config();
        fleet.mode = ResolverMode::Fleet;
        fleet.listen = vec!["127.0.0.1:53".parse().unwrap()];
        fleet.service_address = Some("fd42:6d79:6365::/48".parse().unwrap());
        assert!(!fleet.render(Vec::new()).unwrap().contains("address=/.myc/"));
    }

    fn config() -> ResolverConfig {
        ResolverConfig {
            namespace_owners: Default::default(),
            mode: ResolverMode::LocalhostOnly,
            site: "lab".into(),
            suffix: "myc".into(),
            listen: vec!["127.0.0.1:1053".parse().unwrap()],
            upstreams: vec!["1.1.1.1:53".parse().unwrap()],
            service_address: None,
            delegations: vec![],
            blocklists: vec![],
            block_action: BlockAction::default(),
            allowlist: vec![],
            doh: None,
        }
    }
    #[test]
    fn off_is_default_and_has_no_listener_config() {
        assert_eq!(ResolverMode::default(), ResolverMode::Off);
        let mut c = config();
        c.mode = ResolverMode::Off;
        assert_eq!(c.render(vec![]).unwrap(), "");
    }
    #[test]
    fn localhost_only_bootstraps_unknown_capability_names_to_loopback() {
        let c = config();
        let text = c.render(vec![]).unwrap();
        assert!(text.contains("address=/.myc/127.0.0.1\n"));
    }
    #[test]
    fn lan_serving_never_returns_its_own_loopback() {
        let mut c = config();
        c.mode = ResolverMode::LanServing;
        c.listen = vec!["192.0.2.10:1053".parse().unwrap()];
        let text = c.render(vec![]).unwrap();
        assert!(!text.contains("address=/.myc/127.0.0.1"));
    }
    #[test]
    fn explicit_host_record_wins_over_local_anycast_fallback() {
        let c = config();
        let record = DnsRecord {
            name: "neo.lab.myc".into(),
            site: "lab".into(),
            node: "neo".into(),
            address: "192.0.2.20".parse().unwrap(),
        };
        let text = c.render(vec![record]).unwrap();
        assert!(text.contains("address=/.myc/127.0.0.1\n"));
        assert!(text.contains("host-record=neo.lab.myc,192.0.2.20\n"));
    }
    #[test]
    fn doh_owns_the_default_upstream_and_refuses_plaintext() {
        let mut c = config();
        c.upstreams = vec![];
        c.doh = Some(DohUpstream {
            endpoint: "https://dns.example/dns-query".into(),
            listen: "127.0.0.1:5353".parse().unwrap(),
            timeout_seconds: 5,
            max_inflight: 8,
        });
        let text = c.render(vec![]).unwrap();
        assert!(text.contains("server=127.0.0.1#5353\n"));
        assert!(text.contains("no-resolv\n"));
        assert!(!text.contains("server=1.1.1.1"));
        // No silent plaintext path beside it.
        c.upstreams = vec!["1.1.1.1:53".parse().unwrap()];
        assert!(c.render(vec![]).is_err());
        c.upstreams = vec![];
        c.doh.as_mut().unwrap().listen = "127.0.0.1:1053".parse().unwrap();
        assert!(c.render(vec![]).is_err());
    }

    #[test]
    fn localhost_guard_and_split_namespace() {
        let c = config();
        let text = c.render(vec![]).unwrap();
        assert!(text.contains("local=/myc/"));
        assert!(text.contains("no-resolv\n"));
        assert!(!text.contains("dhcp"));
        assert_eq!(c.macos_namespace().unwrap().0, "myc");
        let mut c = c;
        c.listen = vec!["192.0.2.1:53".parse().unwrap()];
        assert!(c.render(vec![]).is_err());
    }
    #[test]
    fn rejects_wildcards_zero_ports_and_recursive_upstreams() {
        for listener in ["0.0.0.0:1053", "[::]:1053", "127.0.0.1:0"] {
            let mut c = config();
            c.listen = vec![listener.parse().unwrap()];
            assert!(c.render(vec![]).is_err());
        }
        let mut c = config();
        c.upstreams = c.listen.clone();
        assert!(c.render(vec![]).is_err());
    }
    #[test]
    fn lan_is_explicit_and_keeps_namespace_ownership() {
        let mut c = config();
        c.mode = ResolverMode::LanServing;
        c.listen.push("192.0.2.1:1053".parse().unwrap());
        assert!(c
            .render(vec![])
            .unwrap()
            .contains("listen-address=192.0.2.1"));
        c.delegations.push(Delegation {
            zone: "myc".into(),
            site: "lab".into(),
            owner: "shroud".into(),
            server: "192.0.2.2".parse().unwrap(),
            port: 53,
        });
        assert!(c.render(vec![]).is_err());
    }
}
