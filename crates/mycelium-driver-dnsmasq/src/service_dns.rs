//! DNS aliases from application-owned leases, never scanned listeners or ACLs.
use super::Settings;
use fpl_resource_observation::{ServiceCatalog, SCHEMA_VERSION};
use mycelium_dns_policy::{canonical_domain, DnsRecord};
use std::{
    collections::{BTreeMap, BTreeSet},
    io::Read,
    net::{IpAddr, SocketAddr},
};

/// Explicit local plugin files supply labels, never records or authority.
pub(super) fn aliases(settings: &Settings) -> Result<BTreeMap<String, String>, String> {
    if settings.service_alias_plugins.len() > 8 {
        return Err("too many DNS alias plugins".into());
    }
    let mut result = settings.service_aliases.clone();
    for path in &settings.service_alias_plugins {
        if !path.is_absolute() {
            return Err("DNS alias plugins need absolute paths".into());
        }
        let mut source = String::new();
        std::fs::File::open(path)
            .map_err(|_| "cannot read DNS alias plugin")?
            .take(65537)
            .read_to_string(&mut source)
            .map_err(|_| "cannot decode DNS alias plugin")?;
        let aliases = mycelium_plugins_lua::dns_aliases(
            &source,
            serde_json::json!({
                "site": settings.resolver.site, "suffix": settings.resolver.suffix,
            }),
        )
        .map_err(|e| e.to_string())?;
        for (kind, label) in aliases {
            if result
                .insert(kind, label.clone())
                .is_some_and(|old| old != label)
            {
                return Err("conflicting DNS alias policies".into());
            }
        }
    }
    validate_aliases(&result)?;
    Ok(result)
}

/// Resolve a complete policy snapshot once, before any asynchronous discovery.
/// Publication and retained-state metadata must describe that same snapshot.
pub(super) fn resolved(settings: &Settings) -> Result<Settings, String> {
    let mut resolved = settings.clone();
    resolved.service_aliases = aliases(settings)?;
    resolved.service_alias_plugins.clear();
    Ok(resolved)
}

pub(super) fn validate_aliases(aliases: &BTreeMap<String, String>) -> Result<(), String> {
    if aliases.len() > 32 {
        return Err("too many service aliases".into());
    }
    let mut labels = BTreeSet::new();
    for (kind, label) in aliases {
        if kind.is_empty()
            || kind.len() > 128
            || kind.chars().any(char::is_control)
            || canonical_domain(label)? != *label
            || label.contains('.')
            || !labels.insert(label)
        {
            return Err("service aliases need unique canonical single-label names".into());
        }
    }
    Ok(())
}

/// Restricted literal HTTPS entrance. Names, paths, credentials and queries are
/// not rewritten or resolved; service catalogs retain ports and transport hints.
fn address(endpoint: &str) -> Option<IpAddr> {
    let authority = endpoint.strip_prefix("https://")?.trim_end_matches('/');
    let socket: SocketAddr = authority.parse().ok()?;
    (socket.port() != 0 && socket.port() != 80).then_some(socket.ip())
}

pub(super) fn project(
    settings: &Settings,
    mut records: Vec<DnsRecord>,
    catalog: &ServiceCatalog,
    now: u64,
    mut deadline: u64,
) -> Result<(Vec<DnsRecord>, u64), String> {
    let aliases = aliases(settings)?;
    if catalog.schema_version != SCHEMA_VERSION || catalog.observations.len() > 4096 {
        return Err("unsupported or oversized service DNS catalog".into());
    }
    let hosts = records.clone();
    let mut identities = BTreeSet::new();
    let mut entrances = BTreeMap::new();
    for service in &catalog.observations {
        let Some(label) = aliases.get(&service.value.kind) else {
            continue;
        };
        if service.schema_version != SCHEMA_VERSION
            || !service.is_fresh_at(now)
            || service.expires_at.saturating_sub(service.observed_at) > 300
            || service.provenance.provider != "mycelium-application-owner-lease"
            || service.value.attributes.get("node_id") != Some(&service.provenance.observer)
        {
            continue;
        }
        if !identities.insert(&service.service_id) {
            return Err("duplicate service DNS identity".into());
        }
        for endpoint in &service.value.endpoints {
            let Some(ip) = address(endpoint) else {
                continue;
            };
            for host in hosts
                .iter()
                .filter(|r| r.node == service.provenance.observer && r.address == ip)
            {
                let name = canonical_domain(&format!("{label}.{}", host.name))?;
                // One entrance per name/address: DNS cannot choose a port or URL.
                if entrances
                    .insert((name.clone(), ip), endpoint.clone())
                    .is_some_and(|old| old != *endpoint)
                {
                    return Err("ambiguous service entrance; DNS cannot select ports".into());
                }
                records.push(DnsRecord {
                    name,
                    ..host.clone()
                });
                if settings.service_index_peers.get(&service.value.kind)
                    == Some(&service.provenance.observer)
                {
                    records.push(DnsRecord {
                        name: canonical_domain(&format!("{label}.{}", settings.resolver.suffix))?,
                        ..host.clone()
                    });
                }
                deadline = deadline.min(service.expires_at);
            }
        }
    }
    records.sort();
    records.dedup();
    settings.render(records.clone())?;
    Ok((records, deadline))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    struct PolicyFile(std::path::PathBuf);
    impl PolicyFile {
        fn new(source: &str) -> Self {
            static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
            let path = std::env::temp_dir().join(format!(
                "mycelium-dns-policy-{}-{}.lua",
                std::process::id(),
                NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            ));
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)
                .unwrap();
            use std::io::Write;
            file.write_all(source.as_bytes()).unwrap();
            Self(path)
        }
    }
    impl Drop for PolicyFile {
        fn drop(&mut self) {
            std::fs::remove_file(&self.0).unwrap();
        }
    }
    const UNIBUS: &str = include_str!("../../mycelium-plugins-lua/plugins/unibus_dns.lua");
    #[test]
    fn ipfs_policy_names_only_explicit_owned_gateways_not_rpc() {
        let file = PolicyFile::new(include_str!(
            "../../mycelium-plugins-lua/plugins/ipfs_dns.lua"
        ));
        let mut s = crate::tests::settings();
        s.service_alias_plugins.push(file.0.clone());
        let host = DnsRecord {
            name: "neo.lab.myc".into(),
            address: "192.0.2.12".parse().unwrap(),
            site: "lab".into(),
            node: "neo".into(),
        };
        let mut c = catalog();
        c.observations[0].value.kind = "ipfs".into();
        assert_eq!(
            project(&s, vec![host.clone()], &c, 1000, 1200)
                .unwrap()
                .0
                .len(),
            1
        );
        c.observations[0].value.kind = "ipfs-gateway".into();
        assert!(project(&s, vec![host.clone()], &c, 1000, 1200)
            .unwrap()
            .0
            .iter()
            .any(|r| r.name == "ipfs.neo.lab.myc"));
        c.observations[0].value.endpoints = BTreeSet::from(["https://127.0.0.1:5002".into()]);
        assert_eq!(project(&s, vec![host], &c, 1000, 1200).unwrap().0.len(), 1);
    }
    #[test]
    fn lua_policy_reuses_generic_owner_validation_and_explicit_index() {
        let file = PolicyFile::new(UNIBUS);
        let mut s = crate::tests::settings();
        s.service_alias_plugins.push(file.0.clone());
        s.service_index_peers
            .insert("unibus-viewer".into(), "neo".into());
        s.validate().unwrap();
        let host = DnsRecord {
            name: "neo.lab.myc".into(),
            address: "192.0.2.12".parse().unwrap(),
            site: "lab".into(),
            node: "neo".into(),
        };
        let (records, expiry) = project(&s, vec![host.clone()], &catalog(), 1000, 1200).unwrap();
        assert_eq!(expiry, 1050);
        assert!(records.iter().any(|r| r.name == "unibus.myc"));
        assert!(records.iter().any(|r| r.name == "unibus.neo.lab.myc"));
        let mut stale = catalog();
        stale.observations[0].expires_at = 999;
        assert_eq!(
            project(&s, vec![host], &stale, 1000, 1200).unwrap().0.len(),
            1
        );
    }
    #[test]
    fn invalid_plugins_cannot_bypass_dns_policy() {
        for source in [
            "dns_policy={aliases=function() return {a='bad.name'} end}",
            "dns_policy={aliases=function() return {a='same',b='same'} end}",
            "dns_policy={aliases=function() return {a={ip='192.0.2.1'}} end}",
            "dns_policy={aliases=function() while true do end end}",
            "while true do end",
            "dns_policy={aliases=function() return io.open('/etc/passwd') end}",
        ] {
            let file = PolicyFile::new(source);
            let mut s = crate::tests::settings();
            s.service_alias_plugins.push(file.0.clone());
            assert!(aliases(&s).is_err(), "accepted {source}");
        }
        let file = PolicyFile::new(UNIBUS);
        let mut s = crate::tests::settings();
        s.service_alias_plugins.push(file.0.clone());
        s.service_aliases
            .insert("unibus-viewer".into(), "different".into());
        assert!(aliases(&s).is_err());
        s.service_alias_plugins = vec!["relative.lua".into()];
        assert!(aliases(&s).is_err());
    }
    #[test]
    fn changed_plugin_invalidates_retained_state_and_snapshots_are_consistent() {
        let file = PolicyFile::new(UNIBUS);
        let mut s = crate::tests::settings();
        s.service_alias_plugins.push(file.0.clone());
        let snapshot = resolved(&s).unwrap();
        let retained = super::super::Retained {
            mesh_sites: s.mesh_sites,
            additional_sites: vec![],
            site: "lab".into(),
            suffix: "myc".into(),
            records: vec![],
            expires_at: 1050,
            service_aliases: snapshot.service_aliases.clone(),
            service_index_peers: BTreeMap::new(),
        };
        std::fs::write(&file.0,"dns_policy={aliases=function(ctx) assert(ctx.site=='lab'); return {['unibus-viewer']='bus'} end}").unwrap();
        assert_eq!(aliases(&snapshot).unwrap()["unibus-viewer"], "unibus");
        assert_eq!(aliases(&s).unwrap()["unibus-viewer"], "bus");
        assert!(retained.usable(&s, 1000).is_err());
    }
    fn catalog() -> ServiceCatalog {
        serde_json::from_value(json!({"schema_version":1,"observations":[{
            "schema_version":1,"service_id":"service/neo/unibus/viewer","observed_at":990,"expires_at":1050,
            "provenance":{"provider":"mycelium-application-owner-lease","observer":"neo"},"confidence":"strong",
            "value":{"kind":"unibus-viewer","endpoints":["https://192.0.2.12:8444"],"attributes":{"node_id":"neo"}}
        }]})).unwrap()
    }
    fn run(c: &ServiceCatalog) -> Result<(Vec<DnsRecord>, u64), String> {
        let mut s = crate::tests::settings();
        s.service_aliases
            .insert("unibus-viewer".into(), "unibus".into());
        let hosts = vec![DnsRecord {
            name: "neo.lab.myc".into(),
            address: "192.0.2.12".parse().unwrap(),
            site: "lab".into(),
            node: "neo".into(),
        }];
        project(&s, hosts, c, 1000, 1200)
    }
    #[test]
    fn exact_owner_endpoint_and_expiry() {
        let (records, expiry) = run(&catalog()).unwrap();
        assert_eq!(expiry, 1050);
        assert!(records.iter().any(|r| r.name == "unibus.neo.lab.myc"));
    }
    #[test]
    fn root_index_requires_explicit_owner_and_fresh_matching_lease() {
        let mut settings = crate::tests::settings();
        settings
            .service_aliases
            .insert("unibus-viewer".into(), "unibus".into());
        settings
            .service_index_peers
            .insert("unibus-viewer".into(), "neo".into());
        let hosts = vec![DnsRecord {
            name: "neo.lab.myc".into(),
            address: "192.0.2.12".parse().unwrap(),
            site: "lab".into(),
            node: "neo".into(),
        }];
        let mut services = catalog();
        let (records, _) = project(&settings, hosts.clone(), &services, 1000, 1200).unwrap();
        assert!(records.iter().any(|r| r.name == "unibus.myc"));
        settings
            .service_index_peers
            .insert("unibus-viewer".into(), "other".into());
        assert!(!project(&settings, hosts.clone(), &services, 1000, 1200)
            .unwrap()
            .0
            .iter()
            .any(|r| r.name == "unibus.myc"));
        settings
            .service_index_peers
            .insert("unibus-viewer".into(), "neo".into());
        services.observations[0].expires_at = 999;
        assert_eq!(
            project(&settings, hosts, &services, 1000, 1200)
                .unwrap()
                .0
                .len(),
            1
        );
    }
    #[test]
    fn no_promotion_of_scans_expired_or_other_hosts() {
        for scenario in 0..5 {
            let mut c = catalog();
            let s = &mut c.observations[0];
            match scenario {
                0 => s.provenance.provider = "mycelium-topology".into(),
                1 => s.expires_at = 999,
                2 => s.value.endpoints = BTreeSet::from(["https://127.0.0.1:8444".into()]),
                3 => s.provenance.observer = "other".into(),
                _ => s.value.endpoints = BTreeSet::from(["https://198.51.100.2:8444".into()]),
            }
            assert_eq!(run(&c).unwrap().0.len(), 1);
        }
    }
    #[test]
    fn aliases_and_entrances_fail_closed() {
        assert!(validate_aliases(&BTreeMap::from([("a".into(), "bad.name".into())])).is_err());
        let mut c = catalog();
        c.observations[0]
            .value
            .endpoints
            .insert("https://192.0.2.12:9444".into());
        assert!(run(&c).is_err());
        for url in [
            "http://192.0.2.12:8444",
            "https://user@192.0.2.12:8444",
            "https://neo.lab.myc:8444",
            "https://192.0.2.12:8444/admin",
            "https://192.0.2.12:8444?token=x",
        ] {
            assert!(address(url).is_none());
        }
    }
}
