//! Resolver settings are a contract, not a path each consumer rediscovers.
//!
//! The dnsmasq driver writes this file after every successful apply; anything
//! that needs the machine's installed policy reads it from here. The location and
//! the fields consumers act on live in one place so the writer and its readers
//! cannot drift apart.

use serde::Deserialize;
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

/// Written by the resolver driver after every successful apply.
pub const ACTIVE_SETTINGS_FILE: &str = "active-settings.json";

/// `directory` is the mycelium DNS directory, normally `~/.mycelium/dns`.
pub fn active_settings_path(directory: &Path) -> PathBuf {
    directory.join(ACTIVE_SETTINGS_FILE)
}

/// The policy an apply left behind. Only the fields consumers act on are
/// projected out of the driver's larger settings document: which names the zone
/// answers, in which namespace, and for which address scopes.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(from = "Raw")]
pub struct Policy {
    /// Opt-in `service kind -> DNS label`.
    pub service_aliases: BTreeMap<String, String>,
    /// Index owner per kind. Not every reader uses this yet; it belongs to the
    /// same opt-in table, so it is read once, here.
    pub service_index_peers: BTreeMap<String, String>,
    /// The scopes the resolver publishes host records for. Readers that preview
    /// the zone must apply the same scopes the resolver applies, or the preview
    /// and the live answer disagree about which address a name has.
    pub reachable_prefixes: Vec<String>,
    /// Which sites' peers become records. A preview has to admit the same peers.
    pub mesh_sites: bool,
    pub additional_sites: Vec<String>,
    /// The freshness bound on peer observations, in seconds.
    pub expiry_seconds: u64,
    /// Subtrees owned by another resolver; names under them are never published.
    pub delegations: Vec<crate::Delegation>,
    pub suffix: String,
    pub site: String,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            service_aliases: BTreeMap::new(),
            service_index_peers: BTreeMap::new(),
            reachable_prefixes: Vec::new(),
            mesh_sites: false,
            additional_sites: Vec::new(),
            expiry_seconds: 300,
            delegations: Vec::new(),
            suffix: "myc".to_owned(),
            site: String::new(),
        }
    }
}

/// No file means this host runs no resolver, which is a normal state.
pub fn load_active(directory: &Path) -> Result<Option<Policy>, String> {
    let path = active_settings_path(directory);
    let bytes = match fs::read(&path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(format!("read {}: {error}", path.display())),
    };
    let naming = serde_json::from_slice::<Policy>(&bytes)
        .map_err(|error| format!("parse {}: {error}", path.display()))?;
    if !crate::service_names::valid_label(&naming.suffix) {
        return Err(format!(
            "{}: suffix is not a single DNS label",
            path.display()
        ));
    }
    if naming.service_aliases.len() > 32
        || naming
            .service_aliases
            .values()
            .any(|label| !crate::service_names::valid_label(label))
    {
        return Err(format!(
            "{}: service aliases are not single DNS labels",
            path.display()
        ));
    }
    Ok(Some(naming))
}

#[derive(Deserialize)]
struct Raw {
    #[serde(default)]
    service_aliases: BTreeMap<String, String>,
    #[serde(default)]
    service_index_peers: BTreeMap<String, String>,
    #[serde(default)]
    reachable_prefixes: Vec<String>,
    #[serde(default)]
    mesh_sites: bool,
    #[serde(default)]
    additional_sites: Vec<String>,
    #[serde(default = "default_expiry")]
    expiry_seconds: u64,
    #[serde(default)]
    resolver: RawResolver,
}

fn default_expiry() -> u64 {
    300
}

#[derive(Default, Deserialize)]
struct RawResolver {
    #[serde(default)]
    suffix: String,
    #[serde(default)]
    site: String,
    #[serde(default)]
    delegations: Vec<crate::Delegation>,
}

impl From<Raw> for Policy {
    fn from(raw: Raw) -> Self {
        Self {
            service_aliases: raw.service_aliases,
            service_index_peers: raw.service_index_peers,
            reachable_prefixes: raw.reachable_prefixes,
            mesh_sites: raw.mesh_sites,
            additional_sites: raw.additional_sites,
            expiry_seconds: raw.expiry_seconds,
            delegations: raw.resolver.delegations,
            suffix: raw.resolver.suffix,
            site: raw.resolver.site,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(dir: &Path, body: serde_json::Value) {
        fs::write(active_settings_path(dir), body.to_string()).unwrap();
    }

    #[test]
    fn an_installed_resolver_yields_its_naming_policy() {
        let dir = tempdir();
        write(
            &dir,
            serde_json::json!({
                "resolver": {"suffix": "myc", "site": "wagar-house", "listen": []},
                "dnsmasq": "/usr/bin/dnsmasq",
                "reachable_prefixes": ["192.168.10.0/24"],
                "service_aliases": {"files": "files"},
                "service_index_peers": {"files": "n1"}
            }),
        );
        let naming = load_active(&dir).unwrap().unwrap();
        assert_eq!(
            naming.service_aliases.get("files").map(String::as_str),
            Some("files")
        );
        assert_eq!(
            naming.service_index_peers.get("files").map(String::as_str),
            Some("n1")
        );
        assert_eq!(naming.suffix, "myc");
        assert_eq!(naming.site, "wagar-house");
        assert_eq!(
            naming.reachable_prefixes,
            vec!["192.168.10.0/24".to_owned()]
        );
    }

    #[test]
    fn no_resolver_is_not_an_error() {
        assert!(load_active(&tempdir()).unwrap().is_none());
    }

    #[test]
    fn a_suffix_that_is_not_one_label_is_rejected_rather_than_renaming_the_zone() {
        let dir = tempdir();
        write(
            &dir,
            serde_json::json!({"resolver": {"suffix": "myc.example"}}),
        );
        assert!(load_active(&dir).is_err());
        write(&dir, serde_json::json!({"resolver": {"suffix": ""}}));
        assert!(load_active(&dir).is_err());
    }

    #[test]
    fn an_alias_that_is_not_one_label_is_rejected() {
        let dir = tempdir();
        write(
            &dir,
            serde_json::json!({
                "resolver": {"suffix": "myc"},
                "service_aliases": {"files": "Files"}
            }),
        );
        assert!(load_active(&dir).is_err());
    }

    fn tempdir() -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "mycelium-settings-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }
}
