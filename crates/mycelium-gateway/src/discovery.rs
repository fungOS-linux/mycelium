use fpl_resource_observation::ServiceCatalog;
use mycelium_dns_policy::service_names::claimed_services;
use mycelium_dns_policy::settings::Naming;
use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::process::Command;

const MAX_OUTPUT_BYTES: usize = 16 * 1024 * 1024;
/// A cold catalog takes about ten seconds while the daemon merges peer
/// topology, so the bound has to clear that without trusting a hung call.
const COMMAND_TIMEOUT: Duration = Duration::from_secs(25);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Candidate {
    pub url: reqwest::Url,
    pub local: bool,
    pub node: Option<String>,
    pub expires_at: u64,
}

#[derive(Clone, Debug, Default)]
pub struct ServiceIndex {
    local_node: Option<String>,
    by_kind: BTreeMap<String, Vec<Candidate>>,
    /// Names claimed by a fresh lease, mapped to the service kind that answers
    /// them. This is the host table the gateway derives instead of asking every
    /// node to keep a hand-edited route file.
    hosts: BTreeMap<String, String>,
}

impl ServiceIndex {
    pub fn local_node(&self) -> Option<&str> {
        self.local_node.as_deref()
    }

    pub fn candidates(&self, kind: &str) -> &[Candidate] {
        self.by_kind.get(kind).map(Vec::as_slice).unwrap_or(&[])
    }

    pub fn hosts(&self) -> &BTreeMap<String, String> {
        &self.hosts
    }

    pub fn len(&self) -> usize {
        self.by_kind.values().map(Vec::len).sum()
    }

    /// Read the local node identity and the authenticated service catalog from
    /// the running myceliumd. This is intentionally the same CLI surface the
    /// DNS resolver uses, so the gateway and resolver see one catalog.
    pub async fn load(bin: &Path, naming: &Naming) -> Result<Self, String> {
        let status = run_json(bin, &["node", "status", "--json"]).await?;
        let local_node = status
            .pointer("/node/hello/node_id")
            .and_then(serde_json::Value::as_str)
            .filter(|node| !node.is_empty())
            .ok_or("mycelium node status has no node_id")?
            .to_owned();
        let catalog = run_json(bin, &["services", "--json"]).await?;
        Self::from_catalog(&local_node, &catalog, now(), naming)
    }

    /// Build the index from one catalog. Names come from the shared rule in
    /// `mycelium-dns-policy`, so a route can never answer to a name the resolver
    /// would not publish.
    pub(crate) fn from_catalog(
        local_node: &str,
        catalog: &serde_json::Value,
        now: u64,
        naming: &Naming,
    ) -> Result<Self, String> {
        let catalog = serde_json::from_value::<ServiceCatalog>(catalog.clone())
            .map_err(|error| format!("bad service catalog: {error}"))?;
        let mut hosts = BTreeMap::new();
        for claim in claimed_services(&naming.service_aliases, &catalog, now)? {
            hosts.insert(format!("{}.{}", claim.label, naming.suffix), claim.kind);
        }
        let mut by_kind: BTreeMap<String, Vec<Candidate>> = BTreeMap::new();
        let mut seen: BTreeSet<(String, String)> = BTreeSet::new();
        for observation in &catalog.observations {
            let kind = observation.value.kind.as_str();
            if kind.is_empty() || observation.expires_at <= now {
                continue;
            }
            let observer = Some(observation.provenance.observer.as_str());
            let node = observation
                .value
                .attributes
                .get("node_id")
                .map(String::as_str)
                .or(observer);
            let local = node == Some(local_node) || observer == Some(local_node);
            for endpoint in &observation.value.endpoints {
                let Ok(url) = reqwest::Url::parse(endpoint) else {
                    continue;
                };
                if !matches!(url.scheme(), "http" | "https")
                    || url.username() != ""
                    || url.password().is_some()
                    || url.host_str().is_none()
                {
                    continue;
                }
                // A remote lease may expose its loopback hint, but that address
                // belongs to the remote node. Only the local owner may use it.
                if !local && is_loopback(&url) {
                    continue;
                }
                let key = (kind.to_owned(), url.to_string());
                if !seen.insert(key) {
                    continue;
                }
                by_kind.entry(kind.to_owned()).or_default().push(Candidate {
                    url,
                    local,
                    node: node.map(str::to_owned),
                    expires_at: observation.expires_at,
                });
            }
        }
        for candidates in by_kind.values_mut() {
            // Local endpoints first, then a stable URL order. The resolver does
            // not choose ports; the gateway only reorders explicit hints.
            candidates.sort_by(|left, right| {
                right
                    .local
                    .cmp(&left.local)
                    .then_with(|| left.url.as_str().cmp(right.url.as_str()))
            });
        }
        Ok(Self {
            local_node: Some(local_node.to_owned()),
            by_kind,
            hosts,
        })
    }
}

pub(crate) fn is_loopback(url: &reqwest::Url) -> bool {
    url.host_str().is_some_and(|host| {
        host.eq_ignore_ascii_case("localhost")
            || host
                .parse::<IpAddr>()
                .is_ok_and(|address| address.is_loopback())
    })
}

async fn run_json(bin: &Path, args: &[&str]) -> Result<serde_json::Value, String> {
    let mut command = Command::new(bin);
    command.args(args).kill_on_drop(true);
    let output = tokio::time::timeout(COMMAND_TIMEOUT, command.output())
        .await
        .map_err(|_| format!("{} timed out", bin.display()))?
        .map_err(|error| format!("run {}: {error}", bin.display()))?;
    if !output.status.success() {
        return Err(format!(
            "{} {} exited {}",
            bin.display(),
            args.join(" "),
            output.status
        ));
    }
    if output.stdout.len() > MAX_OUTPUT_BYTES {
        return Err(format!("{} output exceeded bound", bin.display()));
    }
    serde_json::from_slice(&output.stdout)
        .map_err(|error| format!("parse {} output: {error}", bin.display()))
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::ServiceIndex;
    use mycelium_dns_policy::settings::Naming;
    use serde_json::json;
    use std::collections::BTreeMap;

    fn observation(
        id: &str,
        provider: &str,
        observer: &str,
        node: &str,
        expires_at: u64,
        endpoints: serde_json::Value,
    ) -> serde_json::Value {
        json!({
            "schema_version": 1,
            "service_id": format!("service/{id}"),
            "observed_at": 100,
            "expires_at": expires_at,
            "provenance": {"provider": provider, "observer": observer},
            "confidence": "strong",
            "value": {
                "kind": "ai",
                "endpoints": endpoints,
                "attributes": {"node_id": node}
            }
        })
    }

    fn catalog() -> serde_json::Value {
        json!({
            "schema_version": 1,
            "observations": [
                observation(
                    "local",
                    "mdns",
                    "local-node",
                    "local-node",
                    200,
                    json!(["http://127.0.0.1:4001"]),
                ),
                observation(
                    "remote",
                    "mdns",
                    "remote-node",
                    "remote-node",
                    200,
                    json!(["http://10.253.0.9:4001", "http://127.0.0.1:4001"]),
                ),
                observation(
                    "stale",
                    "mdns",
                    "local-node",
                    "local-node",
                    100,
                    json!(["http://127.0.0.1:4999"]),
                ),
            ]
        })
    }

    fn naming() -> Naming {
        Naming {
            service_aliases: BTreeMap::from([("ai".to_owned(), "ai".to_owned())]),
            ..Naming::default()
        }
    }

    #[test]
    fn keeps_local_loopback_and_drops_remote_loopback() {
        let index =
            ServiceIndex::from_catalog("local-node", &catalog(), 150, &Naming::default()).unwrap();
        let candidates = index.candidates("ai");
        assert_eq!(candidates.len(), 2);
        assert!(candidates[0].local);
        assert_eq!(candidates[0].url.as_str(), "http://127.0.0.1:4001/");
        assert!(!candidates[1].local);
        assert_eq!(candidates[1].url.as_str(), "http://10.253.0.9:4001/");
    }

    #[test]
    fn expires_stale_leases() {
        let index =
            ServiceIndex::from_catalog("local-node", &catalog(), 201, &Naming::default()).unwrap();
        assert!(index.candidates("ai").is_empty());
    }

    #[test]
    fn a_name_needs_an_application_lease_and_a_zone_label() {
        let application = json!({
            "schema_version": 1,
            "observations": [observation(
                "local",
                "mycelium-application-owner-lease",
                "local-node",
                "local-node",
                200,
                json!(["http://127.0.0.1:4001"]),
            )]
        });
        let index = ServiceIndex::from_catalog("local-node", &application, 150, &naming()).unwrap();
        assert_eq!(index.hosts().get("ai.myc").map(String::as_str), Some("ai"));

        // The same lease without an opted-in label, and a scanned listener with
        // one, are both nameless.
        let unlabelled =
            ServiceIndex::from_catalog("local-node", &application, 150, &Naming::default())
                .unwrap();
        assert!(unlabelled.hosts().is_empty());
        let scanned = ServiceIndex::from_catalog("local-node", &catalog(), 150, &naming()).unwrap();
        assert!(scanned.hosts().is_empty());
    }

    #[test]
    fn a_catalog_that_is_not_the_service_contract_is_rejected() {
        assert!(ServiceIndex::from_catalog(
            "local-node",
            &json!({"observations": [{"expires_at": 200}]}),
            100,
            &Naming::default(),
        )
        .is_err());
    }
}
