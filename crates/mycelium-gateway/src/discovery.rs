use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::process::Command;

const MAX_OUTPUT_BYTES: usize = 16 * 1024 * 1024;
const COMMAND_TIMEOUT: Duration = Duration::from_secs(10);

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
}

impl ServiceIndex {
    pub fn local_node(&self) -> Option<&str> {
        self.local_node.as_deref()
    }

    pub fn candidates(&self, kind: &str) -> &[Candidate] {
        self.by_kind.get(kind).map(Vec::as_slice).unwrap_or(&[])
    }

    pub fn len(&self) -> usize {
        self.by_kind.values().map(Vec::len).sum()
    }

    /// Read the local node identity and the authenticated service catalog from
    /// the running myceliumd. This is intentionally the same CLI surface the
    /// DNS resolver uses, so the gateway and resolver see one catalog.
    pub async fn load(bin: &Path) -> Result<Self, String> {
        let status = run_json(bin, &["node", "status", "--json"]).await?;
        let local_node = status
            .pointer("/node/hello/node_id")
            .and_then(serde_json::Value::as_str)
            .filter(|node| !node.is_empty())
            .ok_or("mycelium node status has no node_id")?
            .to_owned();
        let catalog = run_json(bin, &["services", "--json"]).await?;
        Self::from_catalog(&local_node, &catalog, now())
    }

    fn from_catalog(
        local_node: &str,
        catalog: &serde_json::Value,
        now: u64,
    ) -> Result<Self, String> {
        let observations = catalog
            .get("observations")
            .and_then(serde_json::Value::as_array)
            .ok_or("service catalog has no observations")?;
        let mut by_kind: BTreeMap<String, Vec<Candidate>> = BTreeMap::new();
        let mut seen: BTreeSet<(String, String)> = BTreeSet::new();
        for observation in observations {
            let Some(service) = observation.get("value") else {
                continue;
            };
            let Some(kind) = service.get("kind").and_then(serde_json::Value::as_str) else {
                continue;
            };
            if kind.is_empty() {
                continue;
            }
            let expires_at = observation
                .get("expires_at")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0);
            if expires_at <= now {
                continue;
            }
            let observer = observation
                .pointer("/provenance/observer")
                .and_then(serde_json::Value::as_str);
            let node = service
                .pointer("/attributes/node_id")
                .and_then(serde_json::Value::as_str)
                .or(observer);
            let local = node == Some(local_node) || observer == Some(local_node);
            let Some(endpoints) = service
                .get("endpoints")
                .and_then(serde_json::Value::as_array)
            else {
                continue;
            };
            for endpoint in endpoints {
                let Some(endpoint) = endpoint.as_str() else {
                    continue;
                };
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
                    expires_at,
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
        })
    }
}

fn is_loopback(url: &reqwest::Url) -> bool {
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
    use serde_json::json;

    fn catalog() -> serde_json::Value {
        json!({
            "observations": [
                {
                    "expires_at": 200,
                    "provenance": {"observer": "local-node"},
                    "value": {
                        "kind": "ai",
                        "endpoints": ["http://127.0.0.1:4001"],
                        "attributes": {"node_id": "local-node"}
                    }
                },
                {
                    "expires_at": 200,
                    "provenance": {"observer": "remote-node"},
                    "value": {
                        "kind": "ai",
                        "endpoints": ["http://10.253.0.9:4001", "http://127.0.0.1:4001"],
                        "attributes": {"node_id": "remote-node"}
                    }
                },
                {
                    "expires_at": 100,
                    "provenance": {"observer": "local-node"},
                    "value": {
                        "kind": "ai",
                        "endpoints": ["http://127.0.0.1:4999"],
                        "attributes": {"node_id": "local-node"}
                    }
                }
            ]
        })
    }

    #[test]
    fn keeps_local_loopback_and_drops_remote_loopback() {
        let index = ServiceIndex::from_catalog("local-node", &catalog(), 150).unwrap();
        let candidates = index.candidates("ai");
        assert_eq!(candidates.len(), 2);
        assert!(candidates[0].local);
        assert_eq!(candidates[0].url.as_str(), "http://127.0.0.1:4001/");
        assert!(!candidates[1].local);
        assert_eq!(candidates[1].url.as_str(), "http://10.253.0.9:4001/");
    }

    #[test]
    fn expires_stale_leases() {
        let index = ServiceIndex::from_catalog("local-node", &catalog(), 201).unwrap();
        assert!(index.candidates("ai").is_empty());
    }
}
