use crate::config::Route;
use crate::discovery::ServiceIndex;

/// Configured routes plus the ones the service catalog implies.
///
/// A configured route always owns its hostnames: a derived name only fills what
/// nothing in the file already claims. That keeps `routes.json` as the override
/// for the odd case (a public fallback upstream, a per-route token) without
/// making every node keep a hand-edited copy of the fleet's name table.
#[derive(Clone, Debug)]
pub struct RouteTable {
    routes: Vec<Route>,
    derived: Vec<Route>,
    default: Option<String>,
}

impl RouteTable {
    pub fn new(routes: Vec<Route>, default: Option<String>) -> Self {
        Self {
            routes,
            derived: Vec::new(),
            default,
        }
    }

    /// Replace the catalog-derived routes with what `index` claims now. An
    /// empty or stale catalog withdraws the names it used to carry.
    pub fn set_discovered(&mut self, index: &ServiceIndex) {
        self.derived = derive(&self.routes, index);
    }

    pub fn derived_routes(&self) -> usize {
        self.derived.len()
    }

    pub fn total_routes(&self) -> usize {
        self.routes.len() + self.derived.len()
    }

    fn all(&self) -> impl Iterator<Item = &Route> {
        self.routes.iter().chain(self.derived.iter())
    }

    pub fn select(&self, host: &str) -> Option<Route> {
        let host = normalize_host(host);
        let default = self
            .default
            .as_deref()
            .and_then(|name| self.routes.iter().find(|route| route.name == name).cloned());

        let mut candidates: Vec<Route> = self
            .all()
            .filter(|route| {
                route
                    .hosts
                    .iter()
                    .any(|pattern| host_matches(pattern, &host))
            })
            .cloned()
            .collect();

        candidates.sort_by(|left, right| {
            // Prefer an exact hostname over a wildcard, then priority, then a
            // stable name order so reloads cannot reshuffle equal routes.
            host_specificity(&host, left)
                .cmp(&host_specificity(&host, right))
                .then_with(|| right.priority.cmp(&left.priority))
                .then_with(|| left.name.cmp(&right.name))
        });

        candidates.pop().or(default)
    }

    pub fn routes(&self) -> &[Route] {
        &self.routes
    }
}

/// A name becomes a route only while a fresh lease claims it and no configured
/// route already answers for it.
fn derive(configured: &[Route], index: &ServiceIndex) -> Vec<Route> {
    index
        .hosts()
        .iter()
        .filter(|(host, _)| {
            !configured.iter().any(|route| {
                route
                    .hosts
                    .iter()
                    .any(|pattern| host_matches(pattern, host))
            })
        })
        .map(|(host, kind)| Route {
            name: format!("catalog:{kind}"),
            hosts: vec![host.clone()],
            upstreams: Vec::new(),
            service_kind: Some(kind.clone()),
            remote_token_env: None,
            remote_token_file: None,
            priority: 0,
        })
        .collect()
}

pub fn normalize_host(value: &str) -> String {
    let value = value.trim().trim_end_matches('.');
    let value = if let Some(inner) = value.strip_prefix('[') {
        inner.split_once(']').map_or(inner, |(host, _)| host)
    } else if value.matches(':').count() == 1 {
        value.split_once(':').map_or(value, |(host, _)| host)
    } else {
        value
    };
    value.to_lowercase()
}

fn host_matches(pattern: &str, host: &str) -> bool {
    let pattern = pattern.to_lowercase();
    if pattern == "*" {
        return true;
    }
    if let Some(suffix) = pattern.strip_prefix("*.") {
        let dotted = format!(".{suffix}");
        return host.len() > dotted.len()
            && host.ends_with(&dotted)
            && host[..host.len() - dotted.len()].contains(char::is_alphanumeric);
    }
    pattern == host
}

fn host_specificity(host: &str, route: &Route) -> usize {
    route
        .hosts
        .iter()
        .filter(|pattern| pattern.eq_ignore_ascii_case(host))
        .count()
}

#[cfg(test)]
mod tests {
    use super::{host_matches, normalize_host, RouteTable, ServiceIndex};
    use crate::config::Route;

    fn route(name: &str, hosts: &[&str], priority: i32) -> Route {
        Route {
            name: name.into(),
            hosts: hosts.iter().map(|value| (*value).into()).collect(),
            upstreams: vec![format!("http://127.0.0.1/{name}")],
            service_kind: None,
            remote_token_env: None,
            remote_token_file: None,
            priority,
        }
    }

    #[test]
    fn selects_exact_host() {
        let table = RouteTable::new(
            vec![route("default", &["*"], 0), route("ai", &["ai.myc"], 10)],
            Some("default".into()),
        );
        assert_eq!(table.select("ai.myc").map(|r| r.name), Some("ai".into()));
    }

    #[test]
    fn strips_port_and_trailing_dot() {
        assert_eq!(normalize_host("Neo.MYC:8080"), "neo.myc");
        assert_eq!(normalize_host("ai.myc."), "ai.myc");
        assert_eq!(normalize_host("[::1]:8080"), "::1");
    }

    #[test]
    fn wildcard_matches_subdomain() {
        assert!(host_matches("*.myc", "ai.myc"));
        assert!(!host_matches("*.myc", "myc"));
        assert!(!host_matches("*.myc", ".myc"));
    }

    #[test]
    fn exact_host_beats_wildcard_even_without_priority() {
        let table = RouteTable::new(
            vec![
                route("wildcard", &["*.myc"], 100),
                route("exact", &["ai.myc"], 0),
            ],
            None,
        );
        assert_eq!(table.select("ai.myc").map(|r| r.name), Some("exact".into()));
    }

    fn index_with(entries: &[(&str, &str)]) -> ServiceIndex {
        // (expected name, kind): the label is the name minus the `.myc` suffix,
        // exactly as the resolver would publish it.
        let naming = mycelium_dns_policy::settings::Naming {
            service_aliases: entries
                .iter()
                .map(|(host, kind)| {
                    let label = host.trim_end_matches(".myc").to_owned();
                    ((*kind).to_owned(), label)
                })
                .collect(),
            ..Default::default()
        };
        let observations = entries
            .iter()
            .enumerate()
            .map(|(i, (_, kind))| {
                serde_json::json!({
                    "schema_version": 1,
                    "service_id": format!("service/test/{i}"),
                    "observed_at": 100,
                    "expires_at": 300,
                    "provenance": {"provider": "mycelium-application-owner-lease", "observer": "host"},
                    "confidence": "strong",
                    "value": {
                        "kind": kind,
                        "endpoints": ["https://127.0.0.1:9000"],
                        "attributes": {"node_id": "host"}
                    }
                })
            })
            .collect::<Vec<_>>();
        let catalog = serde_json::json!({"schema_version": 1, "observations": observations});
        ServiceIndex::from_catalog("host", &catalog, 100, &naming).unwrap()
    }

    #[test]
    fn derived_routes_fill_only_unclaimed_names() {
        let mut table = RouteTable::new(vec![route("ai", &["ai.myc"], 10)], None);
        table.set_discovered(&index_with(&[("files.myc", "files"), ("ai.myc", "ai")]));
        assert_eq!(table.derived_routes(), 1);
        assert_eq!(table.total_routes(), 2);
        let selected = table.select("files.myc").expect("derived route");
        assert_eq!(selected.service_kind.as_deref(), Some("files"));
        assert!(selected.upstreams.is_empty());
        assert_eq!(table.select("ai.myc").map(|r| r.name), Some("ai".into()));
    }

    #[test]
    fn a_configured_wildcard_owns_its_namespace() {
        let mut table = RouteTable::new(vec![route("wild", &["*.myc"], 0)], None);
        table.set_discovered(&index_with(&[("files.myc", "files")]));
        assert_eq!(table.derived_routes(), 0);
    }

    #[test]
    fn a_withdrawn_name_stops_routing() {
        let mut table = RouteTable::new(Vec::new(), None);
        table.set_discovered(&index_with(&[("files.myc", "files")]));
        assert_eq!(table.derived_routes(), 1);
        table.set_discovered(&ServiceIndex::default());
        assert_eq!(table.derived_routes(), 0);
        assert!(table.select("files.myc").is_none());
    }
}
