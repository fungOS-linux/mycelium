use crate::config::Route;

#[derive(Clone, Debug)]
pub struct RouteTable {
    routes: Vec<Route>,
    default: Option<String>,
}

impl RouteTable {
    pub fn new(routes: Vec<Route>, default: Option<String>) -> Self {
        Self { routes, default }
    }

    pub fn select(&self, host: &str) -> Option<Route> {
        let host = normalize_host(host);
        let default = self
            .default
            .as_deref()
            .and_then(|name| self.routes.iter().find(|route| route.name == name).cloned());

        let mut candidates: Vec<Route> = self
            .routes
            .iter()
            .filter(|route| route.hosts.iter().any(|pattern| host_matches(pattern, &host)))
            .cloned()
            .collect();

        candidates.sort_by(|left, right| {
            // Prefer explicit hostnames over wildcard patterns, then priority,
            // then stable name order.
            let specificity = host_specificity(&host, left)
                .cmp(&host_specificity(&host, right));
            specificity
                .then_with(|| right.priority.cmp(&left.priority))
                .then_with(|| left.name.cmp(&right.name))
        });

        candidates.pop().or(default)
    }

    pub fn routes(&self) -> &[Route] {
        &self.routes
    }
}

pub fn normalize_host(value: &str) -> String {
    let value = value.trim();
    let value = value
        .strip_prefix('[')
        .and_then(|inner| inner.strip_suffix(']'))
        .unwrap_or(value);
    value.split_once(':').map_or(value, |(host, _)| host).to_lowercase()
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
        .filter(|pattern| pattern_matches_exactly(pattern, host))
        .count()
}

fn pattern_matches_exactly(pattern: &str, host: &str) -> bool {
    pattern.to_lowercase() == host
}

#[cfg(test)]
mod tests {
    use super::{host_matches, normalize_host, RouteTable};
    use crate::config::Route;

    fn route(name: &str, hosts: &[&str], priority: i32) -> Route {
        Route {
            name: name.into(),
            hosts: hosts.iter().map(|value| (*value).into()).collect(),
            upstream: format!("http://127.0.0.1/{name}"),
            priority,
        }
    }

    #[test]
    fn selects_exact_host() {
        let table = RouteTable::new(
            vec![
                route("default", &["*"], 0),
                route("ai", &["ai.myc"], 10),
            ],
            Some("default".into()),
        );
        assert_eq!(table.select("ai.myc").map(|r| r.name), Some("ai".into()));
    }

    #[test]
    fn strips_port() {
        assert_eq!(normalize_host("Neo.MYC:8080"), "neo.myc");
    }

    #[test]
    fn wildcard_matches_subdomain() {
        assert!(host_matches("*.myc", "ai.myc"));
        assert!(!host_matches("*.myc", "myc"));
    }
}
