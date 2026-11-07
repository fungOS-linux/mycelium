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
}
