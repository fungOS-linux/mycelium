use serde::{Deserialize, Serialize};
use std::{
    fmt, fs,
    path::{Path, PathBuf},
};

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct Route {
    pub name: String,
    #[serde(default)]
    pub hosts: Vec<String>,
    /// Static upstream, normally the local backend. Tried before discovered
    /// services. Omit for a discovery-only route.
    #[serde(default)]
    pub upstream: Option<String>,
    /// Mycelium service kind used for remote candidates, e.g. `ai`.
    #[serde(default)]
    pub service_kind: Option<String>,
    /// Environment variable holding the bearer token for remote candidates.
    /// The caller's local token is never forwarded to a discovered peer.
    #[serde(default)]
    pub remote_token_env: Option<String>,
    #[serde(default)]
    pub priority: i32,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct GatewayConfig {
    #[serde(default)]
    pub routes: Vec<Route>,
    #[serde(default)]
    pub default_route: Option<String>,
    /// Binary used to read `node status` and `services` from myceliumd.
    /// Required when any route uses `service_kind`.
    #[serde(default)]
    pub mycelium_bin: Option<PathBuf>,
    #[serde(default = "default_service_refresh_secs")]
    pub service_refresh_secs: u64,
}

fn default_service_refresh_secs() -> u64 {
    15
}

impl Default for GatewayConfig {
    fn default() -> Self {
        Self {
            routes: Vec::new(),
            default_route: None,
            mycelium_bin: None,
            service_refresh_secs: default_service_refresh_secs(),
        }
    }
}

#[derive(Debug)]
pub enum ConfigError {
    Io(std::io::Error),
    Parse(serde_json::Error),
    Validation(String),
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "read config: {error}"),
            Self::Parse(error) => write!(f, "parse config: {error}"),
            Self::Validation(message) => write!(f, "invalid config: {message}"),
        }
    }
}

impl std::error::Error for ConfigError {}

impl GatewayConfig {
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let bytes = fs::read(path).map_err(ConfigError::Io)?;
        let config = serde_json::from_slice::<Self>(&bytes).map_err(ConfigError::Parse)?;
        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> Result<(), ConfigError> {
        if self.routes.is_empty() {
            return Err(ConfigError::Validation("no routes configured".into()));
        }
        if !(5..=3600).contains(&self.service_refresh_secs) {
            return Err(ConfigError::Validation(
                "service_refresh_secs must be between 5 and 3600".into(),
            ));
        }
        let mut names = std::collections::HashSet::new();
        let mut needs_discovery = false;
        for route in &self.routes {
            if route.name.trim().is_empty() {
                return Err(ConfigError::Validation("route name is empty".into()));
            }
            if !names.insert(route.name.as_str()) {
                return Err(ConfigError::Validation(format!(
                    "duplicate route name `{}`",
                    route.name
                )));
            }
            if route.hosts.is_empty() {
                return Err(ConfigError::Validation(format!(
                    "route `{}` has no hosts",
                    route.name
                )));
            }
            if route.hosts.iter().any(|host| host.trim().is_empty()) {
                return Err(ConfigError::Validation(format!(
                    "route `{}` has an empty host pattern",
                    route.name
                )));
            }
            if route.upstream.is_none() && route.service_kind.is_none() {
                return Err(ConfigError::Validation(format!(
                    "route `{}` needs upstream or service_kind",
                    route.name
                )));
            }
            if let Some(upstream) = &route.upstream {
                if !upstream.starts_with("http://") && !upstream.starts_with("https://") {
                    return Err(ConfigError::Validation(format!(
                        "route `{}` upstream must be an http(s) URL",
                        route.name
                    )));
                }
                if reqwest::Url::parse(upstream).is_err() {
                    return Err(ConfigError::Validation(format!(
                        "route `{}` has an invalid upstream URL",
                        route.name
                    )));
                }
            }
            if let Some(kind) = &route.service_kind {
                if kind.is_empty()
                    || kind.len() > 128
                    || !kind.bytes().all(|byte| {
                        byte.is_ascii_lowercase()
                            || byte.is_ascii_digit()
                            || byte == b'-'
                            || byte == b'_'
                    })
                {
                    return Err(ConfigError::Validation(format!(
                        "route `{}` has an invalid service_kind",
                        route.name
                    )));
                }
                needs_discovery = true;
            }
            if route
                .remote_token_env
                .as_deref()
                .is_some_and(|name| name.trim().is_empty())
            {
                return Err(ConfigError::Validation(format!(
                    "route `{}` has an empty remote_token_env",
                    route.name
                )));
            }
        }
        if needs_discovery && self.mycelium_bin.is_none() {
            return Err(ConfigError::Validation(
                "mycelium_bin is required when a route uses service_kind".into(),
            ));
        }
        if let Some(default) = &self.default_route {
            if !names.contains(default.as_str()) {
                return Err(ConfigError::Validation(format!(
                    "default_route `{default}` does not name a configured route"
                )));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(json: &str) -> GatewayConfig {
        serde_json::from_str(json).unwrap()
    }

    #[test]
    fn config_ignores_unknown_fields() {
        let config = config(
            r#"{
                "routes": [{
                    "name": "default",
                    "hosts": ["*"],
                    "upstream": "http://127.0.0.1:4000"
                }],
                "extra": 1
            }"#,
        );
        assert_eq!(config.routes.len(), 1);
    }

    #[test]
    fn rejects_unknown_default_route() {
        let config = config(
            r#"{
                "routes": [{
                    "name": "default",
                    "hosts": ["*"],
                    "upstream": "http://127.0.0.1:4000"
                }],
                "default_route": "missing"
            }"#,
        );
        assert!(config.validate().is_err());
    }

    #[test]
    fn rejects_non_http_upstream() {
        let config = config(
            r#"{
                "routes": [{
                    "name": "default",
                    "hosts": ["*"],
                    "upstream": "file:///tmp/socket"
                }]
            }"#,
        );
        assert!(config.validate().is_err());
    }

    #[test]
    fn discovery_route_requires_mycelium_bin() {
        let invalid = config(
            r#"{
                "routes": [{
                    "name": "ai",
                    "hosts": ["ai.myc"],
                    "service_kind": "ai"
                }]
            }"#,
        );
        assert!(invalid.validate().is_err());

        let valid = config(
            r#"{
                "mycelium_bin": "/Users/example/.local/bin/mycelium",
                "routes": [{
                    "name": "ai",
                    "hosts": ["ai.myc"],
                    "service_kind": "ai"
                }]
            }"#,
        );
        assert!(valid.validate().is_ok());
    }

    #[test]
    fn route_needs_a_source() {
        let config = config(
            r#"{
                "routes": [{
                    "name": "empty",
                    "hosts": ["empty.myc"]
                }]
            }"#,
        );
        assert!(config.validate().is_err());
    }
}
