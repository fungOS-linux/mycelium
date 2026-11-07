use serde::{Deserialize, Serialize};
use std::{fmt, fs, path::Path};

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct Route {
    pub name: String,
    #[serde(default)]
    pub hosts: Vec<String>,
    pub upstream: String,
    #[serde(default)]
    pub priority: i32,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct GatewayConfig {
    #[serde(default)]
    pub routes: Vec<Route>,
    #[serde(default)]
    pub default_route: Option<String>,
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
        let mut names = std::collections::HashSet::new();
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
            if !route.upstream.starts_with("http://") && !route.upstream.starts_with("https://") {
                return Err(ConfigError::Validation(format!(
                    "route `{}` upstream must be an http(s) URL",
                    route.name
                )));
            }
            if reqwest::Url::parse(&route.upstream).is_err() {
                return Err(ConfigError::Validation(format!(
                    "route `{}` has an invalid upstream URL",
                    route.name
                )));
            }
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
}
