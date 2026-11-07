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
    #[serde(default)]
    pub required_token_file: Option<PathBuf>,
    #[serde(default)]
    pub tls_cert: Option<PathBuf>,
    #[serde(default)]
    pub tls_key: Option<PathBuf>,
}

#[derive(Debug)]
pub enum ConfigError {
    Io(std::io::Error),
    Parse(serde_json::Error),
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "read config: {error}"),
            Self::Parse(error) => write!(f, "parse config: {error}"),
        }
    }
}

impl std::error::Error for ConfigError {}

impl GatewayConfig {
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let bytes = fs::read(path).map_err(ConfigError::Io)?;
        serde_json::from_slice(&bytes).map_err(ConfigError::Parse)
    }

    pub fn default_token(&self) -> Option<String> {
        self.required_token_file.as_ref().and_then(|path| {
            fs::read_to_string(path)
                .ok()
                .map(|value| value.trim().to_owned())
                .filter(|value| !value.is_empty())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_ignores_unknown_fields() {
        let config = serde_json::from_str::<GatewayConfig>(
            r#"{
                "routes": [],
                "extra": 1
            }"#,
        );
        assert!(config.is_ok());
    }
}
