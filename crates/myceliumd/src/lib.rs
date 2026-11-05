//! mycelium control-plane daemon.
//!
//! Process model: one `myceliumd` per machine owns the inventory (open
//! device handles), driver/plugin registry, and the merged multi-LAN
//! topology. The CLI is a thin client speaking newline-delimited JSON-RPC
//! over a Unix socket — deliberately `curl`/`nc`-able, so every workflow
//! keeps runbook parity (tenet #8) and automation can skip the CLI.
//!
//! State lives in `$MYCELIUM_HOME` (default `~/.mycelium`):
//! - `myceliumd.sock`  JSON-RPC socket
//! - `daemon.pid`      running daemon pid
//! - `devices.json`    saved device configs, reconnected at boot
//! - `topology.json`   last merged topology (facts, re-derivable via scan)
//! - `plugins/*.lua`   Lua plugin drivers, validated at boot
//! - `recognizers/*.lua` pure advertisement recognizers, validated at boot
//!
//! Secrets never persist: `CredentialSet` round-trips `Secret::Env`, so
//! `devices.json` stores variable names, not values.

pub mod authority;
pub mod client;
pub mod credential_map;
pub mod credential_provider;
mod execution;
mod hardware;
pub mod peer;
#[cfg(feature = "iroh-sync")]
pub use iroh as iroh_transport;
pub mod node_profile;
pub mod protocol;
#[cfg(feature = "iroh-sync")]
pub mod proxy;
pub mod resources;
pub mod rpc;
mod security;
mod service_env;
pub mod service;
pub mod services;
pub mod local_services;
pub mod siem;
pub mod software;
pub mod software_apt;
pub mod software_service;
pub mod ssh_health;
pub mod ssh_renewal;
pub mod state_change;
pub mod topology_feed;
pub mod update_policy;

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct UpdateState {
    pub release_version: Option<String>,
    pub release_digest: Option<String>,
    pub release_target: Option<String>,
    pub activation_state: String,
    pub activated_at: Option<u64>,
    pub last_error: Option<String>,
    #[serde(default)]
    pub staged_digest: Option<String>,
    #[serde(default)]
    pub staged_since: Option<u64>,
    #[serde(default)]
    pub last_attempt_at: Option<u64>,
}

/// Resolve the state dir. Inferred, not configured, unless overridden.
pub fn home_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("MYCELIUM_HOME") {
        return PathBuf::from(dir);
    }
    let home = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .unwrap_or_else(|_| ".".into());
    PathBuf::from(home).join(".mycelium")
}

pub fn socket_path() -> PathBuf {
    if let Ok(p) = std::env::var("MYCELIUM_SOCKET") {
        return PathBuf::from(p);
    }
    home_dir().join("myceliumd.sock")
}

pub fn pid_path() -> PathBuf {
    home_dir().join("daemon.pid")
}

pub fn devices_path() -> PathBuf {
    home_dir().join("devices.json")
}

pub fn credential_map_path() -> PathBuf {
    home_dir().join("credential-map.json")
}

pub(crate) fn load_service_env() -> std::io::Result<()> {
    let home = home_dir();
    service_env::load_missing(&home.join("node.env"))?;
    service_env::load_missing(&home.join("credentials.env"))
}

pub fn topology_path() -> PathBuf {
    home_dir().join("topology.json")
}

pub fn topology_feed_path() -> PathBuf {
    home_dir().join("topology-feed.json")
}

pub fn discovery_path() -> PathBuf {
    home_dir().join("discovery.json")
}

pub fn recognizers_dir() -> PathBuf {
    home_dir().join("recognizers")
}

pub fn allocations_path() -> PathBuf {
    home_dir().join("allocations.json")
}

pub fn networks_path() -> PathBuf {
    home_dir().join("networks.json")
}

pub fn network_bindings_path() -> PathBuf {
    home_dir().join("network-bindings.json")
}

pub fn dhcp_scopes_path() -> PathBuf {
    home_dir().join("dhcp-scopes.json")
}

pub fn siem_dir() -> PathBuf {
    home_dir().join("security").join("siem")
}

pub fn execution_receipts_dir() -> PathBuf {
    home_dir().join("executions")
}

pub fn peer_key_path() -> PathBuf {
    home_dir().join("peer.key")
}

pub fn peer_observations_path() -> PathBuf {
    home_dir().join("peer-observations.json")
}

pub fn artifacts_dir() -> PathBuf {
    home_dir().join("artifacts")
}

pub fn software_dir() -> PathBuf {
    home_dir().join("software")
}

pub fn software_policy_path() -> PathBuf {
    home_dir().join("software-policy.json")
}

pub fn software_state_path() -> PathBuf {
    home_dir().join("software-state.json")
}
pub fn software_automatic_state_path() -> PathBuf {
    home_dir().join("software-automatic-state.json")
}

pub fn update_state_path() -> PathBuf {
    home_dir().join("update-state.json")
}

pub fn update_policy_path() -> PathBuf {
    home_dir().join("update-policy.json")
}

pub fn read_update_policy() -> update_policy::UpdatePolicy {
    std::fs::read(update_policy_path())
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .unwrap_or_default()
}

pub fn write_update_policy(policy: &update_policy::UpdatePolicy) -> std::io::Result<()> {
    let path = update_policy_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let temporary = path.with_extension("json.tmp");
    std::fs::write(
        &temporary,
        serde_json::to_vec_pretty(policy).map_err(std::io::Error::other)?,
    )?;
    std::fs::rename(temporary, path)
}

pub fn wireguard_dir() -> PathBuf {
    home_dir().join("wireguard")
}

pub fn wireguard_private_key_path() -> PathBuf {
    wireguard_dir().join("private.key")
}

pub fn read_update_state() -> UpdateState {
    std::fs::read(update_state_path())
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .unwrap_or_default()
}

pub fn write_update_state(state: &UpdateState) -> std::io::Result<()> {
    let path = update_state_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let temporary = path.with_extension("json.tmp");
    let bytes = serde_json::to_vec_pretty(state).map_err(std::io::Error::other)?;
    std::fs::write(&temporary, bytes)?;
    std::fs::rename(temporary, path)
}

pub fn plugins_dir() -> PathBuf {
    home_dir().join("plugins")
}

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
