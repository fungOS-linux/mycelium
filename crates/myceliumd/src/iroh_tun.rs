//! The daemon owns the L3 tunnel.
//!
//! Registration is a daemon responsibility, not a client one. The catalog and
//! the observation lease are both daemon state: a client that registers itself
//! leaves a stale observation until its TTL when it crashes, and the node then
//! looks alive while routing nowhere. Here the daemon keeps the key, spawns
//! `iroh-tun`, restarts it, and publishes an observation that expires on its own
//! if this process stops renewing it.
//!
//! The split is deliberate:
//! - the daemon owns what this node *claims* (identity, overlay prefixes),
//!   because claims are catalog facts;
//! - the child owns where it *sends* (its learned route table), because only the
//!   process holding the endpoint knows it.
//!
//! Nothing is published unless both agree, which is what makes a wedged child
//! disappear from the catalog instead of lingering as a route to nowhere.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use fpl_resource_observation::Service;
use mycelium_core::Observation;
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};

/// The service kind peers look for. `iroh-tun` matches it byte for byte; a
/// qualified `iroh-tun/1` would also match on the consumer side.
pub const KIND: &str = "iroh-tun";
/// Long enough that a slow tick is not an outage, short enough that a dead
/// daemon stops advertising within a minute.
const LEASE_SECONDS: u64 = 60;
/// Config is re-read and the child reaped on this cadence. Small enough that
/// `mycelium iroh-tun config --write` takes effect while you watch.
const SUPERVISE_TICK: Duration = Duration::from_secs(5);
const MIN_WEDGE_SECS: u64 = 120;
const BACKOFF_CAP_SECS: u64 = 60;

/// Every file the supervisor touches, injected rather than read from the global
/// home so the whole supervisor can be exercised against a temp directory.
#[derive(Clone, Debug)]
pub struct Paths {
    pub config: PathBuf,
    pub key: PathBuf,
    pub status: PathBuf,
    pub log: PathBuf,
}

impl Paths {
    pub fn under(home: &Path) -> Self {
        Self {
            config: home.join("iroh-tun.json"),
            key: home.join("iroh-tun.key"),
            status: home.join("iroh-tun-status.json"),
            log: home.join("iroh-tun.log"),
        }
    }
}

/// `~/.mycelium/iroh-tun.json`. The file's existence is the enable switch; a
/// present file without `enabled` is enabled.
#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tun: Option<String>,
    #[serde(default = "default_mtu")]
    pub mtu: u16,
    /// Prefixes this node answers for, as seen by peers. Empty is legal: a
    /// client-only node reaches the overlay and advertises nothing, which is
    /// how the first node in a fleet bootstraps.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub overlay: Vec<String>,
    #[serde(default = "default_refresh_secs")]
    pub refresh_secs: u64,
    /// Published as an address hint so a peer can dial without a lookup. Only a
    /// specific address is useful; `0.0.0.0:0` is not a hint.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub listen: Option<String>,
    /// A privileged service (root LaunchDaemon or systemd unit) runs the child.
    /// This daemon still owns the key, the endpoint identity and the published
    /// observation, but it never spawns or reaps the tunnel in this mode. The
    /// privileged child writes the same status file the daemon reads.
    #[serde(default)]
    pub external: bool,
    /// Where the tunnel writes its status. A privileged child cannot safely
    /// write into a user-writable directory (a symlink there would redirect a
    /// root write), so the installer points this at a root-owned runtime
    /// directory. The default remains the per-user file beside the config.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub binary: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mycelium_binary: Option<PathBuf>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            enabled: true,
            tun: None,
            mtu: default_mtu(),
            overlay: Vec::new(),
            refresh_secs: default_refresh_secs(),
            listen: None,
            external: false,
            status: None,
            binary: None,
            mycelium_binary: None,
        }
    }
}

fn default_true() -> bool {
    true
}

fn default_mtu() -> u16 {
    1280
}

fn default_refresh_secs() -> u64 {
    15
}

impl Config {
    /// Reject what the child would reject, here, where the message can name the
    /// file. Overlay prefixes are normalized to masked CIDR so two spellings of
    /// the same prefix cannot become two routes.
    pub fn validate(mut self) -> Result<Self, String> {
        if !self.enabled {
            return Ok(self);
        }
        let tun = self.tun.as_deref().unwrap_or_default();
        if tun.is_empty()
            || tun.len() > 32
            || !tun
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return Err(
                "`tun` is required and names one interface (letters, digits, - or _)".into(),
            );
        }
        if !(576..=9000).contains(&self.mtu) {
            return Err("`mtu` must be between 576 and 9000".into());
        }
        if !(1..=300).contains(&self.refresh_secs) {
            return Err("`refresh_secs` must be between 1 and 300".into());
        }
        if let Some(listen) = &self.listen {
            listen
                .parse::<std::net::SocketAddr>()
                .map_err(|_| format!("`listen` must be an IP:PORT socket address, got {listen}"))?;
        }
        if let Some(status) = &self.status {
            if !status.is_absolute() {
                return Err("`status` must be an absolute path".into());
            }
        }
        let mut overlay = Vec::new();
        for value in &self.overlay {
            let prefix = normalize_prefix(value)?;
            if !overlay.contains(&prefix) {
                overlay.push(prefix);
            }
        }
        overlay.sort();
        self.overlay = overlay;
        Ok(self)
    }
}

/// A default route cannot be a claim about one node: publishing it would make
/// every consumer send everything here.
fn normalize_prefix(value: &str) -> Result<String, String> {
    let (address, length) = mycelium_core::parse_cidr(value)
        .ok_or_else(|| format!("overlay prefix `{value}` is not CIDR notation"))?;
    if length == 0 {
        return Err(format!(
            "overlay prefix `{value}` is a default route; publish the prefixes this node owns"
        ));
    }
    let masked = match address {
        std::net::IpAddr::V4(v4) => {
            let mask = u32::MAX << (32 - u32::from(length));
            std::net::IpAddr::V4((u32::from(v4) & mask).into())
        }
        std::net::IpAddr::V6(v6) => {
            let mask = u128::MAX << (128 - u32::from(length));
            std::net::IpAddr::V6((u128::from(v6) & mask).into())
        }
    };
    Ok(format!("{masked}/{length}"))
}

/// The child's own report, written every beat. Only the process holding the
/// endpoint knows its route table, so the daemon reads it rather than guessing.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Status {
    pub schema_version: u32,
    pub endpoint_id: String,
    pub tun: String,
    pub mtu: u16,
    pub observed_at: u64,
    #[serde(default)]
    pub routes: Vec<StatusRoute>,
    #[serde(default)]
    pub refresh_failures: u32,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct StatusRoute {
    pub prefix: String,
    pub peer: String,
}

/// One supervisor per daemon. Disabled is a normal state, not an error.
pub struct Supervisor {
    paths: Paths,
    state: tokio::sync::Mutex<State>,
}

#[derive(Default)]
struct State {
    config: Option<Config>,
    config_error: Option<String>,
    child: Option<tokio::process::Child>,
    pid: Option<u32>,
    started_at: Option<u64>,
    endpoint_id: Option<String>,
    routes: Vec<StatusRoute>,
    status_age: Option<u64>,
    refresh_failures: u32,
    restarts: u32,
    retry_at: Option<Instant>,
    last_exit: Option<String>,
    last_error: Option<String>,
    reported: Option<String>,
}

impl Default for Supervisor {
    fn default() -> Self {
        Self::new()
    }
}

impl Supervisor {
    pub fn new() -> Self {
        Self::at(Paths::under(&crate::home_dir()))
    }

    pub fn at(paths: Paths) -> Self {
        Self {
            paths,
            state: tokio::sync::Mutex::new(State::default()),
        }
    }

    /// One supervision step: reload config, reap or start the child, and return
    /// the observation to publish if the tunnel is demonstrably working.
    pub async fn tick(&self, node: &str, now: u64) -> Option<Observation> {
        let mut state = self.state.lock().await;
        let note = |state: &mut State, message: String| {
            if state.reported.as_deref() != Some(message.as_str()) {
                eprintln!("myceliumd: iroh-tun: {message}");
                state.reported = Some(message.clone());
            }
            state.last_error = Some(message);
        };

        match load_config(&self.paths.config) {
            Ok(Some(config)) => {
                if state.config.as_ref() != Some(&config) {
                    // A changed config is a different tunnel: the old process
                    // was started with flags that no longer describe it.
                    stop_child(&mut state).await;
                    state.endpoint_id = None;
                    state.config = Some(config);
                    state.retry_at = None;
                    state.restarts = 0;
                }
                state.config_error = None;
            }
            Ok(None) => {
                if state.config.is_some() {
                    stop_child(&mut state).await;
                }
                state.config = None;
                state.config_error = None;
                state.endpoint_id = None;
                state.routes.clear();
                return None;
            }
            Err(error) => {
                // An unreadable or invalid config is the operator's intent
                // unknown: stop rather than run a tunnel the file contradicts.
                stop_child(&mut state).await;
                state.config = None;
                state.endpoint_id = None;
                state.routes.clear();
                state.config_error = Some(error.clone());
                note(&mut state, error);
                return None;
            }
        }
        let config = state.config.clone()?;

        let key = match ensure_key(&self.paths.key) {
            Ok(key) => key,
            Err(error) => {
                stop_child(&mut state).await;
                note(&mut state, error);
                return None;
            }
        };
        let binary = resolve_binary(config.binary.as_ref(), "iroh-tun");
        if state.endpoint_id.is_none() {
            match print_id(&binary, config.tun.as_deref().unwrap_or_default(), &key).await {
                Ok(id) => state.endpoint_id = Some(id),
                Err(error) => {
                    stop_child(&mut state).await;
                    note(&mut state, error);
                    return None;
                }
            }
        }
        let endpoint_id = state.endpoint_id.clone()?;

        // Reap before starting: one child, never two. An external tunnel is owned
        // by the privileged service; this daemon has no child to reap or start.
        if config.external {
            if state.child.is_some() {
                stop_child(&mut state).await;
            }
            state.pid = None;
            state.retry_at = None;
        }
        if let Some(child) = state.child.as_mut() {
            match child.try_wait() {
                Ok(Some(status)) => {
                    let detail = last_log_line(&self.paths.log)
                        .map(|line| format!("iroh-tun exited ({status}): {line}"))
                        .unwrap_or_else(|| format!("iroh-tun exited ({status})"));
                    state.child = None;
                    state.pid = None;
                    let lived = state.started_at.map(|at| now.saturating_sub(at));
                    state.started_at = None;
                    // A child that ran a while and then died is a new problem,
                    // not a continuation of the crash loop.
                    if lived.is_some_and(|seconds| seconds >= BACKOFF_CAP_SECS) {
                        state.restarts = 0;
                    }
                    state.restarts = state.restarts.saturating_add(1);
                    let delay = 1u64
                        .checked_shl(state.restarts.min(6))
                        .unwrap_or(BACKOFF_CAP_SECS)
                        .min(BACKOFF_CAP_SECS);
                    state.retry_at = Some(Instant::now() + Duration::from_secs(delay));
                    state.last_exit = Some(detail.clone());
                    note(&mut state, detail);
                }
                Ok(None) => {}
                Err(error) => {
                    state.child = None;
                    state.pid = None;
                    note(&mut state, format!("reap iroh-tun: {error}"));
                }
            }
        }

        if !config.external
            && state.child.is_none()
            && state.retry_at.is_none_or(|at| Instant::now() >= at)
        {
            let mycelium_binary = resolve_binary(config.mycelium_binary.as_ref(), "mycelium");
            match spawn(
                &self.paths,
                &config,
                &binary,
                &mycelium_binary,
                &key,
                &endpoint_id,
                config.status.as_deref().unwrap_or(&self.paths.status),
            ) {
                Ok(child) => {
                    state.pid = child.id();
                    state.child = Some(child);
                    state.started_at = Some(now);
                    state.retry_at = None;
                    state.reported = None;
                    state.last_error = None;
                }
                Err(error) => {
                    state.restarts = state.restarts.saturating_add(1);
                    let delay = 1u64
                        .checked_shl(state.restarts.min(6))
                        .unwrap_or(BACKOFF_CAP_SECS)
                        .min(BACKOFF_CAP_SECS);
                    state.retry_at = Some(Instant::now() + Duration::from_secs(delay));
                    note(&mut state, error);
                }
            }
        }

        // The child's evidence. Stale means wedged, and wedged means it may not
        // speak for this node in the catalog.
        let status_path = config.status.as_deref().unwrap_or(&self.paths.status);
        let status = read_status(status_path);
        let wedged_after = (config.refresh_secs * 5).max(MIN_WEDGE_SECS);
        match status {
            Ok(Some(status)) if status.endpoint_id == endpoint_id => {
                state.status_age = Some(now.saturating_sub(status.observed_at));
                state.routes = status.routes.clone();
                state.refresh_failures = status.refresh_failures;
                if !config.external
                    && now.saturating_sub(status.observed_at) > wedged_after
                    && state.child.is_some()
                {
                    stop_child(&mut state).await;
                    state.restarts = state.restarts.saturating_add(1);
                    state.retry_at = Some(Instant::now() + Duration::from_secs(1));
                    note(
                        &mut state,
                        format!(
                            "iroh-tun stopped reporting for {}s; restarting it",
                            now.saturating_sub(status.observed_at)
                        ),
                    );
                }
            }
            Ok(Some(_)) => {
                // A status document from a previous identity describes a tunnel
                // that no longer exists.
                state.status_age = None;
                state.routes.clear();
            }
            Ok(None) => {
                state.status_age = None;
                state.routes.clear();
            }
            Err(error) => {
                state.status_age = None;
                state.routes.clear();
                note(&mut state, error);
            }
        }

        let running = state.child.is_some() || config.external;
        let fresh = state
            .status_age
            .is_some_and(|age| age <= (config.refresh_secs * 3).max(LEASE_SECONDS));
        if config.external && !fresh {
            note(
                &mut state,
                "external iroh-tun has not written a fresh status; check the privileged service"
                    .into(),
            );
        }
        if !running || !fresh {
            return None;
        }
        match observation(
            node,
            &endpoint_id,
            &config,
            &state.routes,
            state.refresh_failures,
            now,
        ) {
            Ok(observation) => {
                // Healthy again: an error from an earlier tick is history, and a
                // status that keeps showing it teaches the operator to ignore it.
                state.last_error = None;
                Some(observation)
            }
            Err(error) => {
                // Publishing must never take the daemon down because one node id
                // is unspeakable; it is reported and retried next tick.
                note(&mut state, error);
                None
            }
        }
    }

    pub async fn stop(&self) {
        let mut state = self.state.lock().await;
        stop_child(&mut state).await;
        state.retry_at = None;
    }

    pub async fn restart(&self) {
        let mut state = self.state.lock().await;
        stop_child(&mut state).await;
        state.retry_at = None;
        state.restarts = 0;
        state.last_error = None;
    }

    /// The daemon's own account of itself, for `mycelium iroh-tun status` and
    /// for doctor. Every field is a fact this process holds, not a re-derivation.
    pub async fn report(&self, node: &str, now: u64) -> serde_json::Value {
        let state = self.state.lock().await;
        let config = state.config.clone();
        let enabled = config.is_some();
        let running = state.child.is_some() || config.as_ref().is_some_and(|c| c.external);
        let fresh = state.status_age.is_some_and(|age| {
            age <= config
                .as_ref()
                .map_or(0, |c| (c.refresh_secs * 3).max(LEASE_SECONDS))
        });
        serde_json::json!({
            "enabled": enabled,
            "config": self.paths.config.display().to_string(),
            "config_error": state.config_error,
            "running": running,
            "external": config.as_ref().is_some_and(|c| c.external),
            "pid": state.pid,
            "endpoint_id": state.endpoint_id,
            "tun": config.as_ref().and_then(|c| c.tun.clone()),
            "mtu": config.as_ref().map(|c| c.mtu),
            "overlay": config.as_ref().map(|c| c.overlay.clone()).unwrap_or_default(),
            "listen": config.as_ref().and_then(|c| c.listen.clone()),
            "routes": state.routes,
            "refresh_failures": state.refresh_failures,
            "status_age_secs": state.status_age,
            "publishing": running && fresh,
            "restarts": state.restarts,
            "last_exit": state.last_exit,
            "last_error": state.last_error,
            "log": self.paths.log.display().to_string(),
            "status_file": config
                .as_ref()
                .and_then(|c| c.status.clone())
                .unwrap_or_else(|| self.paths.status.clone())
                .display()
                .to_string(),
            "node": node,
            "observed_at": now,
        })
    }
}

fn load_config(path: &Path) -> Result<Option<Config>, String> {
    match std::fs::read(&path) {
        Ok(bytes) => serde_json::from_slice::<Config>(&bytes)
            .map_err(|error| format!("{}: {error}", path.display()))?
            .validate()
            .map(Some)
            .map_err(|error| format!("{}: {error}", path.display())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(format!("read {}: {error}", path.display())),
    }
}

/// A fixed key is the whole point: without it every restart is a new identity
/// and every peer's route goes stale.
fn ensure_key(path: &Path) -> Result<String, String> {
    match std::fs::read_to_string(path) {
        Ok(text) => {
            let key = text.trim().to_owned();
            if !is_hex_64(&key) {
                return Err(format!("{}: a key is 64 hex characters", path.display()));
            }
            Ok(key)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let mut bytes = [0u8; 32];
            OsRng.fill_bytes(&mut bytes);
            let key = hex(&bytes);
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)
                    .map_err(|error| format!("create {}: {error}", parent.display()))?;
            }
            match std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(path)
            {
                Ok(mut file) => {
                    use std::io::Write;
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt;
                        file.set_permissions(std::fs::Permissions::from_mode(0o600))
                            .map_err(|error| format!("chmod {}: {error}", path.display()))?;
                    }
                    writeln!(file, "{key}")
                        .map_err(|error| format!("write {}: {error}", path.display()))?;
                    Ok(key)
                }
                // Another writer won the race; its key is just as good.
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => ensure_key(path),
                Err(error) => Err(format!("create {}: {error}", path.display())),
            }
        }
        Err(error) => Err(format!("read {}: {error}", path.display())),
    }
}

fn is_hex_64(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// A configured path wins; otherwise the sibling of this daemon, because a fleet
/// installs the pair together; otherwise PATH.
fn resolve_binary(configured: Option<&PathBuf>, name: &str) -> PathBuf {
    if let Some(path) = configured {
        return expand_home(path);
    }
    if let Ok(executable) = std::env::current_exe() {
        if let Some(directory) = executable.parent() {
            let sibling = directory.join(name);
            if sibling.is_file() {
                return sibling;
            }
        }
    }
    PathBuf::from(name)
}

fn expand_home(path: &Path) -> PathBuf {
    match path.to_str().and_then(|text| text.strip_prefix("~/")) {
        Some(suffix) => std::env::var_os("HOME")
            .map(PathBuf::from)
            .unwrap_or_default()
            .join(suffix),
        None => path.to_path_buf(),
    }
}

async fn print_id(binary: &Path, tun: &str, key: &str) -> Result<String, String> {
    let output = tokio::time::timeout(
        Duration::from_secs(10),
        tokio::process::Command::new(binary)
            .arg("--tun")
            .arg(tun)
            .arg("--secret")
            .arg(key)
            .arg("--print-id")
            .output(),
    )
    .await
    .map_err(|_| format!("{} --print-id timed out", binary.display()))?
    .map_err(|error| format!("run {}: {error}", binary.display()))?;
    if !output.status.success() {
        return Err(format!(
            "{} --print-id exited {}: {}",
            binary.display(),
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let id = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    if !is_hex_64(&id) {
        return Err(format!(
            "{} --print-id printed no endpoint id",
            binary.display()
        ));
    }
    Ok(id)
}

fn spawn(
    paths: &Paths,
    config: &Config,
    binary: &Path,
    mycelium_binary: &Path,
    key: &str,
    endpoint_id: &str,
    status_file: &Path,
) -> Result<tokio::process::Child, String> {
    let log = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&paths.log)
        .map_err(|error| format!("open {}: {error}", paths.log.display()))?;
    let errors = log
        .try_clone()
        .map_err(|error| format!("clone {}: {error}", paths.log.display()))?;
    let mut command = tokio::process::Command::new(binary);
    command
        .arg("--tun")
        .arg(config.tun.as_deref().unwrap_or_default())
        .arg("--mtu")
        .arg(config.mtu.to_string())
        .arg("--refresh-secs")
        .arg(config.refresh_secs.to_string())
        .arg("--secret")
        .arg(key)
        .arg("--status-file")
        .arg(status_file)
        .arg("--mycelium")
        .arg(mycelium_binary)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::from(log))
        .stderr(std::process::Stdio::from(errors));
    if let Some(listen) = &config.listen {
        command.arg("--listen").arg(listen);
    }
    command
        .spawn()
        .map_err(|error| format!("start {} for {endpoint_id}: {error}", binary.display()))
}

async fn stop_child(state: &mut State) {
    if let Some(mut child) = state.child.take() {
        // Ask, then make sure. A tunnel that ignores SIGTERM still holds the
        // tun device, and the next spawn would fail on a busy interface.
        let _ = child.start_kill();
        match tokio::time::timeout(Duration::from_secs(5), child.wait()).await {
            Ok(_) => {}
            Err(_) => {
                eprintln!("myceliumd: iroh-tun did not exit within 5s");
            }
        }
    }
    state.pid = None;
    state.started_at = None;
}

fn read_status(path: &Path) -> Result<Option<Status>, String> {
    match std::fs::read(path) {
        Ok(bytes) => serde_json::from_slice::<Status>(&bytes)
            .map(Some)
            .map_err(|error| format!("{}: {error}", path.display())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(format!("read {}: {error}", path.display())),
    }
}

fn last_log_line(path: &Path) -> Option<String> {
    let bytes = std::fs::read(path).ok()?;
    let tail = &bytes[bytes.len().saturating_sub(4096)..];
    String::from_utf8_lossy(tail)
        .lines()
        .rev()
        .find(|line| !line.trim().is_empty())
        .map(|line| line.trim().to_owned())
}

/// The published claim: identity, what this node answers for, and how much of
/// the fleet it can currently reach. Address hints are optional and only ever a
/// specific socket address, never a wildcard.
fn observation(
    node: &str,
    endpoint_id: &str,
    config: &Config,
    routes: &[StatusRoute],
    refresh_failures: u32,
    now: u64,
) -> Result<Observation, String> {
    let service_id = format!("service/{}/iroh-tun", node.to_lowercase());
    let mut attributes = BTreeMap::from([
        ("node_id".to_owned(), node.to_owned()),
        ("endpoint_id".to_owned(), endpoint_id.to_owned()),
        ("tun".to_owned(), config.tun.clone().unwrap_or_default()),
        ("mtu".to_owned(), config.mtu.to_string()),
        ("routes".to_owned(), routes.len().to_string()),
        ("refresh_failures".to_owned(), refresh_failures.to_string()),
    ]);
    if !config.overlay.is_empty() {
        attributes.insert("overlay".to_owned(), config.overlay.join(","));
    }
    if let Some(listen) = &config.listen {
        if let Ok(address) = listen.parse::<std::net::SocketAddr>() {
            if !address.ip().is_unspecified() && address.port() != 0 {
                attributes.insert("addresses".to_owned(), address.to_string());
            }
        }
    }
    crate::local_services::lease(
        node,
        &service_id,
        Service {
            kind: KIND.to_owned(),
            // The tunnel is addressed by endpoint id, not by a DNS name.
            names: Vec::new(),
            endpoints: BTreeSet::from([format!("iroh://{endpoint_id}")]),
            protocols: BTreeSet::from(["quic".to_owned()]),
            formats: BTreeSet::new(),
            attributes,
        },
        now,
        now.saturating_add(LEASE_SECONDS),
    )
}

/// How often the supervisor wakes. Kept here so `serve` does not invent a second
/// cadence that could disagree with the lease.
pub fn tick_interval() -> Duration {
    SUPERVISE_TICK
}

pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(value: serde_json::Value) -> Result<Config, String> {
        serde_json::from_value::<Config>(value)
            .map_err(|error| error.to_string())?
            .validate()
    }

    /// A stand-in for the real binary: it answers `--print-id`, and on a normal
    /// run writes the status document the daemon reads, then idles. This is the
    /// whole contract between the two processes, so testing it is testing the
    /// feature, minus the tun device.
    fn fake_tunnel(dir: &Path, id: &str) -> PathBuf {
        let path = dir.join("fake-iroh-tun");
        // Raw text plus a token replace: the script is full of braces, and
        // escaping them for `format!` would make the fixture unreadable.
        let script = r#"#!/bin/sh
for a in "$@"; do
  if [ "$a" = "--print-id" ]; then echo __ID__; exit 0; fi
done
prev=""
for a in "$@"; do
  if [ "$prev" = "--status-file" ]; then
    printf '%s' '{"schema_version":1,"endpoint_id":"__ID__","tun":"utun-test","mtu":1280,"observed_at":' > "$a"
    date +%s | tr -d '\n' >> "$a"
    printf '%s' ',"routes":[{"prefix":"10.9.0.0/24","peer":"__ID__"}],"refresh_failures":0}' >> "$a"
  fi
  prev="$a"
done
sleep 30
"#;
        std::fs::write(&path, script.replace("__ID__", id)).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        path
    }

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "mycelium-iroh-tun-{name}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .subsec_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    const ID: &str = "295ca41d4e6e4b0f8d5b1c2f9a7e3d6c8b4a2f1e0d9c7b6a5f4e3d2c1b0a9f8e";

    #[tokio::test]
    async fn the_daemon_starts_the_tunnel_and_publishes_what_it_reports() {
        let dir = temp_dir("publish");
        let paths = Paths::under(&dir);
        let binary = fake_tunnel(&dir, ID);
        std::fs::write(
            &paths.config,
            serde_json::json!({
                "tun": "utun-test",
                "overlay": ["10.42.0.7/24"],
                "refresh_secs": 1,
                "binary": binary,
                "mycelium_binary": "/bin/true"
            })
            .to_string(),
        )
        .unwrap();
        let supervisor = Supervisor::at(paths.clone());
        // First tick starts the child; it needs a moment to write its status.
        assert!(supervisor.tick("neo", now()).await.is_none());
        let mut observation = None;
        for _ in 0..40 {
            tokio::time::sleep(Duration::from_millis(50)).await;
            if let Some(found) = supervisor.tick("neo", now()).await {
                observation = Some(found);
                break;
            }
        }
        let Observation::ServiceAdvertisement { advertisement, .. } =
            observation.expect("a running, reporting tunnel is published")
        else {
            panic!("a daemon lease is an advertisement")
        };
        let projected = crate::local_services::project(&advertisement)
            .unwrap()
            .unwrap();
        assert_eq!(projected.value.kind, KIND);
        assert_eq!(projected.value.attributes["overlay"], "10.42.0.0/24");
        assert_eq!(projected.value.attributes["endpoint_id"], ID);
        assert_eq!(projected.value.attributes["routes"], "1");
        assert!(projected.value.endpoints.contains(&format!("iroh://{ID}")));
        assert!(projected.is_fresh_at(now()));
        supervisor.stop().await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn an_external_tunnel_publishes_from_its_status_without_a_child() {
        let dir = temp_dir("external");
        let paths = Paths::under(&dir);
        let status_path = dir.join("root-status.json");
        let binary = fake_tunnel(&dir, ID);
        std::fs::write(
            &paths.config,
            serde_json::json!({
                "tun": "utun-test",
                "overlay": ["10.42.0.7/24"],
                "refresh_secs": 1,
                "external": true,
                "status": status_path.to_string_lossy(),
                "binary": binary,
                "mycelium_binary": "/bin/true"
            })
            .to_string(),
        )
        .unwrap();
        std::fs::write(
            &status_path,
            serde_json::json!({
                "schema_version": 1,
                "endpoint_id": ID,
                "tun": "utun-test",
                "mtu": 1280,
                "observed_at": now(),
                "routes": [{"prefix": "10.9.0.0/24", "peer": ID}],
                "refresh_failures": 0
            })
            .to_string(),
        )
        .unwrap();
        let supervisor = Supervisor::at(paths);
        let observation = supervisor
            .tick("neo", now())
            .await
            .expect("a fresh external status is enough evidence to publish");
        let Observation::ServiceAdvertisement { advertisement, .. } = observation else {
            panic!("a daemon lease is an advertisement")
        };
        let projected = crate::local_services::project(&advertisement)
            .unwrap()
            .unwrap();
        assert_eq!(projected.value.attributes["overlay"], "10.42.0.0/24");
        assert_eq!(projected.value.attributes["routes"], "1");

        let report = supervisor.report("neo", now()).await;
        assert_eq!(report["external"], serde_json::json!(true));
        assert_eq!(report["running"], serde_json::json!(true));
        assert!(report["publishing"].as_bool().unwrap());
        assert!(report["pid"].is_null(), "no child belongs to this daemon");
        supervisor.stop().await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn a_tunnel_that_dies_is_reported_and_not_published() {
        let dir = temp_dir("dead");
        let paths = Paths::under(&dir);
        let binary = dir.join("fake-iroh-tun");
        let script = r#"#!/bin/sh
for a in "$@"; do
  if [ "$a" = "--print-id" ]; then echo __ID__; exit 0; fi
done
echo "fake-iroh-tun: open tun device utun-test: Device or resource busy" >&2
exit 1
"#;
        std::fs::write(&binary, script.replace("__ID__", ID)).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        std::fs::write(
            &paths.config,
            serde_json::json!({
                "tun": "utun-test",
                "binary": binary,
                "mycelium_binary": "/bin/true"
            })
            .to_string(),
        )
        .unwrap();
        let supervisor = Supervisor::at(paths);
        assert!(supervisor.tick("neo", now()).await.is_none());
        tokio::time::sleep(Duration::from_millis(200)).await;
        // A dead child never produces an observation, and the failure is named
        // rather than swallowed.
        assert!(supervisor.tick("neo", now()).await.is_none());
        let report = supervisor.report("neo", now()).await;
        assert_eq!(report["running"], serde_json::json!(false));
        assert!(!report["publishing"].as_bool().unwrap());
        let error = report["last_error"].as_str().unwrap_or_default();
        assert!(error.contains("exited"), "{error}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_file_without_enabled_means_enabled() {
        let parsed = config(serde_json::json!({"tun": "utun220"})).unwrap();
        assert!(parsed.enabled);
        assert_eq!(parsed.mtu, 1280);
        assert_eq!(parsed.refresh_secs, 15);
        assert!(!parsed.external, "the daemon owns the child by default");
    }

    #[test]
    fn an_external_tunnel_is_explicit() {
        let parsed = config(serde_json::json!({
            "tun": "utun220",
            "external": true
        }))
        .unwrap();
        assert!(parsed.external);
    }

    #[test]
    fn disabled_needs_nothing_else() {
        let parsed = config(serde_json::json!({"enabled": false})).unwrap();
        assert!(!parsed.enabled);
        assert!(parsed.tun.is_none());
    }

    #[test]
    fn overlay_prefixes_are_masked_deduplicated_and_sorted() {
        let parsed = config(serde_json::json!({
            "tun": "utun220",
            "overlay": ["10.42.0.7/24", "192.168.10.0/24", "10.42.0.0/24"]
        }))
        .unwrap();
        assert_eq!(parsed.overlay, vec!["10.42.0.0/24", "192.168.10.0/24"]);
    }

    #[test]
    fn bad_configs_name_the_problem() {
        let error =
            config(serde_json::json!({"tun": "utun220", "overlay": ["0.0.0.0/0"]})).unwrap_err();
        assert!(error.contains("default route"), "{error}");
        let error = config(serde_json::json!({"tun": "utun220", "overlay": ["nope"]})).unwrap_err();
        assert!(error.contains("CIDR"), "{error}");
        assert!(config(serde_json::json!({})).is_err(), "tun is required");
        assert!(config(serde_json::json!({"tun": "utun220", "mtu": 99})).is_err());
        assert!(config(serde_json::json!({"tun": "utun220", "status": "relative"})).is_err());
        assert!(config(serde_json::json!({"tun": "utun220", "extra": 1})).is_err());
    }

    #[test]
    fn the_published_lease_survives_projection_as_the_kind_peers_look_for() {
        let parsed = config(serde_json::json!({
            "tun": "utun220",
            "overlay": ["10.42.0.0/24"],
            "listen": "192.0.2.10:4400"
        }))
        .unwrap();
        let id = "295ca41d4e6e4b0f8d5b1c2f9a7e3d6c8b4a2f1e0d9c7b6a5f4e3d2c1b0a9f8e";
        let Observation::ServiceAdvertisement { advertisement, .. } =
            observation("neo", id, &parsed, &[], 0, 1_000).unwrap()
        else {
            panic!("a daemon lease is an advertisement")
        };
        let projected = crate::local_services::project(&advertisement)
            .unwrap()
            .unwrap();
        assert_eq!(projected.value.kind, KIND);
        assert_eq!(projected.expires_at, 1_000 + LEASE_SECONDS);
        assert!(projected.value.endpoints.contains(&format!("iroh://{id}")));
        assert_eq!(projected.value.attributes["overlay"], "10.42.0.0/24");
        assert_eq!(projected.value.attributes["addresses"], "192.0.2.10:4400");
        assert_eq!(projected.value.attributes["node_id"], "neo");
        assert_eq!(projected.provenance.observer, "neo");
    }

    #[test]
    fn a_wildcard_listen_address_is_not_published_as_a_hint() {
        let parsed = config(serde_json::json!({
            "tun": "utun220",
            "listen": "0.0.0.0:4400"
        }))
        .unwrap();
        let Observation::ServiceAdvertisement { advertisement, .. } = observation(
            "neo",
            "295ca41d4e6e4b0f8d5b1c2f9a7e3d6c8b4a2f1e0d9c7b6a5f4e3d2c1b0a9f8e",
            &parsed,
            &[],
            0,
            1_000,
        )
        .unwrap() else {
            panic!()
        };
        let projected = crate::local_services::project(&advertisement)
            .unwrap()
            .unwrap();
        assert!(!projected.value.attributes.contains_key("addresses"));
    }
}
