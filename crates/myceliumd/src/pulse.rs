//! The daemon's scheduled work.
//!
//! Pulse has two layers:
//!
//! - **System pulses** are built in. `system.ssh-renewal` is the first one.
//! - **User pulses** are records with a five-field cron schedule and a bounded
//!   shell command. They are stored in `$MYCELIUM_HOME/pulse.json` and run by
//!   the same scheduler.
//!
//! The daemon owns the clock, the startup jitter, the next-fire calculation and
//! the run history. The Pulse Spore and the `pulse` CLI are clients; neither
//! owns a store of its own.

use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::Write as _;
use std::path::PathBuf;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;
use tokio::time::{sleep, Instant};

use crate::peer::Mesh;

mod cron;

pub use cron::{Problem, Schedule};

const RUN_TIMEOUT: Duration = Duration::from_secs(60);
const TICK: Duration = Duration::from_secs(5);
const OVERDUE_GRACE_MS: u64 = 5 * 60 * 1000;
const MAX_COMMAND_BYTES: usize = 8192;
const MAX_DETAIL_BYTES: usize = 2_000;
const MAX_RUNS: usize = 10_000;

/// A built-in task the daemon runs on a fixed cadence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SystemPulse {
    pub id: &'static str,
    pub interval: Duration,
    pub action: SystemAction,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SystemAction {
    SshRenewal,
}

/// System pulse config. User/desktop pulses are loaded beside this table.
pub const SYSTEM_PULSES: [SystemPulse; 1] = [SystemPulse {
    id: "system.ssh-renewal",
    interval: Duration::from_secs(30),
    action: SystemAction::SshRenewal,
}];

/// A user-created pulse. The schedule is five-field cron; the command is run
/// with `/bin/sh -c` under a 60-second timeout.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UserPulse {
    pub id: String,
    pub schedule: String,
    pub command: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub created_at_ms: u64,
    #[serde(default)]
    pub updated_at_ms: u64,
    /// The last nominal fire, used to make restarts idempotent.
    #[serde(default)]
    pub last_fired_ms: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PulseRun {
    pub id: String,
    pub pulse_id: String,
    pub scheduled_at_ms: u64,
    pub fired_at_ms: u64,
    pub finished_at_ms: u64,
    pub outcome: String,
    pub detail: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PulseView {
    #[serde(flatten)]
    pub pulse: UserPulse,
    pub next_at_ms: Option<i64>,
}

/// A read-only system pulse as the console sees it.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SystemPulseView {
    pub id: String,
    pub interval_secs: u64,
    pub description: String,
}

/// One response for the console: system pulses plus user pulses.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PulseList {
    pub system: Vec<SystemPulseView>,
    pub user: Vec<PulseView>,
}

pub(crate) async fn list_all() -> PulseList {
    let store = store().lock().await;
    PulseList {
        system: SYSTEM_PULSES
            .iter()
            .map(|pulse| SystemPulseView {
                id: pulse.id.to_owned(),
                interval_secs: pulse.interval.as_secs(),
                description: match pulse.action {
                    SystemAction::SshRenewal => {
                        "renew the node SSH certificate before it expires".to_owned()
                    }
                },
            })
            .collect(),
        user: store.list(),
    }
}

pub(crate) struct Store {
    pulses_path: PathBuf,
    runs_path: PathBuf,
    pulses: BTreeMap<String, UserPulse>,
}

static STORE: OnceLock<Arc<Mutex<Store>>> = OnceLock::new();

/// The daemon-owned Pulse store. The scheduler and RPC use this one instance.
pub(crate) fn store() -> &'static Arc<Mutex<Store>> {
    STORE.get_or_init(|| Arc::new(Mutex::new(Store::load())))
}

impl Store {
    fn load() -> Self {
        let home = crate::home_dir();
        let pulses_path = home.join("pulse.json");
        let runs_path = home.join("pulse-runs.jsonl");
        let pulses = fs::read_to_string(&pulses_path)
            .ok()
            .and_then(|text| serde_json::from_str::<Vec<UserPulse>>(&text).ok())
            .unwrap_or_default()
            .into_iter()
            .map(|pulse| (pulse.id.clone(), pulse))
            .collect();
        Self {
            pulses_path,
            runs_path,
            pulses,
        }
    }

    fn save(&self) -> Result<(), String> {
        if let Some(parent) = self.pulses_path.parent() {
            fs::create_dir_all(parent).map_err(|e| format!("create {}: {e}", parent.display()))?;
        }
        let pulses: Vec<&UserPulse> = self.pulses.values().collect();
        let bytes = serde_json::to_vec_pretty(&pulses).map_err(|e| e.to_string())?;
        let temporary = self.pulses_path.with_extension("json.tmp");
        fs::write(&temporary, bytes).map_err(|e| format!("write {}: {e}", temporary.display()))?;
        fs::rename(&temporary, &self.pulses_path)
            .map_err(|e| format!("install {}: {e}", self.pulses_path.display()))
    }

    pub(crate) fn list(&self) -> Vec<PulseView> {
        let now = now_ms() as i64;
        self.pulses
            .values()
            .map(|pulse| PulseView {
                pulse: pulse.clone(),
                next_at_ms: next_fire(pulse, now),
            })
            .collect()
    }

    pub(crate) fn put(&mut self, mut pulse: UserPulse) -> Result<UserPulse, String> {
        validate(&pulse)?;
        if pulse.id.trim().is_empty() {
            pulse.id = format!("pulse-{}", now_ms());
        }
        pulse.id = pulse.id.trim().to_owned();
        pulse.schedule = pulse.schedule.trim().to_owned();
        pulse.command = pulse.command.trim().to_owned();
        let now = now_ms();
        if let Some(existing) = self.pulses.get(&pulse.id) {
            pulse.created_at_ms = existing.created_at_ms;
            pulse.last_fired_ms = existing.last_fired_ms;
        } else if pulse.created_at_ms == 0 {
            pulse.created_at_ms = now;
        }
        pulse.updated_at_ms = now;
        self.pulses.insert(pulse.id.clone(), pulse.clone());
        self.save()?;
        Ok(pulse)
    }

    pub(crate) fn remove(&mut self, id: &str) -> Result<bool, String> {
        let existed = self.pulses.remove(id).is_some();
        if existed {
            self.save()?;
        }
        Ok(existed)
    }

    fn due(&mut self, now: u64) -> Vec<(UserPulse, u64)> {
        let mut due = Vec::new();
        let mut changed = false;
        for pulse in self.pulses.values_mut() {
            if !pulse.enabled {
                continue;
            }
            let Ok(schedule) = Schedule::parse(&pulse.schedule) else {
                continue;
            };
            let base = if pulse.last_fired_ms > 0 {
                pulse.last_fired_ms
            } else {
                pulse.created_at_ms.saturating_sub(1)
            };
            let Some(next) = schedule.next_after(base as i64) else {
                continue;
            };
            let fire_at = (next as u64).saturating_add(jitter_ms(&pulse.id));
            if fire_at.saturating_add(OVERDUE_GRACE_MS) < now {
                // Do not replay a backlog after a long stop. Move the cursor to
                // the skipped fire; the next future occurrence will run.
                pulse.last_fired_ms = fire_at;
                changed = true;
                continue;
            }
            if fire_at <= now {
                pulse.last_fired_ms = fire_at;
                changed = true;
                due.push((pulse.clone(), fire_at));
            }
        }
        if changed {
            let _ = self.save();
        }
        due
    }

    fn record_run(&mut self, run: PulseRun) -> Result<(), String> {
        if let Some(parent) = self.runs_path.parent() {
            fs::create_dir_all(parent).map_err(|e| format!("create {}: {e}", parent.display()))?;
        }
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.runs_path)
            .map_err(|e| format!("open {}: {e}", self.runs_path.display()))?;
        let line = serde_json::to_vec(&run).map_err(|e| e.to_string())?;
        file.write_all(&line)
            .and_then(|_| file.write_all(b"\n"))
            .map_err(|e| format!("append {}: {e}", self.runs_path.display()))?;
        // Keep the file bounded without rewriting it on every run.
        if let Ok(metadata) = file.metadata() {
            if metadata.len() > 8 * 1024 * 1024 {
                prune_runs(&self.runs_path);
            }
        }
        Ok(())
    }

    pub(crate) fn runs(&self, pulse_id: Option<&str>, limit: usize) -> Vec<PulseRun> {
        let Ok(text) = fs::read_to_string(&self.runs_path) else {
            return Vec::new();
        };
        let mut runs: Vec<PulseRun> = text
            .lines()
            .filter_map(|line| serde_json::from_str::<PulseRun>(line).ok())
            .filter(|run| pulse_id.is_none_or(|id| run.pulse_id == id))
            .collect();
        runs.reverse();
        runs.truncate(limit.clamp(1, MAX_RUNS));
        runs
    }
}

fn validate(pulse: &UserPulse) -> Result<(), String> {
    if pulse.id.len() > 128 {
        return Err("pulse id is longer than 128 bytes".into());
    }
    if !pulse.id.trim().is_empty()
        && !pulse
            .id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.:".contains(&b))
    {
        return Err("pulse id may contain letters, digits, '-', '_', '.', ':'".into());
    }
    if pulse.command.trim().is_empty() {
        return Err("pulse command is empty".into());
    }
    if pulse.command.len() > MAX_COMMAND_BYTES {
        return Err(format!(
            "pulse command is longer than {MAX_COMMAND_BYTES} bytes"
        ));
    }
    Schedule::parse(&pulse.schedule)
        .map(|_| ())
        .map_err(|problems| {
            problems
                .into_iter()
                .map(|problem| problem.to_string())
                .collect::<Vec<_>>()
                .join("; ")
        })
}

fn next_fire(pulse: &UserPulse, now: i64) -> Option<i64> {
    let schedule = Schedule::parse(&pulse.schedule).ok()?;
    let mut base = if pulse.last_fired_ms > 0 {
        pulse.last_fired_ms
    } else {
        pulse.created_at_ms
    };
    loop {
        let at = schedule.next_after(base as i64)?;
        let fire = at.saturating_add(jitter_ms(&pulse.id) as i64);
        if fire > now {
            return Some(fire);
        }
        base = fire as u64;
    }
}

fn prune_runs(path: &std::path::Path) {
    let Ok(text) = fs::read_to_string(path) else {
        return;
    };
    let lines: Vec<&str> = text.lines().rev().take(5_000).collect();
    let temporary = path.with_extension("jsonl.tmp");
    let mut text = lines.into_iter().rev().collect::<Vec<_>>().join("\n");
    text.push('\n');
    if fs::write(&temporary, text).is_ok() {
        let _ = fs::rename(&temporary, path);
    }
}

/// Run system and user pulses until the daemon exits.
pub(crate) async fn run_system(mesh: Arc<Mesh>) {
    let seed = mesh.pulse_seed();
    for pulse in SYSTEM_PULSES {
        eprintln!(
            "myceliumd: system pulse {} every {:?}",
            pulse.id, pulse.interval
        );
    }
    let mut next_ssh = Instant::now() + startup_offset(seed, &SYSTEM_PULSES[0]);

    loop {
        let now = Instant::now();
        if now >= next_ssh {
            if let Err(error) = mesh.renew_ssh_credentials().await {
                eprintln!("myceliumd: pulse system.ssh-renewal: {error}");
            }
            next_ssh = now + SYSTEM_PULSES[0].interval;
        }

        let due = {
            let mut store = store().lock().await;
            store.due(now_ms())
        };
        for (pulse, scheduled_at_ms) in due {
            run_user_pulse(pulse, scheduled_at_ms).await;
        }
        sleep(TICK).await;
    }
}

async fn run_user_pulse(pulse: UserPulse, scheduled_at_ms: u64) {
    let fired_at_ms = now_ms();
    let result = tokio::time::timeout(
        RUN_TIMEOUT,
        tokio::process::Command::new("sh")
            .arg("-c")
            .arg(&pulse.command)
            .output(),
    )
    .await;

    let (outcome, detail) = match result {
        Ok(Ok(output)) => {
            let mut detail = String::new();
            if !output.stdout.is_empty() {
                detail.push_str(&String::from_utf8_lossy(&output.stdout));
            }
            if !output.stderr.is_empty() {
                if !detail.is_empty() {
                    detail.push_str("\n");
                }
                detail.push_str(&String::from_utf8_lossy(&output.stderr));
            }
            let outcome = if output.status.success() {
                "ok"
            } else {
                "failed"
            };
            (outcome.to_owned(), truncate(detail))
        }
        Ok(Err(error)) => ("failed".to_owned(), format!("spawn: {error}")),
        Err(_) => (
            "failed".to_owned(),
            format!("timeout after {} seconds", RUN_TIMEOUT.as_secs()),
        ),
    };
    let finished_at_ms = now_ms();
    let run = PulseRun {
        id: format!("{}-{fired_at_ms}", pulse.id),
        pulse_id: pulse.id.clone(),
        scheduled_at_ms,
        fired_at_ms,
        finished_at_ms,
        outcome: outcome.clone(),
        detail,
    };
    if let Err(error) = store().lock().await.record_run(run) {
        eprintln!("myceliumd: pulse {}: record run: {error}", pulse.id);
    }
    if outcome != "ok" {
        eprintln!("myceliumd: pulse {} failed", pulse.id);
    }
}

fn truncate(mut detail: String) -> String {
    if detail.len() > MAX_DETAIL_BYTES {
        detail.truncate(MAX_DETAIL_BYTES);
        detail.push_str("\n[truncated]");
    }
    if detail.trim().is_empty() {
        detail = "(no output)".into();
    }
    detail
}

/// The node-derived startup offset for a pulse. A pure function: the scheduler
/// is testable without a `Mesh`, a clock or a runtime.
pub(crate) fn startup_offset(seed: u64, pulse: &SystemPulse) -> Duration {
    let window = pulse.interval.as_secs().max(1);
    Duration::from_secs(seed % window)
}

/// A stable 0..60s offset so two nodes do not fire the same user pulse on the
/// same second. It is deliberately not random: a restart must not move a fire.
pub fn jitter_ms(id: &str) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325_u64;
    for byte in id.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash % 60_000
}

pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn default_true() -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::{jitter_ms, startup_offset, SystemAction, SYSTEM_PULSES};
    use std::time::Duration;

    #[test]
    fn ssh_renewal_is_a_system_pulse() {
        assert!(SYSTEM_PULSES
            .iter()
            .any(|pulse| pulse.id == "system.ssh-renewal"
                && pulse.action == SystemAction::SshRenewal));
    }

    #[test]
    fn startup_offset_is_bounded_and_node_derived() {
        let pulse = SYSTEM_PULSES[0];
        assert_eq!(startup_offset(0, &pulse), Duration::ZERO);
        assert_eq!(startup_offset(31, &pulse), Duration::from_secs(1));
        assert_eq!(startup_offset(255, &pulse), Duration::from_secs(255 % 30));
        assert!(startup_offset(u64::MAX, &pulse) < pulse.interval);
    }

    #[test]
    fn jitter_is_stable_and_bounded() {
        assert_eq!(jitter_ms("nightly"), jitter_ms("nightly"));
        assert!(jitter_ms("nightly") < 60_000);
        assert_ne!(jitter_ms("nightly"), jitter_ms("digest"));
    }
}
