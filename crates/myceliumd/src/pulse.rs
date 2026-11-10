//! The daemon's scheduled work.
//!
//! SSH renewal is the first **system pulse**: a node-local task with a fixed
//! interval and a startup offset derived from the node key. It used to be its
//! own loop in `Peer::start`; putting it here gives the daemon one place to
//! schedule system work and, later, the user/desktop pulses layered on top.
//!
//! This module owns the clock and the jitter. It does not own delivery: a
//! user pulse will be a record whose action is dispatched through the same
//! scheduler, while system pulses call daemon methods directly.

use std::sync::Arc;
use std::time::Duration;

use tokio::time::{sleep_until, Instant};

use crate::peer::Mesh;

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

/// System pulse config. A user/desktop pulse store will be loaded beside this
/// table, not replace it.
pub const SYSTEM_PULSES: [SystemPulse; 1] = [SystemPulse {
    id: "system.ssh-renewal",
    interval: Duration::from_secs(30),
    action: SystemAction::SshRenewal,
}];

/// Run the system pulses until the daemon exits.
///
/// The first tick is delayed by a node-key-derived offset so a fleet that
/// starts together does not renew in lockstep. `token` is bounded to keep a
/// bad key from delaying the first renewal indefinitely.
pub async fn run_system(mesh: Arc<Mesh>) {
    let seed = mesh.pulse_seed();
    for pulse in SYSTEM_PULSES {
        eprintln!(
            "myceliumd: system pulse {} every {:?}",
            pulse.id, pulse.interval
        );
    }
    let mut next: Vec<Instant> = SYSTEM_PULSES
        .iter()
        .map(|pulse| Instant::now() + startup_offset(seed, pulse))
        .collect();

    loop {
        // SAFETY: SYSTEM_PULSES and next are built from the same table and
        // always have at least one entry.
        let (index, at) = next
            .iter()
            .enumerate()
            .min_by_key(|(_, at)| **at)
            .expect("system pulse table is non-empty");
        sleep_until(*at).await;

        let pulse = SYSTEM_PULSES[index];
        match pulse.action {
            SystemAction::SshRenewal => {
                if let Err(error) = mesh.renew_ssh_credentials().await {
                    eprintln!("myceliumd: pulse {}: {error}", pulse.id);
                }
            }
        }

        next[index] = Instant::now() + pulse.interval;
    }
}

/// The node-derived startup offset for a pulse. This is deliberately a pure
/// function: the scheduler is testable without a `Peer`, a clock or a runtime.
pub(crate) fn startup_offset(seed: u64, pulse: &SystemPulse) -> Duration {
    let window = pulse.interval.as_secs().max(1);
    Duration::from_secs(seed % window)
}

#[cfg(test)]
mod tests {
    use super::{startup_offset, SystemAction, SYSTEM_PULSES};
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
}
