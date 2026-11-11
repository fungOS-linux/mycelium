//! Which nodes should carry public ingress.
//!
//! Eligibility is a property of the machine, not a permission: no grant is
//! involved. The score answers one question - would putting public traffic on
//! this host make the fleet worse? - and the reasons are kept so an operator
//! can see why a node ranked where it did.

use crate::{HostHealth, LinkKind, PowerSource};
use serde::{Deserialize, Serialize};

/// A host that has not stayed up for an hour is still settling: it is either
/// coming out of a reboot or it is not a server.
pub const MIN_UPTIME_SECONDS: u64 = 3_600;

/// A health snapshot older than this is not evidence about anything.
pub const MAX_SNAPSHOT_AGE_SECONDS: u64 = 120;

/// Twenty-eight days of uptime is as much as the score rewards.
const FULL_UPTIME_SECONDS: f64 = 28.0 * 24.0 * 3_600.0;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct EdgeProfile {
    /// Whether this node may carry public ingress at all.
    pub eligible: bool,
    /// 0.0 (worst) to 1.0 (best). Only meaningful when `eligible`.
    pub score: f32,
    /// Why the node is excluded, or what limits its score.
    pub reasons: Vec<String>,
}

/// Score one host for public ingress.
///
/// Exclusions are absolute: battery power, a wireless link, a host that has not
/// held a connection for an hour, or a snapshot too old to describe anything.
/// Everything else only lowers the score.
pub fn edge_profile(health: &HostHealth, now: u64) -> EdgeProfile {
    let mut reasons = Vec::new();
    let mut eligible = true;

    match health.power {
        PowerSource::Battery => {
            eligible = false;
            reasons.push("battery power".to_owned());
        }
        PowerSource::Unknown => reasons.push("power source unknown".to_owned()),
        PowerSource::Mains => {}
    }
    match health.link {
        LinkKind::Wireless => {
            eligible = false;
            reasons.push("wireless link".to_owned());
        }
        LinkKind::Unknown => reasons.push("link kind unknown".to_owned()),
        LinkKind::Wired => {}
    }
    if health.uptime_seconds < MIN_UPTIME_SECONDS {
        eligible = false;
        reasons.push(format!(
            "uptime {}s is below the {}s floor",
            health.uptime_seconds, MIN_UPTIME_SECONDS
        ));
    }
    let age = now.saturating_sub(health.observed_at);
    if age > MAX_SNAPSHOT_AGE_SECONDS {
        eligible = false;
        reasons.push(format!("health snapshot is {age}s old"));
    }

    let uptime =
        (health.uptime_seconds as f64).min(FULL_UPTIME_SECONDS) / FULL_UPTIME_SECONDS;
    let load = if health.logical_cpus == 0 {
        1.0
    } else {
        (health.load_average[0] / health.logical_cpus as f64).clamp(0.0, 1.0)
    };
    let headroom = 1.0 - load;
    let memory = if health.memory_total_bytes == 0 {
        0.0
    } else {
        (health.memory_available_bytes as f64 / health.memory_total_bytes as f64).clamp(0.0, 1.0)
    };
    // Uptime dominates because it is the only signal that predicts the next
    // hour; load and memory only describe this instant.
    let score = (0.6 * uptime + 0.2 * headroom + 0.2 * memory) as f32;

    if eligible && score < 0.5 {
        reasons.push(format!("low score {score:.2}"));
    }

    EdgeProfile {
        eligible,
        score,
        reasons,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn host(power: PowerSource, link: LinkKind, uptime: u64) -> HostHealth {
        HostHealth {
            observed_at: 1_000,
            uptime_seconds: uptime,
            load_average: [0.1, 0.1, 0.1],
            logical_cpus: 4,
            memory_total_bytes: 8 * 1024 * 1024 * 1024,
            memory_available_bytes: 6 * 1024 * 1024 * 1024,
            swap_total_bytes: 0,
            swap_free_bytes: 0,
            filesystems: Vec::new(),
            process_leaders: Vec::new(),
            ssh_listening: true,
            established_ssh_sessions: 0,
            power,
            link,
            platform_metrics: Default::default(),
        }
    }

    #[test]
    fn battery_and_wireless_hosts_are_never_ingress_candidates() {
        let battery = edge_profile(&host(PowerSource::Battery, LinkKind::Wired, 90 * 86_400), 1_000);
        assert!(!battery.eligible);
        assert!(battery.reasons.iter().any(|reason| reason.contains("battery")));

        let wireless = edge_profile(&host(PowerSource::Mains, LinkKind::Wireless, 90 * 86_400), 1_000);
        assert!(!wireless.eligible);
        assert!(wireless.reasons.iter().any(|reason| reason.contains("wireless")));
    }

    #[test]
    fn a_host_that_has_not_held_an_hour_is_excluded() {
        let profile = edge_profile(&host(PowerSource::Mains, LinkKind::Wired, 3_599), 1_000);
        assert!(!profile.eligible);
        assert!(profile.reasons.iter().any(|reason| reason.contains("uptime")));
    }

    #[test]
    fn a_stale_snapshot_describes_nothing() {
        let profile = edge_profile(&host(PowerSource::Mains, LinkKind::Wired, 30 * 86_400), 1_121);
        assert!(!profile.eligible);
        assert!(profile.reasons.iter().any(|reason| reason.contains("old")));
    }

    #[test]
    fn a_long_lived_wired_host_outranks_a_fresh_one() {
        let settled = edge_profile(&host(PowerSource::Mains, LinkKind::Wired, 21 * 86_400), 1_000);
        let fresh = edge_profile(&host(PowerSource::Mains, LinkKind::Wired, 2 * 3_600), 1_000);
        assert!(settled.eligible && fresh.eligible);
        assert!(settled.score > fresh.score);
        assert!(settled.score > 0.6, "settled score {}", settled.score);
    }

    #[test]
    fn load_only_lowers_the_score() {
        let mut idle = host(PowerSource::Mains, LinkKind::Wired, 7 * 86_400);
        let mut busy = idle.clone();
        busy.load_average = [4.0, 4.0, 4.0];
        idle.load_average = [0.0, 0.0, 0.0];
        let idle = edge_profile(&idle, 1_000);
        let busy = edge_profile(&busy, 1_000);
        assert!(idle.eligible && busy.eligible);
        assert!(idle.score > busy.score);
    }

    #[test]
    fn unknown_power_does_not_exclude_but_says_so() {
        let profile = edge_profile(&host(PowerSource::Unknown, LinkKind::Unknown, 30 * 86_400), 1_000);
        assert!(profile.eligible);
        assert_eq!(profile.reasons.len(), 2);
    }
}
