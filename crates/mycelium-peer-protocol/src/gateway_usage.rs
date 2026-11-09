//! Token accounting that the local `mycelium-gateway` writes to
//! `$MYCELIUM_HOME/gateway/usage.json` and `myceliumd` republishes in gossiped
//! `platform_metrics`.
//!
//! One definition, three readers: the gateway fills it in, the daemon flattens
//! it into peer-visible metrics, and the CLI aggregates it across the fleet. The
//! schema is versioned because a rolled-back binary must not misread counters
//! written by a newer one.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

pub const GATEWAY_USAGE_SCHEMA_VERSION: u16 = 1;

/// Window used for throughput. Long enough to stop a single slow request from
/// looking like idle, short enough to answer "what is the fleet doing now".
pub const GATEWAY_USAGE_WINDOW_SECONDS: u64 = 60;

/// A usage snapshot older than this is no longer presented as current. A
/// gateway that stopped running must not look like a fleet that went quiet.
pub const GATEWAY_USAGE_MAX_AGE_SECONDS: u64 = 600;

pub const METRIC_PREFIX: &str = "mycelium_ai.";

#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, Eq, Serialize)]
#[serde(default)]
pub struct TokenCounts {
    /// Responses that reached the client successfully. Failures are not usage.
    pub requests: u64,
    /// Subset of `requests` whose upstream reported token counts.
    pub metered_requests: u64,
    pub prompt_tokens: u64,
    pub completion_tokens: u64,
    /// Prompt tokens the upstream billed as cache hits.
    pub cached_tokens: u64,
    /// End-to-end response time of metered requests, used for throughput that
    /// ignores idle time.
    pub generation_millis: u64,
}

impl TokenCounts {
    pub fn unmetered_requests(&self) -> u64 {
        self.requests.saturating_sub(self.metered_requests)
    }

    pub fn tokens(&self) -> u64 {
        self.prompt_tokens + self.completion_tokens
    }

    pub fn add(&mut self, other: &Self) {
        self.requests += other.requests;
        self.metered_requests += other.metered_requests;
        self.prompt_tokens += other.prompt_tokens;
        self.completion_tokens += other.completion_tokens;
        self.cached_tokens += other.cached_tokens;
        self.generation_millis += other.generation_millis;
    }

    /// Completion tokens per second of wall clock. Zero when nothing ran.
    pub fn tokens_per_second(&self, window_seconds: u64) -> f64 {
        if window_seconds == 0 {
            return 0.0;
        }
        self.completion_tokens as f64 / window_seconds as f64
    }

    /// Completion tokens per second while a request was in flight.
    pub fn generation_tokens_per_second(&self) -> f64 {
        if self.generation_millis == 0 {
            return 0.0;
        }
        self.completion_tokens as f64 * 1000.0 / self.generation_millis as f64
    }
}

/// What one gateway published about its own machine.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
#[serde(default)]
pub struct GatewayUsageSnapshot {
    pub schema_version: u16,
    pub generated_at: u64,
    pub window_seconds: u64,
    pub totals: TokenCounts,
    pub window: TokenCounts,
    pub routes: BTreeMap<String, TokenCounts>,
    pub models: BTreeMap<String, TokenCounts>,
}

/// The subset small enough to gossip with every heartbeat: scalars only, no
/// per-route maps that would grow the topology.
#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, Serialize)]
#[serde(default)]
pub struct GatewayUsageMetrics {
    pub updated_at: u64,
    pub window_seconds: u64,
    pub totals: TokenCounts,
    pub window: TokenCounts,
}

impl GatewayUsageMetrics {
    pub fn from_snapshot(snapshot: &GatewayUsageSnapshot) -> Self {
        Self {
            updated_at: snapshot.generated_at,
            window_seconds: snapshot.window_seconds,
            totals: snapshot.totals,
            window: snapshot.window,
        }
    }

    pub fn tokens_per_second(&self) -> f64 {
        self.window.tokens_per_second(self.window_seconds)
    }

    pub fn generation_tokens_per_second(&self) -> f64 {
        self.window.generation_tokens_per_second()
    }

    /// True when the numbers still describe a running gateway.
    pub fn is_fresh(&self, now: u64) -> bool {
        self.updated_at != 0 && now.saturating_sub(self.updated_at) <= GATEWAY_USAGE_MAX_AGE_SECONDS
    }

    pub fn to_platform_metrics(&self) -> BTreeMap<String, String> {
        let mut metrics = BTreeMap::new();
        metrics.insert(
            format!("{METRIC_PREFIX}updated_at"),
            self.updated_at.to_string(),
        );
        metrics.insert(
            format!("{METRIC_PREFIX}window_seconds"),
            self.window_seconds.to_string(),
        );
        for (suffix, counts) in [("", &self.totals), ("window_", &self.window)] {
            for (field, value) in [
                ("requests", counts.requests),
                ("metered_requests", counts.metered_requests),
                ("prompt_tokens", counts.prompt_tokens),
                ("completion_tokens", counts.completion_tokens),
                ("cached_tokens", counts.cached_tokens),
                ("generation_millis", counts.generation_millis),
            ] {
                metrics.insert(format!("{METRIC_PREFIX}{suffix}{field}"), value.to_string());
            }
        }
        metrics
    }

    /// Rebuild metrics from one peer's `platform_metrics`. Returns `None` when
    /// the peer runs no gateway or gossiped nothing this schema understands.
    pub fn from_platform_metrics(metrics: &BTreeMap<String, String>) -> Option<Self> {
        let read = |suffix: &str| -> u64 {
            metrics
                .get(&format!("{METRIC_PREFIX}{suffix}"))
                .and_then(|value| value.parse().ok())
                .unwrap_or(0)
        };
        let updated_at = read("updated_at");
        if updated_at == 0 {
            return None;
        }
        let counts = |prefix: &str| TokenCounts {
            requests: read(&format!("{prefix}requests")),
            metered_requests: read(&format!("{prefix}metered_requests")),
            prompt_tokens: read(&format!("{prefix}prompt_tokens")),
            completion_tokens: read(&format!("{prefix}completion_tokens")),
            cached_tokens: read(&format!("{prefix}cached_tokens")),
            generation_millis: read(&format!("{prefix}generation_millis")),
        };
        Some(Self {
            updated_at,
            window_seconds: read("window_seconds"),
            totals: counts(""),
            window: counts("window_"),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn counts() -> TokenCounts {
        TokenCounts {
            requests: 4,
            metered_requests: 3,
            prompt_tokens: 400,
            completion_tokens: 120,
            cached_tokens: 100,
            generation_millis: 4_000,
        }
    }

    #[test]
    fn metrics_round_trip_through_gossip_strings() {
        let metrics = GatewayUsageMetrics {
            updated_at: 1_700_000_000,
            window_seconds: 60,
            totals: counts(),
            window: counts(),
        };
        let gossiped = metrics.to_platform_metrics();
        assert_eq!(
            gossiped
                .get("mycelium_ai.completion_tokens")
                .map(String::as_str),
            Some("120")
        );
        assert_eq!(
            GatewayUsageMetrics::from_platform_metrics(&gossiped),
            Some(metrics)
        );
    }

    #[test]
    fn hosts_without_a_gateway_report_nothing() {
        let mut metrics = BTreeMap::new();
        metrics.insert("pressure_cpu".into(), "some cpu=avg10=0".into());
        assert_eq!(GatewayUsageMetrics::from_platform_metrics(&metrics), None);
    }

    #[test]
    fn rates_ignore_idle_time_and_are_zero_without_traffic() {
        assert!((counts().tokens_per_second(60) - 2.0).abs() < 1e-9);
        assert!((counts().generation_tokens_per_second() - 30.0).abs() < 1e-9);
        assert_eq!(TokenCounts::default().tokens_per_second(60), 0.0);
        assert_eq!(TokenCounts::default().generation_tokens_per_second(), 0.0);
    }

    #[test]
    fn fleet_totals_are_the_sum_of_machines() {
        let mut total = TokenCounts::default();
        total.add(&counts());
        total.add(&counts());
        assert_eq!(total.requests, 8);
        assert_eq!(total.tokens(), 1_040);
    }

    #[test]
    fn stale_snapshots_are_not_current() {
        let metrics = GatewayUsageMetrics {
            updated_at: 100,
            window_seconds: 60,
            ..GatewayUsageMetrics::default()
        };
        assert!(metrics.is_fresh(200));
        assert!(!metrics.is_fresh(100 + GATEWAY_USAGE_MAX_AGE_SECONDS + 1));
        assert!(!GatewayUsageMetrics::default().is_fresh(100));
    }
}
