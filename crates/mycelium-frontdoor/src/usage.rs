//! Token accounting for the AI route.
//!
//! The frontdoor is the one choke point every client talks to, so it is the one
//! place that can count tokens regardless of which backend answered. It reads
//! the OpenAI `usage` object the upstream already reports, in a JSON body or in
//! the final SSE event, and records it per route and model. Requests whose
//! upstream reports nothing are counted as unattributed rather than guessed at:
//! an estimate that looks exact is worse than a visible gap.

use mycelium_peer_protocol::frontdoor_usage::{
    FrontdoorUsageSnapshot, TokenCounts, FRONTDOOR_USAGE_SCHEMA_VERSION,
    FRONTDOOR_USAGE_WINDOW_SECONDS,
};
use serde_json::Value;
use std::collections::BTreeMap;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Bound on the model breakdown so a client cannot grow the store with invented
/// model names.
const MAX_MODELS: usize = 64;
/// Bound on one SSE line. Usage events are small; anything larger is not one.
const MAX_SSE_LINE_BYTES: usize = 64 * 1024;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ReportedUsage {
    pub prompt_tokens: u64,
    pub completion_tokens: u64,
    pub cached_tokens: u64,
}

/// What the frontdoor decided to do with one request before forwarding it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Metering {
    /// Not an AI completion request; the response passes through untouched.
    Skip,
    /// Usage arrives in one JSON body.
    Buffered { model: Option<String> },
    /// Usage arrives in the last SSE event.
    Streamed { model: Option<String> },
}

impl Metering {
    pub fn model(&self) -> Option<&str> {
        match self {
            Self::Skip => None,
            Self::Buffered { model } | Self::Streamed { model } => model.as_deref(),
        }
    }
}

/// Decide from the request path and body whether the response can be counted.
/// Parsing the body is also how the frontdoor learns the model; a body that is not
/// JSON is forwarded unmetered instead of failing the request.
pub fn classify(path: &str, body: &[u8]) -> Metering {
    if !path.ends_with("/completions") {
        return Metering::Skip;
    }
    let Ok(value) = serde_json::from_slice::<Value>(body) else {
        return Metering::Skip;
    };
    let model = value
        .get("model")
        .and_then(Value::as_str)
        .map(str::to_owned);
    if value.get("stream").and_then(Value::as_bool) == Some(true) {
        Metering::Streamed { model }
    } else {
        Metering::Buffered { model }
    }
}

/// Ask a streaming upstream to close with a usage event. Without it the frontdoor
/// sees generated text but no token counts. An explicit client choice is kept.
pub fn with_stream_usage(body: &[u8]) -> Option<Vec<u8>> {
    let mut value: Value = serde_json::from_slice(body).ok()?;
    let object = value.as_object_mut()?;
    if object.get("stream").and_then(Value::as_bool) != Some(true) {
        return None;
    }
    let options = object
        .entry("stream_options")
        .or_insert_with(|| Value::Object(Default::default()))
        .as_object_mut()?;
    if options.contains_key("include_usage") {
        return None;
    }
    options.insert("include_usage".into(), Value::Bool(true));
    serde_json::to_vec(&value).ok()
}

/// Read the `usage` object of one OpenAI-compatible response.
pub fn reported_usage(value: &Value) -> Option<ReportedUsage> {
    let usage = value.get("usage")?;
    if !usage.is_object() {
        return None;
    }
    let count = |key: &str| usage.get(key).and_then(Value::as_u64).unwrap_or(0);
    let cached = usage
        .pointer("/prompt_tokens_details/cached_tokens")
        .and_then(Value::as_u64)
        .or_else(|| usage.get("prompt_cache_hit_tokens").and_then(Value::as_u64))
        .unwrap_or(0);
    Some(ReportedUsage {
        prompt_tokens: count("prompt_tokens"),
        completion_tokens: count("completion_tokens"),
        cached_tokens: cached,
    })
}

/// Incremental reader for the usage event of an SSE completion stream.
#[derive(Debug, Default)]
pub struct StreamUsage {
    pending: Vec<u8>,
    line_too_long: bool,
    usage: Option<ReportedUsage>,
}

impl StreamUsage {
    /// Feed bytes as they pass through. The relay keeps forwarding them
    /// untouched; this only watches the same bytes.
    pub fn feed(&mut self, chunk: &[u8]) {
        if self.line_too_long {
            return;
        }
        for byte in chunk {
            if *byte == b'\n' {
                let mut line = std::mem::take(&mut self.pending);
                if line.last() == Some(&b'\r') {
                    line.pop();
                }
                self.take_line(&line);
            } else if self.pending.len() < MAX_SSE_LINE_BYTES {
                self.pending.push(*byte);
            } else {
                // A line this long is not an SSE usage event. Stop watching
                // instead of buffering an unbounded body.
                self.line_too_long = true;
                self.pending = Vec::new();
            }
        }
    }

    fn take_line(&mut self, line: &[u8]) {
        let Some(payload) = line.strip_prefix(b"data:") else {
            return;
        };
        let payload = match payload.first() {
            Some(b' ') => &payload[1..],
            _ => payload,
        };
        let Ok(value) = serde_json::from_slice::<Value>(payload) else {
            return;
        };
        // Every usage-bearing event carries the running totals, so the last one
        // wins. Keeping the maximum would report double for split events.
        if let Some(usage) = reported_usage(&value) {
            self.usage = Some(usage);
        }
    }

    pub fn finish(self) -> Option<ReportedUsage> {
        self.usage
    }
}

#[derive(Debug, Default)]
struct UsageMeter {
    totals: TokenCounts,
    routes: BTreeMap<String, TokenCounts>,
    models: BTreeMap<String, TokenCounts>,
    /// Per-second buckets, pruned to the reporting window.
    buckets: BTreeMap<u64, TokenCounts>,
    dirty: bool,
}

impl UsageMeter {
    fn record(
        &mut self,
        route: &str,
        model: Option<&str>,
        usage: Option<ReportedUsage>,
        elapsed: Duration,
    ) {
        let counts = match usage {
            Some(usage) => TokenCounts {
                requests: 1,
                metered_requests: 1,
                prompt_tokens: usage.prompt_tokens,
                completion_tokens: usage.completion_tokens,
                cached_tokens: usage.cached_tokens,
                generation_millis: elapsed.as_millis().min(u64::MAX as u128) as u64,
            },
            None => TokenCounts {
                requests: 1,
                ..TokenCounts::default()
            },
        };
        self.totals.add(&counts);
        self.routes
            .entry(route.to_owned())
            .or_default()
            .add(&counts);
        if let Some(model) = model {
            if self.models.contains_key(model) || self.models.len() < MAX_MODELS {
                self.models
                    .entry(model.to_owned())
                    .or_default()
                    .add(&counts);
            }
        }
        let second = now();
        self.buckets.entry(second).or_default().add(&counts);
        let oldest = second.saturating_sub(FRONTDOOR_USAGE_WINDOW_SECONDS);
        while self.buckets.keys().next().is_some_and(|at| *at < oldest) {
            let key = *self.buckets.keys().next().unwrap();
            self.buckets.remove(&key);
        }
        self.dirty = true;
    }

    fn snapshot(&self) -> FrontdoorUsageSnapshot {
        let second = now();
        let oldest = second.saturating_sub(FRONTDOOR_USAGE_WINDOW_SECONDS);
        let mut window = TokenCounts::default();
        for (at, counts) in &self.buckets {
            if *at >= oldest {
                window.add(counts);
            }
        }
        FrontdoorUsageSnapshot {
            schema_version: FRONTDOOR_USAGE_SCHEMA_VERSION,
            generated_at: second,
            window_seconds: FRONTDOOR_USAGE_WINDOW_SECONDS,
            totals: self.totals,
            window,
            routes: self.routes.clone(),
            models: self.models.clone(),
        }
    }
}

/// Shared meter plus the file the daemon reads to gossip these counters.
pub struct UsageStore {
    path: Option<PathBuf>,
    meter: Mutex<UsageMeter>,
}

impl UsageStore {
    /// Continue from the totals a previous frontdoor process left on disk. The
    /// throughput window starts empty: a restart is not current traffic.
    pub fn open(path: Option<PathBuf>) -> Self {
        let meter = path
            .as_deref()
            .and_then(read_snapshot)
            .map(|snapshot| UsageMeter {
                totals: snapshot.totals,
                routes: snapshot.routes,
                models: snapshot.models,
                ..UsageMeter::default()
            })
            .unwrap_or_default();
        Self {
            path,
            meter: Mutex::new(meter),
        }
    }

    pub fn record(
        &self,
        route: &str,
        model: Option<&str>,
        usage: Option<ReportedUsage>,
        elapsed: Duration,
    ) {
        self.meter
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .record(route, model, usage, elapsed);
    }

    pub fn snapshot(&self) -> FrontdoorUsageSnapshot {
        self.meter
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .snapshot()
    }

    /// Write the snapshot when something changed. Returns whether a write
    /// happened, so the caller can stay quiet between idle periods.
    pub fn persist(&self) -> io::Result<bool> {
        let Some(path) = self.path.as_deref() else {
            return Ok(false);
        };
        let snapshot = {
            let mut meter = self
                .meter
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if !meter.dirty {
                return Ok(false);
            }
            meter.dirty = false;
            meter.snapshot()
        };
        let encoded = serde_json::to_vec(&snapshot)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        write_atomically(path, &encoded)?;
        Ok(true)
    }
}

fn read_snapshot(path: &Path) -> Option<FrontdoorUsageSnapshot> {
    let bytes = std::fs::read(path).ok()?;
    let snapshot: FrontdoorUsageSnapshot = serde_json::from_slice(&bytes).ok()?;
    (snapshot.schema_version == FRONTDOOR_USAGE_SCHEMA_VERSION).then_some(snapshot)
}

fn write_atomically(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(parent)?;
    let temporary = parent.join(format!(
        ".{}.tmp",
        path.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("usage")
    ));
    std::fs::write(&temporary, bytes)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&temporary, std::fs::Permissions::from_mode(0o600))?;
    }
    // Rename keeps readers from seeing a half-written document.
    std::fs::rename(&temporary, path)
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn only_completion_paths_are_metered() {
        assert_eq!(
            classify("/v1/chat/completions", br#"{"model":"m"}"#),
            Metering::Buffered {
                model: Some("m".into())
            }
        );
        assert!(matches!(
            classify("/v1/completions", br#"{"model":"m","stream":true}"#),
            Metering::Streamed { .. }
        ));
        assert_eq!(classify("/v1/models", b""), Metering::Skip);
        assert_eq!(classify("/health", b"not json"), Metering::Skip);
    }

    #[test]
    fn stream_usage_is_requested_only_when_the_client_left_it_open() {
        let injected = with_stream_usage(br#"{"model":"m","stream":true}"#).unwrap();
        let value: Value = serde_json::from_slice(&injected).unwrap();
        assert_eq!(value["stream_options"]["include_usage"], json!(true));
        assert_eq!(with_stream_usage(br#"{"model":"m"}"#), None);
        assert_eq!(
            with_stream_usage(br#"{"stream":true,"stream_options":{"include_usage":false}}"#),
            None
        );
    }

    #[test]
    fn reads_usage_from_a_body_or_a_stream() {
        let body = json!({"usage":{"prompt_tokens":11,"completion_tokens":7,
            "prompt_tokens_details":{"cached_tokens":5}}});
        assert_eq!(
            reported_usage(&body),
            Some(ReportedUsage {
                prompt_tokens: 11,
                completion_tokens: 7,
                cached_tokens: 5
            })
        );
        assert_eq!(reported_usage(&json!({"choices":[]})), None);

        let mut stream = StreamUsage::default();
        for chunk in [
            &br#"data: {"choices":[{"delta":{"content":"h"}}]}

"#[..],
            &br#"data: {"choices":[],"usage":{"prompt_tokens":3,"completion_tokens":"#[..],
        ] {
            stream.feed(chunk);
        }
        // A usage event split across network chunks still parses once complete.
        stream.feed(
            br#"9,"total_tokens":12}}

"#,
        );
        stream.feed(b"data: [DONE]\n\n");
        assert_eq!(
            stream.finish(),
            Some(ReportedUsage {
                prompt_tokens: 3,
                completion_tokens: 9,
                cached_tokens: 0
            })
        );
    }

    #[test]
    fn a_stream_without_usage_is_unmetered() {
        let mut stream = StreamUsage::default();
        stream.feed(
            br#"data: {"choices":[{"delta":{"content":"hi"}}]}

"#,
        );
        assert_eq!(stream.finish(), None);
    }

    #[test]
    fn counters_split_by_route_and_model_and_bucket_by_second() {
        let store = UsageStore::open(None);
        store.record(
            "ai",
            Some("fpl/coder"),
            Some(ReportedUsage {
                prompt_tokens: 10,
                completion_tokens: 20,
                cached_tokens: 4,
            }),
            Duration::from_millis(1_000),
        );
        store.record("ai", Some("fpl/coder"), None, Duration::from_millis(5));
        let snapshot = store.snapshot();
        assert_eq!(snapshot.totals.requests, 2);
        assert_eq!(snapshot.totals.metered_requests, 1);
        assert_eq!(snapshot.totals.completion_tokens, 20);
        assert_eq!(snapshot.totals.unmetered_requests(), 1);
        assert_eq!(snapshot.routes["ai"].requests, 2);
        assert_eq!(snapshot.models["fpl/coder"].requests, 2);
        assert_eq!(snapshot.window.requests, 2);
        assert_eq!(snapshot.schema_version, FRONTDOOR_USAGE_SCHEMA_VERSION);
    }

    #[test]
    fn persisted_totals_survive_a_restart_but_the_window_does_not() {
        let dir = std::env::temp_dir().join(format!("mycelium-usage-{}", std::process::id()));
        let path = dir.join("usage.json");
        let _ = std::fs::remove_dir_all(&dir);
        let store = UsageStore::open(Some(path.clone()));
        store.record(
            "ai",
            None,
            Some(ReportedUsage {
                prompt_tokens: 2,
                completion_tokens: 3,
                cached_tokens: 0,
            }),
            Duration::from_millis(100),
        );
        assert!(store.persist().unwrap());
        assert!(!store.persist().unwrap());

        let restarted = UsageStore::open(Some(path));
        let snapshot = restarted.snapshot();
        assert_eq!(snapshot.totals.completion_tokens, 3);
        assert_eq!(snapshot.window.requests, 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_foreign_schema_is_ignored_rather_than_reinterpreted() {
        let dir =
            std::env::temp_dir().join(format!("mycelium-usage-schema-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("usage.json");
        std::fs::write(
            &path,
            serde_json::to_vec(&json!({"schema_version":99,"totals":{"requests":7}})).unwrap(),
        )
        .unwrap();
        assert_eq!(UsageStore::open(Some(path)).snapshot().totals.requests, 0);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
