//! Durable, explicit export of converged security events.
//!
//! Gossip carries signed facts. This module alone owns delivery side effects:
//! events enter a bounded spool before a sink is contacted and are marked
//! delivered only after the sink confirms success.

use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};

use mycelium_peer_protocol::{SecurityEvent, SecurityEventBatch};
use serde::{Deserialize, Serialize};

type AnyError = Box<dyn std::error::Error + Send + Sync>;
const MAX_PENDING: usize = 4096;
const MAX_DELIVERED: usize = 16384;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SinkConfig {
    Jsonl {
        name: String,
        path: PathBuf,
    },
    Loki {
        name: String,
        url: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        token_env: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        tenant: Option<String>,
    },
    /// Publish structured events to the nearest MQTT broker. Unibus remains
    /// responsible for carrying those publications between brokers.
    Mqtt {
        name: String,
        host: String,
        #[serde(default = "default_mqtt_port")]
        port: u16,
        topic: String,
        client_id: String,
        #[serde(default)]
        tls: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        username_env: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        password_env: Option<String>,
    },
}

fn default_mqtt_port() -> u16 {
    1883
}

impl SinkConfig {
    pub fn name(&self) -> &str {
        match self {
            Self::Jsonl { name, .. } | Self::Loki { name, .. } | Self::Mqtt { name, .. } => name,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExportRecord {
    pub schema_version: u16,
    pub delivery_id: String,
    pub node_id: String,
    pub hostname: String,
    pub site: String,
    #[serde(flatten)]
    pub event: SecurityEvent,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct SinkState {
    #[serde(default)]
    pending: BTreeMap<String, ExportRecord>,
    #[serde(default)]
    delivered: BTreeMap<String, u64>,
    last_success_at: Option<u64>,
    last_error: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct State {
    #[serde(default)]
    sinks: BTreeMap<String, SinkState>,
}

#[derive(Clone, Debug, Serialize)]
pub struct SinkStatus {
    pub name: String,
    pub kind: String,
    pub pending: usize,
    pub delivered_retained: usize,
    pub last_success_at: Option<u64>,
    pub last_error: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ExportResult {
    pub sink: String,
    pub queued: usize,
    pub delivered: usize,
    pub dry_run: bool,
}

fn config_path() -> PathBuf {
    crate::siem_dir().join("sinks.json")
}
fn state_path() -> PathBuf {
    crate::siem_dir().join("state.json")
}
fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn read_json<T: serde::de::DeserializeOwned + Default>(path: &Path) -> Result<T, AnyError> {
    match std::fs::read(path) {
        Ok(bytes) => Ok(serde_json::from_slice(&bytes)?),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(T::default()),
        Err(error) => Err(error.into()),
    }
}

fn write_json<T: Serialize>(path: &Path, value: &T) -> Result<(), AnyError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let temporary = path.with_extension(format!("tmp-{}", std::process::id()));
    std::fs::write(&temporary, serde_json::to_vec_pretty(value)?)?;
    std::fs::rename(temporary, path)?;
    Ok(())
}

pub fn list() -> Result<Vec<SinkConfig>, AnyError> {
    read_json(&config_path())
}

pub fn add(config: SinkConfig, write: bool, dry_run: bool) -> Result<SinkConfig, AnyError> {
    validate(&config)?;
    if dry_run {
        return Ok(config);
    }
    if !write {
        return Err("adding a SIEM sink requires --write".into());
    }
    let mut configs = list()?;
    configs.retain(|value| value.name() != config.name());
    configs.push(config.clone());
    configs.sort_by(|a, b| a.name().cmp(b.name()));
    write_json(&config_path(), &configs)?;
    Ok(config)
}

fn validate(config: &SinkConfig) -> Result<(), AnyError> {
    if config.name().trim().is_empty() {
        return Err("sink name cannot be empty".into());
    }
    match config {
        SinkConfig::Jsonl { path, .. } if !path.is_absolute() => {
            Err("JSONL path must be absolute".into())
        }
        SinkConfig::Loki { url, token_env, .. } => {
            let parsed = reqwest::Url::parse(url)?;
            if !matches!(parsed.scheme(), "http" | "https") {
                return Err("Loki URL must use http or https".into());
            }
            if token_env.as_ref().is_some_and(|v| v.trim().is_empty()) {
                return Err("token env name cannot be empty".into());
            }
            Ok(())
        }
        SinkConfig::Mqtt {
            host,
            port,
            topic,
            client_id,
            username_env,
            password_env,
            ..
        } => {
            if host.trim().is_empty() {
                return Err("MQTT host cannot be empty".into());
            }
            if *port == 0 {
                return Err("MQTT port cannot be zero".into());
            }
            if topic.is_empty() || topic.contains(['#', '+', '\0']) {
                return Err("MQTT topic must be a concrete topic without wildcards".into());
            }
            if client_id.trim().is_empty() {
                return Err("MQTT client ID cannot be empty".into());
            }
            if username_env.is_some() != password_env.is_some() {
                return Err(
                    "MQTT username and password env names must be configured together".into(),
                );
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

fn flatten(batches: &[SecurityEventBatch]) -> Vec<ExportRecord> {
    let mut records = Vec::new();
    for batch in batches {
        for event in &batch.events {
            records.push(ExportRecord {
                schema_version: 1,
                delivery_id: mycelium_peer_protocol::sha256_hex(
                    format!("{}\0{}", batch.node_id, event.id).as_bytes(),
                ),
                node_id: batch.node_id.clone(),
                hostname: batch.hostname.clone(),
                site: batch.site.clone(),
                event: event.clone(),
            });
        }
    }
    records.sort_by(|a, b| a.delivery_id.cmp(&b.delivery_id));
    records
}

pub fn status() -> Result<Vec<SinkStatus>, AnyError> {
    let state: State = read_json(&state_path())?;
    Ok(list()?
        .into_iter()
        .map(|config| {
            let value = state.sinks.get(config.name()).cloned().unwrap_or_default();
            SinkStatus {
                name: config.name().into(),
                kind: match config {
                    SinkConfig::Jsonl { .. } => "jsonl",
                    SinkConfig::Loki { .. } => "loki",
                    SinkConfig::Mqtt { .. } => "mqtt",
                }
                .into(),
                pending: value.pending.len(),
                delivered_retained: value.delivered.len(),
                last_success_at: value.last_success_at,
                last_error: value.last_error,
            }
        })
        .collect())
}

pub async fn export(
    batches: &[SecurityEventBatch],
    selected: Option<&str>,
    dry_run: bool,
    write: bool,
) -> Result<Vec<ExportResult>, AnyError> {
    if !dry_run && !write {
        return Err("SIEM export requires --write (or --dry-run)".into());
    }
    let configs = list()?
        .into_iter()
        .filter(|c| selected.is_none_or(|name| name == c.name()))
        .collect::<Vec<_>>();
    if let Some(name) = selected {
        if configs.is_empty() {
            return Err(format!("unknown SIEM sink `{name}`").into());
        }
    }
    let records = flatten(batches);
    let mut state: State = read_json(&state_path())?;
    let mut results = Vec::new();
    for config in configs {
        let queued = {
            let sink = state.sinks.entry(config.name().into()).or_default();
            let queued = records
                .iter()
                .filter(|record| {
                    !sink.delivered.contains_key(&record.delivery_id)
                        && !sink.pending.contains_key(&record.delivery_id)
                })
                .count();
            if sink.pending.len() + queued > MAX_PENDING {
                return Err(format!("SIEM spool for `{}` is full ({MAX_PENDING}); delivery must recover before accepting more events", config.name()).into());
            }
            if !dry_run {
                for record in &records {
                    if !sink.delivered.contains_key(&record.delivery_id) {
                        sink.pending
                            .entry(record.delivery_id.clone())
                            .or_insert_with(|| record.clone());
                    }
                }
            }
            queued
        };
        if dry_run {
            results.push(ExportResult {
                sink: config.name().into(),
                queued,
                delivered: 0,
                dry_run: true,
            });
            continue;
        }
        write_json(&state_path(), &state)?; // durable before external side effect
        let pending = state.sinks[config.name()]
            .pending
            .values()
            .cloned()
            .collect::<Vec<_>>();
        match deliver(&config, &pending).await {
            Ok(()) => {
                let timestamp = now();
                let sink = state
                    .sinks
                    .get_mut(config.name())
                    .expect("sink state exists");
                for record in sink.pending.values() {
                    sink.delivered.insert(record.delivery_id.clone(), timestamp);
                }
                sink.pending.clear();
                while sink.delivered.len() > MAX_DELIVERED {
                    if let Some(key) = sink
                        .delivered
                        .iter()
                        .min_by_key(|(_, time)| *time)
                        .map(|(key, _)| key.clone())
                    {
                        sink.delivered.remove(&key);
                    }
                }
                sink.last_success_at = Some(timestamp);
                sink.last_error = None;
                results.push(ExportResult {
                    sink: config.name().into(),
                    queued,
                    delivered: pending.len(),
                    dry_run: false,
                });
            }
            Err(error) => {
                state
                    .sinks
                    .get_mut(config.name())
                    .expect("sink state exists")
                    .last_error = Some(error.to_string());
                write_json(&state_path(), &state)?;
                return Err(error);
            }
        }
        write_json(&state_path(), &state)?;
    }
    Ok(results)
}

async fn deliver(config: &SinkConfig, records: &[ExportRecord]) -> Result<(), AnyError> {
    if records.is_empty() {
        return Ok(());
    }
    match config {
        SinkConfig::Jsonl { path, .. } => {
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            let mut output = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)?;
            for record in records {
                serde_json::to_writer(&mut output, record)?;
                output.write_all(b"\n")?;
            }
            output.sync_data()?;
            Ok(())
        }
        SinkConfig::Loki {
            url,
            token_env,
            tenant,
            ..
        } => {
            let body = loki_body(records)?;
            let client = reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(15))
                .build()?;
            let mut request = client.post(url).json(&body);
            if let Some(name) = token_env {
                request = request.bearer_auth(
                    std::env::var(name).map_err(|_| format!("Loki token env `{name}` is unset"))?,
                );
            }
            if let Some(tenant) = tenant {
                request = request.header("X-Scope-OrgID", tenant);
            }
            let response = request.send().await?;
            if !response.status().is_success() {
                return Err(format!(
                    "Loki returned {}: {}",
                    response.status(),
                    response.text().await.unwrap_or_default()
                )
                .into());
            }
            Ok(())
        }
        SinkConfig::Mqtt {
            host,
            port,
            topic,
            client_id,
            tls,
            username_env,
            password_env,
            ..
        } => {
            use rumqttc::{AsyncClient, Event, Incoming, MqttOptions, QoS, Transport};
            let mut options = MqttOptions::new(client_id, host, *port);
            options.set_keep_alive(std::time::Duration::from_secs(30));
            if *tls {
                options.set_transport(Transport::tls_with_default_config());
            }
            if let (Some(username), Some(password)) = (username_env, password_env) {
                options.set_credentials(
                    std::env::var(username)
                        .map_err(|_| format!("MQTT username env `{username}` is unset"))?,
                    std::env::var(password)
                        .map_err(|_| format!("MQTT password env `{password}` is unset"))?,
                );
            }
            // The disk spool caps this batch at MAX_PENDING. Keep enough
            // request slots to enqueue it before deliberately driving the
            // event loop and waiting for every QoS 1 acknowledgement.
            let (client, mut eventloop) = AsyncClient::new(options, records.len().max(10));
            for record in records {
                client
                    .publish(topic, QoS::AtLeastOnce, false, serde_json::to_vec(record)?)
                    .await?;
            }
            let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(20);
            let mut acknowledged = 0usize;
            while acknowledged < records.len() {
                match tokio::time::timeout_at(deadline, eventloop.poll()).await {
                    Ok(Ok(Event::Incoming(Incoming::PubAck(_)))) => acknowledged += 1,
                    Ok(Ok(_)) => {}
                    Ok(Err(error)) => return Err(error.into()),
                    Err(_) => {
                        return Err(format!(
                            "MQTT acknowledgement timeout: {acknowledged}/{} events",
                            records.len()
                        )
                        .into())
                    }
                }
            }
            Ok(())
        }
    }
}

fn loki_body(records: &[ExportRecord]) -> Result<serde_json::Value, AnyError> {
    let mut streams: BTreeMap<(String, String, String, String, String), Vec<[String; 2]>> =
        BTreeMap::new();
    for record in records {
        let labels = (
            record.site.clone(),
            record.hostname.clone(),
            record.event.category.clone(),
            format!("{:?}", record.event.severity).to_lowercase(),
            record.event.outcome.clone(),
        );
        let line = serde_json::to_string(record)?;
        streams.entry(labels).or_default().push([
            (record.event.observed_at as u128 * 1_000_000_000).to_string(),
            line,
        ]);
    }
    let streams = streams.into_iter().map(|((site, hostname, category, severity, outcome), values)| serde_json::json!({"stream":{"job":"mycelium-security","site":site,"hostname":hostname,"category":category,"severity":severity,"outcome":outcome},"values":values})).collect::<Vec<_>>();
    Ok(serde_json::json!({"streams": streams}))
}

#[cfg(test)]
mod tests {
    use super::*;
    use mycelium_peer_protocol::SecuritySeverity;
    fn batches() -> Vec<SecurityEventBatch> {
        vec![SecurityEventBatch {
            schema_version: 1,
            node_id: "node-a".into(),
            hostname: "host-a".into(),
            site: "lab".into(),
            observed_at: 7,
            events: vec![SecurityEvent {
                id: "event-a".into(),
                observed_at: 7,
                category: "ssh".into(),
                action: "login".into(),
                outcome: "failure".into(),
                severity: SecuritySeverity::Medium,
                message: "denied".into(),
                fields: BTreeMap::new(),
            }],
        }]
    }
    #[test]
    fn delivery_ids_are_stable_and_node_scoped() {
        assert_eq!(flatten(&batches()), flatten(&batches()));
        assert_eq!(flatten(&batches()).len(), 1);
    }
    #[test]
    fn loki_uses_bounded_labels_and_structured_line() {
        let body = loki_body(&flatten(&batches())).unwrap();
        let stream = &body["streams"][0];
        assert_eq!(stream["stream"]["site"], "lab");
        assert!(stream["stream"].get("node_id").is_none());
        assert!(stream["values"][0][1]
            .as_str()
            .unwrap()
            .contains("delivery_id"));
    }
    #[test]
    fn rejects_relative_jsonl_path() {
        assert!(validate(&SinkConfig::Jsonl {
            name: "x".into(),
            path: "events.jsonl".into()
        })
        .is_err());
    }

    #[test]
    fn mqtt_requires_a_concrete_topic_and_complete_credentials() {
        let config = |topic: &str, username_env: Option<&str>, password_env: Option<&str>| {
            SinkConfig::Mqtt {
                name: "bus".into(),
                host: "127.0.0.1".into(),
                port: 1883,
                topic: topic.into(),
                client_id: "mycelium-test".into(),
                tls: false,
                username_env: username_env.map(str::to_owned),
                password_env: password_env.map(str::to_owned),
            }
        };
        assert!(validate(&config("mycelium/security/events/v1", None, None)).is_ok());
        assert!(validate(&config("mycelium/security/+", None, None)).is_err());
        assert!(validate(&config("mycelium/security", Some("USER"), None)).is_err());
    }

    #[tokio::test]
    async fn jsonl_delivery_is_newline_delimited_and_structured() {
        let path = crate::test_dir("siem").join("events.jsonl");
        let config = SinkConfig::Jsonl {
            name: "test".into(),
            path: path.clone(),
        };
        deliver(&config, &flatten(&batches())).await.unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        let lines = text.lines().collect::<Vec<_>>();
        assert_eq!(lines.len(), 1);
        let record: ExportRecord = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(record.node_id, "node-a");
        std::fs::remove_file(path).unwrap();
    }
}
