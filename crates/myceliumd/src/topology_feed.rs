use std::collections::VecDeque;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use mycelium_core::{Origin, Topology};
use serde::{Deserialize, Serialize};

const SCHEMA_VERSION: u32 = 1;
const MAX_RETAINED_GENERATIONS: usize = 32;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct TopologyGeneration {
    pub schema_version: u32,
    pub generation: String,
    pub sequence: u64,
    pub observed_at: u64,
    /// Complete means this event contains one atomic projection, not that every
    /// possible observer was online when it was produced.
    pub complete: bool,
    pub provenance: Vec<Origin>,
    pub topology: Topology,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct TopologyFeedRead {
    pub events: Vec<TopologyGeneration>,
    /// Pass this value back as `since` to resume after this read.
    pub position: u64,
    /// Number of unavailable generations when `since` predates retention.
    pub missed: u64,
}

#[derive(Default, Serialize, Deserialize)]
struct PersistedFeed {
    #[serde(default)]
    generations: VecDeque<TopologyGeneration>,
}

pub struct TopologyFeed {
    generations: VecDeque<TopologyGeneration>,
    path: PathBuf,
}

impl TopologyFeed {
    pub fn load(path: PathBuf) -> Result<Self, String> {
        let generations = match fs::read(&path) {
            Ok(bytes) => {
                serde_json::from_slice::<PersistedFeed>(&bytes)
                    .map_err(|error| format!("read {}: {error}", path.display()))?
                    .generations
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => VecDeque::new(),
            Err(error) => return Err(format!("read {}: {error}", path.display())),
        };
        if generations.len() > MAX_RETAINED_GENERATIONS {
            return Err(format!(
                "read {}: retained topology feed exceeds {} generations",
                path.display(),
                MAX_RETAINED_GENERATIONS
            ));
        }
        let mut prior_sequence = None;
        for generation in &generations {
            if generation.schema_version != SCHEMA_VERSION || !generation.complete {
                return Err(format!(
                    "read {}: unsupported or incomplete retained generation",
                    path.display()
                ));
            }
            if prior_sequence.is_some_and(|prior| generation.sequence <= prior) {
                return Err(format!(
                    "read {}: topology generation sequences are not monotonic",
                    path.display()
                ));
            }
            if topology_digest(&generation.topology)? != generation.generation {
                return Err(format!(
                    "read {}: topology generation digest mismatch",
                    path.display()
                ));
            }
            prior_sequence = Some(generation.sequence);
        }
        Ok(Self { generations, path })
    }

    pub fn observe(&mut self, topology: Topology) -> Result<&TopologyGeneration, String> {
        let generation = topology_digest(&topology)?;
        if self
            .generations
            .back()
            .is_none_or(|current| current.generation != generation)
        {
            let sequence = self
                .generations
                .back()
                .map_or(1, |current| current.sequence.saturating_add(1));
            self.generations.push_back(TopologyGeneration {
                schema_version: SCHEMA_VERSION,
                generation,
                sequence,
                observed_at: now(),
                complete: true,
                provenance: topology.updated_from.iter().cloned().collect(),
                topology,
            });
            while self.generations.len() > MAX_RETAINED_GENERATIONS {
                self.generations.pop_front();
            }
            self.persist()?;
        }
        Ok(self
            .generations
            .back()
            .expect("observe inserts a generation"))
    }

    pub fn read_since(&self, since: u64, limit: usize) -> TopologyFeedRead {
        let Some(first) = self.generations.front() else {
            return TopologyFeedRead {
                position: since,
                ..TopologyFeedRead::default()
            };
        };
        let earliest_cursor = first.sequence.saturating_sub(1);
        let missed = earliest_cursor.saturating_sub(since);
        let effective_since = since.max(earliest_cursor);
        let events = self
            .generations
            .iter()
            .filter(|generation| generation.sequence > effective_since)
            .take(limit.max(1))
            .cloned()
            .collect::<Vec<_>>();
        let position = events
            .last()
            .map_or(effective_since, |generation| generation.sequence);
        TopologyFeedRead {
            events,
            position,
            missed,
        }
    }

    fn persist(&self) -> Result<(), String> {
        let bytes = serde_json::to_vec_pretty(&PersistedFeed {
            generations: self.generations.clone(),
        })
        .map_err(|error| error.to_string())?;
        atomic_write(&self.path, &bytes)
    }
}

fn topology_digest(topology: &Topology) -> Result<String, String> {
    let bytes = serde_json::to_vec(topology).map_err(|error| error.to_string())?;
    Ok(format!(
        "sha256:{}",
        mycelium_peer_protocol::sha256_hex(&bytes)
    ))
}

fn atomic_write(path: &Path, bytes: &[u8]) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| format!("create {}: {error}", parent.display()))?;
    }
    let temporary = path.with_extension("json.tmp");
    fs::write(&temporary, bytes)
        .map_err(|error| format!("write {}: {error}", temporary.display()))?;
    fs::rename(&temporary, path).map_err(|error| format!("install {}: {error}", path.display()))
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
    use std::sync::atomic::{AtomicU64, Ordering};

    fn feed() -> TopologyFeed {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "mycelium-topology-feed-test-{}-{}.json",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        TopologyFeed::load(path).unwrap()
    }

    #[test]
    fn unchanged_topology_keeps_one_generation() {
        let mut feed = feed();
        let first = feed.observe(Topology::empty()).unwrap().clone();
        let second = feed.observe(Topology::empty()).unwrap().clone();
        assert_eq!(first.sequence, second.sequence);
        assert_eq!(feed.read_since(0, 32).events.len(), 1);
    }

    #[test]
    fn changed_topology_advances_and_resumes_exclusively() {
        let mut feed = feed();
        let first = feed.observe(Topology::empty()).unwrap().sequence;
        let mut changed = Topology::empty();
        changed
            .conflicts
            .push(mycelium_core::Conflict::SegmentParamsDiff {
                segment: "lan".into(),
                field: "hostname".into(),
                values: vec!["one".into(), "two".into()],
                sources: Vec::new(),
            });
        let second = feed.observe(changed).unwrap().sequence;
        let read = feed.read_since(first, 32);
        assert_eq!(read.events.len(), 1);
        assert_eq!(read.events[0].sequence, second);
        assert_eq!(read.position, second);
        assert_eq!(read.missed, 0);
    }

    #[test]
    fn bounded_retention_reports_a_gap() {
        let mut feed = feed();
        for index in 0..(MAX_RETAINED_GENERATIONS + 3) {
            let mut topology = Topology::empty();
            topology
                .conflicts
                .push(mycelium_core::Conflict::SegmentParamsDiff {
                    segment: "lan".into(),
                    field: index.to_string(),
                    values: vec!["one".into(), "two".into()],
                    sources: Vec::new(),
                });
            feed.observe(topology).unwrap();
        }
        let read = feed.read_since(0, 64);
        assert_eq!(read.events.len(), MAX_RETAINED_GENERATIONS);
        assert_eq!(read.missed, 3);
    }

    #[test]
    fn persisted_feed_resumes_sequence_after_restart() {
        let mut feed = feed();
        let path = feed.path.clone();
        let first = feed.observe(Topology::empty()).unwrap().sequence;
        drop(feed);
        let mut reloaded = TopologyFeed::load(path).unwrap();
        let mut changed = Topology::empty();
        changed
            .conflicts
            .push(mycelium_core::Conflict::SegmentParamsDiff {
                segment: "lan".into(),
                field: "vlan".into(),
                values: vec!["10".into(), "20".into()],
                sources: Vec::new(),
            });
        assert_eq!(reloaded.observe(changed).unwrap().sequence, first + 1);
    }

    #[test]
    fn corrupted_persisted_generation_fails_loudly() {
        let mut feed = feed();
        let path = feed.path.clone();
        feed.observe(Topology::empty()).unwrap();
        let mut stored: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        stored["generations"][0]["generation"] = serde_json::json!("sha256:tampered");
        fs::write(&path, serde_json::to_vec(&stored).unwrap()).unwrap();
        assert!(TopologyFeed::load(path).is_err());
    }
}
