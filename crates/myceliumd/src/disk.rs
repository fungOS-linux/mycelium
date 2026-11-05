//! Disk headroom for writes the daemon must not perform into a full volume.
//!
//! A full disk is not a rare edge case: it silently broke SSH certificate
//! renewal on a live host (`No space left on device`). Rather than discover
//! that from an opaque `ENOSPC` deep in an install path, callers check
//! available space first and report a clear, actionable error. The same
//! measurement feeds the gossiped health record so the fleet sees a nearly
//! full node before an operator does.
use std::path::{Path, PathBuf};

/// Keep this much space free so a small write never leaves the host unable to
/// log in, rotate a log, or finish a renewal.
pub const MIN_RESERVE_BYTES: u64 = 512 * 1024 * 1024;
/// Below this the host is in trouble: services can start failing to write.
pub const WARN_BYTES: u64 = 2 * 1024 * 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DiskState {
    Ok,
    Low,
    Critical,
}

impl DiskState {
    pub fn label(self) -> &'static str {
        match self {
            DiskState::Ok => "ok",
            DiskState::Low => "low",
            DiskState::Critical => "critical",
        }
    }
}

pub fn state(available: u64) -> DiskState {
    if available < MIN_RESERVE_BYTES {
        DiskState::Critical
    } else if available < WARN_BYTES {
        DiskState::Low
    } else {
        DiskState::Ok
    }
}

fn existing_ancestor(path: &Path) -> PathBuf {
    let mut current = path.to_path_buf();
    loop {
        if current.exists() {
            return current;
        }
        match current.parent() {
            Some(parent) if parent != current => current = parent.to_path_buf(),
            _ => return PathBuf::from("/"),
        }
    }
}

/// Available bytes on the filesystem that holds `path`, via the portable
/// `df -Pk` output the health collector already relies on.
pub fn available_bytes(path: &Path) -> Result<u64, String> {
    let target = existing_ancestor(path);
    let output = std::process::Command::new("df")
        .arg("-Pk")
        .arg(&target)
        .output()
        .map_err(|error| format!("df {}: {error}", target.display()))?;
    if !output.status.success() {
        return Err(format!(
            "df {}: {}",
            target.display(),
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let fields = text
        .lines()
        .last()
        .ok_or("df returned no filesystem")?
        .split_whitespace()
        .collect::<Vec<_>>();
    if fields.len() < 4 {
        return Err("unexpected df output".into());
    }
    let available = fields[3]
        .parse::<u64>()
        .map_err(|_| "df available field is not numeric")?;
    Ok(available.saturating_mul(1024))
}

/// Refuse a write when it would eat into the reserve. `needed` is the size the
/// caller is about to write; a best-effort 0 is accepted for tiny metadata.
pub fn ensure_headroom(path: &Path, needed: u64) -> Result<u64, String> {
    let available = available_bytes(path)?;
    if available < needed.saturating_add(MIN_RESERVE_BYTES) {
        return Err(format!(
            "only {} MiB free on {}; need at least {} MiB headroom before writing {} MiB",
            available / (1024 * 1024),
            existing_ancestor(path).display(),
            MIN_RESERVE_BYTES / (1024 * 1024),
            needed / (1024 * 1024),
        ));
    }
    Ok(available)
}

/// Stale incomplete downloads and interrupted atomic-write temporaries are
/// never useful after a day. Removing them is safe and bounded and keeps a
/// failed transfer from pinning disk forever.
pub fn prune_stale(home: &Path, now: u64, max_age_secs: u64) -> Result<(u64, usize), String> {
    let mut freed = 0u64;
    let mut removed = 0usize;
    let mut candidates = Vec::new();
    let artifacts = home.join("artifacts");
    if let Ok(entries) = std::fs::read_dir(&artifacts) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().is_some_and(|extension| extension == "part") {
                candidates.push(path);
            }
        }
    }
    if let Ok(entries) = std::fs::read_dir(home) {
        for entry in entries.flatten() {
            let path = entry.path();
            let name = path.file_name().and_then(|name| name.to_str()).unwrap_or("");
            if name.contains(".tmp-") || name.ends_with(".tmp") {
                candidates.push(path);
            }
        }
    }
    for path in candidates {
        let Ok(metadata) = std::fs::metadata(&path) else {
            continue;
        };
        let modified = metadata
            .modified()
            .ok()
            .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|duration| duration.as_secs())
            .unwrap_or(0);
        if modified == 0 || now.saturating_sub(modified) <= max_age_secs {
            continue;
        }
        let size = metadata.len();
        if std::fs::remove_file(&path).is_ok() {
            freed = freed.saturating_add(size);
            removed += 1;
        }
    }
    Ok((freed, removed))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn thresholds_are_ordered() {
        assert_eq!(state(MIN_RESERVE_BYTES - 1), DiskState::Critical);
        assert_eq!(state(MIN_RESERVE_BYTES), DiskState::Low);
        assert_eq!(state(WARN_BYTES - 1), DiskState::Low);
        assert_eq!(state(WARN_BYTES), DiskState::Ok);
    }

    #[test]
    fn headroom_refuses_a_write_larger_than_the_reserve_allows() {
        // available is whatever the test host has; asking for u64::MAX must fail.
        let result = ensure_headroom(Path::new("/"), u64::MAX / 2);
        assert!(result.is_err());
    }

    #[test]
    fn measurement_falls_back_to_an_existing_ancestor() {
        let missing = std::env::temp_dir().join(format!(
            "mycelium-disk-missing-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        assert!(available_bytes(&missing).unwrap() > 0);
    }

    #[test]
    fn prune_removes_only_stale_partial_files() {
        let home = std::env::temp_dir().join(format!(
            "mycelium-disk-prune-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let artifacts = home.join("artifacts");
        std::fs::create_dir_all(&artifacts).unwrap();
        let stale = artifacts.join("deadbeef.part");
        let fresh = artifacts.join("cafebabe.part");
        std::fs::write(&stale, b"partial").unwrap();
        std::fs::write(&fresh, b"partial").unwrap();
        // Backdate the stale file well past the max age.
        let old = std::time::SystemTime::now() - std::time::Duration::from_secs(48 * 3600);
        std::fs::File::options()
            .write(true)
            .open(&stale)
            .unwrap()
            .set_modified(old)
            .unwrap();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let (freed, removed) = prune_stale(&home, now, 24 * 3600).unwrap();
        assert_eq!(removed, 1);
        assert!(freed >= b"partial".len() as u64);
        assert!(!stale.exists());
        assert!(fresh.exists());
        std::fs::remove_dir_all(&home).ok();
    }
}
