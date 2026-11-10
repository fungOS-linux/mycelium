//! Release selection and version verdicts shared by `update`, `doctor`, and
//! the fleet projection. Release manifests are signed; selection only chooses
//! among manifests the daemon already admitted.
use mycelium_peer_protocol::ReleaseManifest;
use semver::Version;
use std::cmp::Ordering;

pub fn channel() -> String {
    std::env::var("MYCELIUM_UPDATE_CHANNEL").unwrap_or_else(|_| "canary".into())
}

pub fn parse_releases(value: &serde_json::Value) -> Vec<ReleaseManifest> {
    value
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|value| serde_json::from_value(value.clone()).ok())
        .collect()
}

/// Pick the highest semantic version for `channel` among the comma-free target
/// list. Earlier targets win ties, matching the local architecture preference.
pub fn select_release<'a>(
    releases: &'a [ReleaseManifest],
    channel: &str,
    targets: &[String],
) -> Option<&'a ReleaseManifest> {
    releases
        .iter()
        .filter(|release| release.channel == channel)
        .filter_map(|release| {
            let rank = targets
                .iter()
                .position(|target| target == &release.target)?;
            let version = Version::parse(&release.version).ok()?;
            Some((release, version, rank))
        })
        .max_by(|(_, left, left_rank), (_, right, right_rank)| {
            left.cmp(right).then_with(|| right_rank.cmp(left_rank))
        })
        .map(|(release, _, _)| release)
}

pub fn compare(installed: &str, latest: &str) -> Option<Ordering> {
    Some(
        Version::parse(installed)
            .ok()?
            .cmp(&Version::parse(latest).ok()?),
    )
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VersionVerdict {
    Current,
    UpdateAvailable,
    Ahead,
    Unknown,
}

pub fn version_verdict(installed: Option<&str>, latest: &str) -> VersionVerdict {
    let Some(installed) = installed else {
        return VersionVerdict::Unknown;
    };
    match compare(installed, latest) {
        Some(Ordering::Less) => VersionVerdict::UpdateAvailable,
        Some(Ordering::Equal) => VersionVerdict::Current,
        Some(Ordering::Greater) => VersionVerdict::Ahead,
        None => VersionVerdict::Unknown,
    }
}

#[derive(Clone, Debug)]
pub struct RunningRelease {
    pub version: Option<String>,
    pub source: &'static str,
    pub digest: Option<String>,
    pub digest_matches: bool,
}

/// Identify the running binary against admitted releases and the recorded
/// update state. A version is only trusted when its digest matches the bytes
/// actually executing.
pub fn running_release(releases: &[ReleaseManifest]) -> RunningRelease {
    let Ok(executable) = std::env::current_exe() else {
        return RunningRelease {
            version: None,
            source: "unrecorded",
            digest: None,
            digest_matches: false,
        };
    };
    let Ok(bytes) = std::fs::read(&executable) else {
        return RunningRelease {
            version: None,
            source: "unrecorded",
            digest: None,
            digest_matches: false,
        };
    };
    let digest = mycelium_peer_protocol::sha256_hex(&bytes);
    if let Some(release) = releases
        .iter()
        .find(|release| release.artifact_digest == digest)
    {
        return RunningRelease {
            version: Some(release.version.clone()),
            source: "binary digest",
            digest: Some(digest),
            digest_matches: true,
        };
    }
    let state = crate::read_update_state();
    let (version, source, matches) = match (state.release_version, state.release_digest) {
        (Some(version), Some(recorded)) if recorded == digest => {
            (Some(version), "update state", true)
        }
        (Some(version), _) => (Some(version), "update state", false),
        _ => (None, "unrecorded", false),
    };
    RunningRelease {
        version,
        source,
        digest: Some(digest),
        digest_matches: matches,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn release(version: &str, channel: &str, target: &str) -> ReleaseManifest {
        ReleaseManifest {
            version: version.into(),
            channel: channel.into(),
            target: target.into(),
            protocol_version: 1,
            artifact_digest: "00".repeat(32),
            artifact_size: 1,
            signer: "00".repeat(32),
            signature: "00".repeat(64),
        }
    }

    #[test]
    fn selects_by_semver_not_lexicographic_order() {
        let releases = vec![
            release("0.2.4", "canary", "aarch64-apple-darwin"),
            release("0.2.14", "canary", "aarch64-apple-darwin"),
        ];
        let selected =
            select_release(&releases, "canary", &["aarch64-apple-darwin".to_owned()]).unwrap();
        assert_eq!(selected.version, "0.2.14");
    }

    #[test]
    fn filters_channel_and_prefers_earlier_targets() {
        let releases = vec![
            release("0.3.0", "stable", "aarch64-apple-darwin"),
            release("0.2.4", "canary", "x86_64-unknown-linux-gnu"),
            release("0.2.4", "canary", "aarch64-apple-darwin"),
        ];
        let selected = select_release(
            &releases,
            "canary",
            &[
                "aarch64-apple-darwin".to_owned(),
                "x86_64-unknown-linux-gnu".to_owned(),
            ],
        )
        .unwrap();
        assert_eq!(selected.target, "aarch64-apple-darwin");
    }

    #[test]
    fn verdict_distinguishes_current_update_and_ahead() {
        assert_eq!(
            version_verdict(Some("0.2.4"), "0.2.4"),
            VersionVerdict::Current
        );
        assert_eq!(
            version_verdict(Some("0.2.3"), "0.2.4"),
            VersionVerdict::UpdateAvailable
        );
        assert_eq!(
            version_verdict(Some("0.2.27"), "0.2.4"),
            VersionVerdict::Ahead
        );
        assert_eq!(version_verdict(None, "0.2.4"), VersionVerdict::Unknown);
    }
}
