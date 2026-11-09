//! DNS blocking policy over already-fetched local lists.
//!
//! Fetching is a separate, explicit step: this module never reaches the
//! network. A resolver that silently fetched a list at startup would make
//! `apply` non-deterministic and turn a failed download into a policy change.
//!
//! The rendered form is dnsmasq `address=/zone/...` (sinkhole) or
//! `local=/zone/` (NXDOMAIN). Both match the zone and every name below it, so
//! a wildcard entry is normalized to its bare zone instead of being a second
//! concept.
use crate::{canonical_domain, within};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::io::Read;
use std::net::IpAddr;
use std::path::PathBuf;

/// Bounds keep a hostile or mistaken list from turning into resolver downtime.
pub const MAX_SOURCES: usize = 16;
pub const MAX_SOURCE_BYTES: u64 = 4 * 1024 * 1024;
pub const MAX_ENTRIES: usize = 200_000;
pub const MAX_ALLOWLIST: usize = 1024;

/// What a blocked name answers with.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum BlockAction {
    /// `0.0.0.0` and `::`: a fast refusal, and what Pi-hole does.
    #[default]
    Sinkhole,
    /// NXDOMAIN: no address family is invented, and what NextDNS does.
    Nxdomain,
}

impl BlockAction {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sinkhole => "sinkhole",
            Self::Nxdomain => "nxdomain",
        }
    }

    pub fn parse(value: &str) -> Result<Self, String> {
        match value {
            "sinkhole" => Ok(Self::Sinkhole),
            "nxdomain" => Ok(Self::Nxdomain),
            _ => Err("block action must be `sinkhole` or `nxdomain`".into()),
        }
    }
}

/// One local list. Hosts files (`0.0.0.0 ads.example.com`) and plain domain
/// lists (`ads.example.com`) are both accepted; the leading address is
/// discarded because the configured action decides the answer.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BlocklistSource {
    pub path: PathBuf,
}

#[derive(Clone, Debug, Serialize)]
pub struct SourceStat {
    pub path: PathBuf,
    pub zones: usize,
    pub skipped: usize,
}

#[derive(Clone, Debug, Default)]
pub struct Blocklist {
    zones: BTreeSet<String>,
    skipped: usize,
    sources: Vec<SourceStat>,
    allowlist: Vec<String>,
}

impl Blocklist {
    pub fn load(
        sources: &[BlocklistSource],
        suffix: &str,
        allowlist: &[String],
    ) -> Result<Self, String> {
        let suffix = canonical_domain(suffix)?;
        if sources.len() > MAX_SOURCES {
            return Err(format!("blocklists are limited to {MAX_SOURCES} sources"));
        }
        if allowlist.len() > MAX_ALLOWLIST {
            return Err(format!(
                "DNS allowlist is limited to {MAX_ALLOWLIST} domains"
            ));
        }
        let mut allowed = Vec::with_capacity(allowlist.len());
        for domain in allowlist {
            let domain = canonical_domain(domain)?;
            if !domain.contains('.') {
                return Err(format!(
                    "allowlist entry `{domain}` must name a host or zone"
                ));
            }
            allowed.push(domain);
        }
        allowed.sort();
        allowed.dedup();
        let mut seen = BTreeSet::new();
        for source in sources {
            if !seen.insert(&source.path) {
                return Err(format!(
                    "duplicate blocklist source {}",
                    source.path.display()
                ));
            }
        }
        let mut zones = BTreeSet::new();
        let mut skipped = 0;
        let mut stats = Vec::with_capacity(sources.len());
        for source in sources {
            let text = read_source(&source.path)?;
            let mut counted = 0;
            let mut exempt = 0;
            let mut source_skipped = 0;
            for line in text.lines() {
                for candidate in candidates(line) {
                    let Some(name) = normalize(candidate) else {
                        source_skipped += 1;
                        continue;
                    };
                    // Checked before any other rule: `myc` is one label, and
                    // the namespace guard must not depend on that.
                    if within(&name, &suffix) || within(&suffix, &name) {
                        return Err(format!(
                            "blocklist entry `{name}` shadows the Mycelium namespace {suffix}"
                        ));
                    }
                    // A single label would blackhole an entire TLD
                    // (`address=/com/`).
                    if !name.contains('.') {
                        source_skipped += 1;
                        continue;
                    }
                    if allowed.iter().any(|zone| within(&name, zone)) {
                        exempt += 1;
                        continue;
                    }
                    zones.insert(name);
                    counted += 1;
                    if zones.len() > MAX_ENTRIES {
                        return Err(format!("blocklist exceeds {MAX_ENTRIES} zones"));
                    }
                }
            }
            // An HTML error page, a compressed archive, or the wrong file is a
            // configuration mistake. Treat it as one instead of serving an
            // unfiltered resolver that looks configured. A list that is
            // entirely allowlisted is not mistaken: it was understood and
            // deliberately exempted.
            if counted == 0 && exempt == 0 {
                return Err(format!(
                    "blocklist {} contains no usable domains",
                    source.path.display()
                ));
            }
            skipped += source_skipped;
            stats.push(SourceStat {
                path: source.path.clone(),
                zones: counted,
                skipped: source_skipped,
            });
        }
        Ok(Self {
            zones,
            skipped,
            sources: stats,
            allowlist: allowed,
        })
    }

    pub fn len(&self) -> usize {
        self.zones.len()
    }

    pub fn is_empty(&self) -> bool {
        self.zones.is_empty()
    }

    /// Lines that carried no usable domain, reported rather than hidden.
    pub fn skipped(&self) -> usize {
        self.skipped
    }

    pub fn sources(&self) -> &[SourceStat] {
        &self.sources
    }

    pub fn allowlist(&self) -> &[String] {
        &self.allowlist
    }

    pub fn zones(&self) -> impl Iterator<Item = &str> {
        self.zones.iter().map(String::as_str)
    }

    /// The most specific blocking zone for a name, for `blocklist check`.
    pub fn matched(&self, name: &str) -> Option<&str> {
        let name = canonical_domain(name).ok()?;
        let mut candidate = Some(name.as_str());
        while let Some(current) = candidate {
            if let Some(zone) = self.zones.get(current) {
                return Some(zone);
            }
            candidate = current.split_once('.').map(|(_, rest)| rest);
        }
        None
    }

    /// Any entry at or below `zone`. Such an entry would lose to a more
    /// specific delegation or owned namespace, so it must not be installed.
    pub fn covers(&self, zone: &str) -> Option<&str> {
        self.zones
            .range(zone.to_string()..)
            .next()
            .filter(|entry| within(entry, zone))
            .map(String::as_str)
    }

    /// Deterministic: zones are sorted, so the same lists always render the
    /// same bytes and a refresh diff shows only real policy changes.
    pub fn render(&self, action: BlockAction) -> String {
        let mut out = String::new();
        for zone in &self.zones {
            match action {
                BlockAction::Sinkhole => {
                    out.push_str(&format!("address=/{zone}/0.0.0.0\n"));
                    out.push_str(&format!("address=/{zone}/::\n"));
                }
                BlockAction::Nxdomain => out.push_str(&format!("local=/{zone}/\n")),
            }
        }
        out
    }
}

fn read_source(path: &std::path::Path) -> Result<String, String> {
    let mut bytes = Vec::new();
    std::fs::File::open(path)
        .and_then(|file| file.take(MAX_SOURCE_BYTES + 1).read_to_end(&mut bytes))
        .map_err(|error| format!("read blocklist {}: {error}", path.display()))?;
    if bytes.len() as u64 > MAX_SOURCE_BYTES {
        return Err(format!(
            "blocklist {} exceeds {MAX_SOURCE_BYTES} bytes",
            path.display()
        ));
    }
    String::from_utf8(bytes).map_err(|_| format!("blocklist {} is not UTF-8", path.display()))
}

/// Name tokens a line contributes. Unsupported syntax yields nothing so the
/// caller can count it, never guess at it.
fn candidates(line: &str) -> Vec<&str> {
    let line = line.trim();
    if line.is_empty()
        || line.starts_with('#')
        || line.starts_with('!')
        || line.starts_with(';')
        || line.starts_with('/')
    {
        return Vec::new();
    }
    // AdBlock exception rules never block, and option suffixes (`$third-party`)
    // cannot be honored without a query context, so neither is approximated.
    if line.starts_with("@@") || line.contains('$') {
        return Vec::new();
    }
    let line = line.split('#').next().unwrap_or_default().trim();
    if line.is_empty() {
        return Vec::new();
    }
    let mut tokens = line.split_whitespace().collect::<Vec<_>>();
    if tokens
        .first()
        .is_some_and(|token| token.parse::<IpAddr>().is_ok())
    {
        tokens.remove(0);
    }
    tokens
}

/// Canonical zone for one token, or `None` when it is not a blockable name.
fn normalize(token: &str) -> Option<String> {
    let token = token.trim_end_matches('.');
    let token = token.strip_prefix("||").unwrap_or(token);
    let token = token.strip_suffix('^').unwrap_or(token);
    // `address=/zone/` already covers every subdomain, so a wildcard is the
    // same statement as its bare zone.
    let token = token.strip_prefix("*.").unwrap_or(token);
    canonical_domain(token).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Temp(PathBuf);
    impl Temp {
        fn new(name: &str, body: &str) -> Self {
            let path =
                std::env::temp_dir().join(format!("blocklist-{}-{name}", std::process::id()));
            std::fs::write(&path, body).unwrap();
            Self(path)
        }
        fn source(&self) -> BlocklistSource {
            BlocklistSource {
                path: self.0.clone(),
            }
        }
    }
    impl Drop for Temp {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    #[test]
    fn accepts_hosts_domain_wildcard_and_adblock_shapes() {
        let list = Temp::new(
            "shapes",
            "# comment\n\n0.0.0.0 ads.example.com tracker.example.com\n127.0.0.1 metrics.example.net\nplain.example.org\n*.wild.example.com\n||blocked.example.io^\n",
        );
        let blocks = Blocklist::load(&[list.source()], "myc", &[]).unwrap();
        let rendered = blocks.render(BlockAction::Sinkhole);
        for zone in [
            "ads.example.com",
            "tracker.example.com",
            "metrics.example.net",
            "plain.example.org",
            "wild.example.com",
            "blocked.example.io",
        ] {
            assert!(
                rendered.contains(&format!("address=/{zone}/0.0.0.0")),
                "{zone}"
            );
            assert!(rendered.contains(&format!("address=/{zone}/::")), "{zone}");
        }
        assert_eq!(blocks.len(), 6);
        assert_eq!(blocks.skipped(), 0);
    }

    #[test]
    fn refuses_entries_that_shadow_the_mycelium_namespace() {
        for entry in ["myc", "node.myc", "mac-studio.wagar-house.myc"] {
            let list = Temp::new("shadow", &format!("ads.example.com\n{entry}\n"));
            let error = Blocklist::load(&[list.source()], "myc", &[]).unwrap_err();
            assert!(error.contains("shadows the Mycelium namespace"), "{entry}");
        }
        // A parent of the suffix is equally fatal: `address=/example.net/`
        // would sit beside `local=/mesh.example.net/`.
        let list = Temp::new("parent", "example.net\n");
        assert!(Blocklist::load(&[list.source()], "mesh.example.net", &[]).is_err());
    }

    #[test]
    fn allowlist_wins_over_its_whole_subtree() {
        let list = Temp::new(
            "allow",
            "ads.example.com\ngist.github.com\nstatus.example.com\n",
        );
        let blocks = Blocklist::load(
            &[list.source()],
            "myc",
            &["github.com".into(), "example.com".into()],
        )
        .unwrap();
        assert_eq!(blocks.len(), 0);
        assert_eq!(
            blocks.allowlist().to_vec(),
            vec!["example.com".to_string(), "github.com".to_string()]
        );
    }

    #[test]
    fn a_source_without_usable_domains_is_an_error() {
        for body in ["<html>error</html>\n", "# only comments\n", "com\n"] {
            let list = Temp::new("empty", body);
            assert!(
                Blocklist::load(&[list.source()], "myc", &[]).is_err(),
                "{body}"
            );
        }
    }

    #[test]
    fn unsupported_syntax_is_counted_instead_of_approximated() {
        let list = Temp::new(
            "skip",
            "||ads.example.com^$third-party\n@@||ok.example.com^\nhttps://tracker.example.com/p\n_bad.example.com\nreal.example.com\n",
        );
        let blocks = Blocklist::load(&[list.source()], "myc", &[]).unwrap();
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks.skipped(), 2);
        assert_eq!(blocks.sources()[0].zones, 1);
    }

    #[test]
    fn rendering_is_deterministic_and_action_switches_the_answer() {
        let a = Temp::new("a", "b.example.com\na.example.com\n");
        let b = Temp::new("b", "a.example.com\n");
        let first = Blocklist::load(&[a.source(), b.source()], "myc", &[]).unwrap();
        let second = Blocklist::load(&[b.source(), a.source()], "myc", &[]).unwrap();
        assert_eq!(
            first.render(BlockAction::Sinkhole),
            second.render(BlockAction::Sinkhole)
        );
        assert_eq!(first.len(), 2);
        assert_eq!(
            first.render(BlockAction::Nxdomain),
            "local=/a.example.com/\nlocal=/b.example.com/\n"
        );
        assert!(!first.render(BlockAction::Nxdomain).contains("address="));
    }

    #[test]
    fn check_reports_the_most_specific_blocking_zone() {
        let list = Temp::new("check", "ads.example.com\nsub.tracker.example.net\n");
        let blocks = Blocklist::load(&[list.source()], "myc", &[]).unwrap();
        assert_eq!(blocks.matched("x.ads.example.com"), Some("ads.example.com"));
        assert_eq!(blocks.matched("Ads.Example.COM."), Some("ads.example.com"));
        assert_eq!(
            blocks.matched("a.sub.tracker.example.net"),
            Some("sub.tracker.example.net")
        );
        assert_eq!(blocks.matched("example.com"), None);
    }

    #[test]
    fn bounds_reject_duplicate_missing_and_oversized_sources() {
        let list = Temp::new("bounds", "ads.example.com\n");
        let duplicate = vec![list.source(), list.source()];
        assert!(Blocklist::load(&duplicate, "myc", &[]).is_err());
        let missing = vec![BlocklistSource {
            path: PathBuf::from("/nonexistent/blocklist.txt"),
        }];
        assert!(Blocklist::load(&missing, "myc", &[]).is_err());
        let too_many = vec![list.source(); MAX_SOURCES + 1];
        assert!(Blocklist::load(&too_many, "myc", &[]).is_err());
    }
}
