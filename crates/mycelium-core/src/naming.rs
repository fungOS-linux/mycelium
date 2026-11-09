//! Stable names for nodes.
//!
//! A node's transport address changes when it moves networks; its name must
//! not. Names are derived from the hostname and site so a certificate can carry
//! an identity that survives a new LAN address.

/// The fleet name of a node, e.g. `mac-studio.wagar-house.myc`.
///
/// Returns `None` when either part has no usable label, so a caller can refuse
/// to mint an identity instead of writing a broken SAN.
pub fn fleet_name(hostname: &str, site: &str) -> Option<String> {
    let host = sanitize_label(hostname)?;
    let site = sanitize_label(site)?;
    Some(format!("{host}.{site}.myc"))
}

/// A DNS label: lowercase alphanumerics and hyphens, no leading or trailing
/// hyphen, at most 63 bytes. Any other character is a separator, so a single
/// input always yields exactly one label.
pub fn sanitize_label(value: &str) -> Option<String> {
    let mut label = String::with_capacity(value.len());
    let mut last_was_hyphen = false;
    for character in value.trim().chars() {
        let character = character.to_ascii_lowercase();
        let mapped = if character.is_ascii_alphanumeric() {
            character
        } else {
            '-'
        };
        if mapped == '-' {
            if label.is_empty() || last_was_hyphen {
                continue;
            }
            last_was_hyphen = true;
        } else {
            last_was_hyphen = false;
        }
        label.push(mapped);
        if label.len() == 63 {
            break;
        }
    }
    let label = label.trim_end_matches('-');
    (!label.is_empty()).then(|| label.to_owned())
}

/// True when `value` is a `.myc` name with valid labels, e.g. `ai.myc` or
/// `mac-studio.wagar-house.myc`.
pub fn is_myc_name(value: &str) -> bool {
    let value = value.trim_end_matches('.');
    value.ends_with(".myc")
        && value.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && sanitize_label(label).as_deref() == Some(label)
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fleet_name_normalizes_hostname_and_site() {
        assert_eq!(
            fleet_name("Averys-MacBook-Neo", "Wagar House"),
            Some("averys-macbook-neo.wagar-house.myc".into())
        );
        assert_eq!(
            fleet_name("agora-one", "wagar-house"),
            Some("agora-one.wagar-house.myc".into())
        );
    }

    #[test]
    fn a_name_needs_both_parts() {
        assert_eq!(fleet_name("", "home"), None);
        assert_eq!(fleet_name("neo", "  "), None);
        assert_eq!(fleet_name("!!!", "home"), None);
    }

    #[test]
    fn labels_drop_leading_and_repeated_separators() {
        assert_eq!(
            sanitize_label("  --neo--studio  ").as_deref(),
            Some("neo-studio")
        );
        assert_eq!(sanitize_label("a.b").as_deref(), Some("a-b"));
        assert_eq!(sanitize_label("neo\tstudio").as_deref(), Some("neo-studio"));
    }

    #[test]
    fn myc_names_are_checked_per_label() {
        assert!(is_myc_name("ai.myc"));
        assert!(is_myc_name("mac-studio.wagar-house.myc"));
        assert!(!is_myc_name("myc"));
        assert!(!is_myc_name("ai.local"));
        assert!(!is_myc_name("Bad.Name.myc"));
        assert!(!is_myc_name("ai..myc"));
    }
}
