//! Parsing the decrypted Bitwarden vault and translating it into geode entries.

use std::collections::BTreeSet;

use geode::{CredentialKind, GeodeRef, Purpose, SecretBytes};
use serde::Deserialize;

use crate::{BitwardenError, ImportedCredential, MAX_COMPONENT};

/// Bitwarden cipher types. Only login and secure-note are mapped; card and
/// identity are skipped (see [`Cipher::kind`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum CipherKind {
    Login = 1,
    SecureNote = 2,
    Card = 3,
    Identity = 4,
}

impl CipherKind {
    fn from_u8(value: u8) -> Option<CipherKind> {
        match value {
            1 => Some(CipherKind::Login),
            2 => Some(CipherKind::SecureNote),
            3 => Some(CipherKind::Card),
            4 => Some(CipherKind::Identity),
            _ => None,
        }
    }
}

/// A single Bitwarden item as far as the importer cares. All optional fields so
/// a partial or foreign export still parses; unknown fields are ignored.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Cipher {
    #[serde(default, rename = "type")]
    kind: Option<u8>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    notes: Option<String>,
    #[serde(default)]
    login: Option<Login>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Login {
    #[serde(default)]
    username: Option<String>,
    #[serde(default)]
    password: Option<String>,
    #[serde(default)]
    totp: Option<String>,
    #[serde(default)]
    uris: Vec<Uri>,
}

#[derive(Clone, Debug, Default, Deserialize)]
struct Uri {
    #[serde(default)]
    uri: Option<String>,
}

impl Cipher {
    fn kind(&self) -> Option<CipherKind> {
        self.kind.and_then(CipherKind::from_u8)
    }

    fn name_or_default(&self) -> String {
        self.name
            .clone()
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| "unnamed".to_string())
    }
}

/// The decrypted export top level. The raw export splits items into per-type
/// arrays; the encrypted export uses a single `ciphers` array. Both are read.
#[derive(Debug, Default, Deserialize)]
struct Vault {
    #[serde(default)]
    ciphers: Vec<Cipher>,
    #[serde(default)]
    passwords: Vec<Cipher>,
    #[serde(default)]
    notes: Vec<Cipher>,
    #[serde(default)]
    cards: Vec<Cipher>,
    #[serde(default)]
    identities: Vec<Cipher>,
}

/// Parse a decrypted (or raw) vault into a flat list of ciphers.
pub(crate) fn parse_vault(json: &[u8]) -> Result<Vec<Cipher>, BitwardenError> {
    let vault: Vault = serde_json::from_slice(json)
        .map_err(|error| BitwardenError::Parse(format!("vault JSON: {error}")))?;

    let mut ciphers = vault.ciphers;
    if ciphers.is_empty() {
        ciphers.extend(vault.passwords);
        ciphers.extend(vault.notes);
        ciphers.extend(vault.cards);
        ciphers.extend(vault.identities);
    }
    Ok(ciphers)
}

/// Translate every mappable cipher into a geode entry.
///
/// Login items become `geode://<realm>/<account>/password` (plus a `/totp` slot
/// when one is present); secure notes become `geode://notes/<name>/note`. Card
/// and identity items are not simple credential secrets, so they are skipped —
/// the count is returned for the caller to report.
pub(crate) fn to_credentials(ciphers: Vec<Cipher>) -> Result<ImportReport, BitwardenError> {
    let mut report = ImportReport::default();
    for cipher in &ciphers {
        match cipher.kind() {
            Some(CipherKind::Login) => report.push_all(cipher)?,
            Some(CipherKind::SecureNote) => report.push_note(cipher)?,
            Some(_) | None => report.skipped += 1,
        }
    }
    Ok(report)
}

/// The mapped credentials plus a count of items that were skipped.
#[derive(Debug, Default)]
pub struct ImportReport {
    pub credentials: Vec<ImportedCredential>,
    pub skipped: usize,
}

impl ImportReport {
    fn push_all(&mut self, cipher: &Cipher) -> Result<(), BitwardenError> {
        let login = cipher.login.clone().unwrap_or_default();
        let realm = realm_from_login(&login);

        let account = match login
            .username
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            Some(username) => sanitize_component(username, "default"),
            None => "default".to_string(),
        };

        if let Some(password) = login.password.filter(|value| !value.is_empty()) {
            let reference = GeodeRef::new(realm.clone(), account.clone(), "password")
                .map_err(|error| BitwardenError::Reference(error.to_string()))?;
            self.credentials.push(ImportedCredential {
                reference,
                secret: SecretBytes::from(password),
                kind: CredentialKind::Opaque,
                purposes: BTreeSet::from([Purpose::http_basic()]),
                label: cipher.name.clone(),
            });
        }

        if let Some(totp) = login.totp.filter(|value| !value.is_empty()) {
            let reference = GeodeRef::new(realm, account, "totp")
                .map_err(|error| BitwardenError::Reference(error.to_string()))?;
            self.credentials.push(ImportedCredential {
                reference,
                secret: SecretBytes::from(totp),
                kind: CredentialKind::OtpSecret,
                purposes: BTreeSet::from([Purpose::otp_generate()]),
                label: cipher.name.clone(),
            });
        }

        Ok(())
    }

    fn push_note(&mut self, cipher: &Cipher) -> Result<(), BitwardenError> {
        let name = cipher.name_or_default();
        let account = sanitize_component(&name, "note");
        if let Some(body) = cipher.notes.clone().filter(|value| !value.is_empty()) {
            let reference = GeodeRef::new("notes", account, "note")
                .map_err(|error| BitwardenError::Reference(error.to_string()))?;
            self.credentials.push(ImportedCredential {
                reference,
                secret: SecretBytes::from(body),
                kind: CredentialKind::SecureNote,
                purposes: BTreeSet::from([Purpose::secure_note()]),
                label: Some(name),
            });
        }
        Ok(())
    }
}

/// The host of the login's first URI, sanitized into a realm; `"bitwarden"` if
/// there is no usable URI.
fn realm_from_login(login: &Login) -> String {
    let host = login
        .uris
        .iter()
        .find_map(|uri| uri.uri.as_deref())
        .map(host_of)
        .filter(|value| !value.is_empty())
        .unwrap_or_default();
    let host = sanitize_component(&host, "bitwarden");
    host.to_ascii_lowercase()
}

/// The host portion of a URL (everything after the scheme, before the path).
fn host_of(uri: &str) -> String {
    let rest = uri
        .strip_prefix("https://")
        .or_else(|| uri.strip_prefix("http://"))
        .unwrap_or(uri);
    rest.split(['/', '?', '#'])
        .next()
        .unwrap_or(rest)
        .to_string()
}

/// Reduce an arbitrary string to a valid [`GeodeRef`] component: it must start
/// with an ASCII alphanumeric and contain only letters, digits, `.`, `_`, or
/// `-`, at most [`MAX_COMPONENT`] bytes. Anything else becomes `_`; a leading
/// punctuation mark is shifted past with `x`; an empty result falls back to
/// `default_value`.
fn sanitize_component(input: &str, default_value: &str) -> String {
    let mut out = String::with_capacity(input.len().min(MAX_COMPONENT));
    for ch in input.chars() {
        if out.len() >= MAX_COMPONENT {
            break;
        }
        let c = if ch.is_ascii_alphanumeric() {
            ch
        } else if matches!(ch, '.' | '_' | '-') {
            ch
        } else {
            '_'
        };
        out.push(c);
    }
    if out.is_empty() {
        return default_value.to_string();
    }
    // Fall back to the default when only separators survived (e.g. three
    // spaces), and shift a leading separator past `x` so the component starts
    // with an ASCII alphanumeric as the reference grammar requires.
    let has_alnum = out
        .trim_matches(|c| c == '_' || c == '.' || c == '-')
        .chars()
        .any(|c| c.is_ascii_alphanumeric());
    if !has_alnum {
        return default_value.to_string();
    }
    if !out
        .chars()
        .next()
        .is_some_and(|c| c.is_ascii_alphanumeric())
    {
        out.insert(0, 'x');
    }
    out
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn host_extraction_handles_scheme_and_path() {
        assert_eq!(host_of("https://example.com/path?a=b"), "example.com");
        assert_eq!(host_of("http://sub.example.org"), "sub.example.org");
        assert_eq!(host_of("example.com/x"), "example.com");
    }

    #[test]
    fn sanitize_produces_valid_components() {
        assert_eq!(
            sanitize_component("user@example.com", "default"),
            "user_example.com"
        );
        assert_eq!(sanitize_component(".hidden", "default"), "x.hidden");
        assert_eq!(sanitize_component("   ", "default"), "default");
        let long = "a".repeat(120);
        assert_eq!(sanitize_component(&long, "default").len(), MAX_COMPONENT);
    }
}
