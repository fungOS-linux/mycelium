use serde::{Deserialize, Serialize};

/// A non-secret pointer resolved only by the daemon that invokes a driver.
/// References deliberately reject URI user-info, queries, and fragments so a
/// password cannot be smuggled into durable inventory by accident.
///
/// Supported providers:
///
/// - `env://NAME` — read the variable at use time.
/// - `ssh-key:///absolute/path` — a private key file.
/// - `geode://<realm>/<account>/<slot>` — an owner-local geode credential.
///
/// A valid reference is not a promise that this host can resolve it. `geode`
/// references require a configured geode backend; without one, resolution fails
/// closed instead of falling back to another provider.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct CredentialRef(String);

impl CredentialRef {
    pub fn parse(value: impl Into<String>) -> Result<Self, String> {
        let value = value.into();
        let (scheme, location) = value
            .split_once("://")
            .ok_or("credential reference needs a provider scheme")?;
        if !matches!(scheme, "env" | "ssh-key" | "geode") {
            return Err(format!("unsupported credential provider `{scheme}`"));
        }
        if location.is_empty()
            || value.bytes().any(|byte| byte.is_ascii_whitespace())
            || value.contains(['@', '?', '#'])
        {
            return Err("credential reference contains unsafe or secret-bearing syntax".into());
        }
        if scheme == "env" {
            let mut bytes = location.bytes();
            let valid_start = bytes
                .next()
                .is_some_and(|byte| byte.is_ascii_alphabetic() || byte == b'_');
            if !valid_start || !bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_') {
                return Err("env credential reference needs an environment variable name".into());
            }
        }
        if scheme == "ssh-key" && !location.starts_with('/') {
            return Err("ssh-key credential reference needs an absolute path".into());
        }
        if scheme == "geode" {
            geode::GeodeRef::parse(&value).map_err(|error| error.to_string())?;
        }
        Ok(Self(value))
    }

    /// Construct from an already-validated geode reference.
    pub fn from_geode(reference: &geode::GeodeRef) -> Self {
        Self(reference.as_reference())
    }

    /// The typed geode reference, when this is a geode credential.
    ///
    /// `parse` and serde validate the value, so a `geode` scheme that fails to
    /// parse here would mean a `CredentialRef` was constructed outside this API.
    pub fn as_geode(&self) -> Option<geode::GeodeRef> {
        if self.scheme() != "geode" {
            return None;
        }
        geode::GeodeRef::parse(self.as_str()).ok()
    }

    pub fn scheme(&self) -> &str {
        self.0.split_once("://").expect("validated reference").0
    }

    pub fn location(&self) -> &str {
        self.0.split_once("://").expect("validated reference").1
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for CredentialRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "CredentialRef({})", self.0)
    }
}

impl TryFrom<String> for CredentialRef {
    type Error = String;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::parse(value)
    }
}

impl From<CredentialRef> for String {
    fn from(value: CredentialRef) -> Self {
        value.0
    }
}

/// Credentials a driver may use against an appliance.
///
/// Secrets are redacted in every display path, and resolution is lazy:
/// an `Env` value is read at use time so nothing sensitive is cached in
/// long-lived structures or serialized to disk.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum Secret {
    Literal(String),
    Env(String),
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Even Debug must not leak the literal.
        match self {
            Secret::Literal(_) => f.write_str("Secret(***redacted***)"),
            Secret::Env(var) => write!(f, "Secret(env:{var})"),
        }
    }
}

impl Secret {
    pub fn resolve(&self) -> Option<String> {
        match self {
            Secret::Literal(s) => Some(s.clone()),
            Secret::Env(var) => std::env::var(var).ok(),
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialSet {
    pub username: Option<String>,
    pub password: Option<Secret>,
    /// Path to a private key file (OpenSSH format).
    pub key_path: Option<String>,
    pub sudo_password: Option<Secret>,
}

impl CredentialSet {
    pub fn username(&self) -> Option<&str> {
        self.username.as_deref()
    }

    pub fn with_user(mut self, user: impl Into<String>) -> Self {
        self.username = Some(user.into());
        self
    }

    pub fn with_password(mut self, secret: Secret) -> Self {
        self.password = Some(secret);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secrets_are_redacted_in_debug() {
        let creds = CredentialSet {
            username: Some("admin".into()),
            password: Some(Secret::Literal("hunter2".into())),
            ..Default::default()
        };
        let shown = format!("{creds:?}");
        assert!(!shown.contains("hunter2"));
        assert!(shown.contains("redacted"));
    }

    #[test]
    fn credential_references_are_typed_and_cannot_embed_secrets() {
        let env = CredentialRef::parse("env://ROUTER_PASSWORD").unwrap();
        assert_eq!(env.scheme(), "env");
        assert_eq!(env.location(), "ROUTER_PASSWORD");
        let key = CredentialRef::parse("ssh-key:///Users/operator/.ssh/id_ed25519").unwrap();
        assert_eq!(key.scheme(), "ssh-key");
        assert!(CredentialRef::parse("env://user:pass@example").is_err());
        assert!(CredentialRef::parse("env://9INVALID").is_err());
        assert!(CredentialRef::parse("vault://secret/router").is_err());
        assert!(CredentialRef::parse("ssh-key://relative-key").is_err());
    }

    #[test]
    fn geode_references_are_typed_and_validated() {
        let reference = CredentialRef::parse("geode://mail/work/imap").unwrap();
        assert_eq!(reference.scheme(), "geode");
        assert_eq!(reference.location(), "mail/work/imap");
        let typed = reference.as_geode().unwrap();
        assert_eq!(typed.realm(), "mail");
        assert_eq!(typed.account(), "work");
        assert_eq!(typed.slot(), "imap");
        assert_eq!(CredentialRef::from_geode(&typed), reference);
        assert!(CredentialRef::parse("env://ROUTER_PASSWORD")
            .unwrap()
            .as_geode()
            .is_none());

        for invalid in [
            "geode://user:pass@mail/work/imap",
            "geode://mail/work/imap?password=hunter2",
            "geode://mail/work/imap#hunter2",
            "geode://mail/work",
            "geode:///work/imap",
            "geode://mail/work/imap/extra",
        ] {
            assert!(
                CredentialRef::parse(invalid).is_err(),
                "accepted invalid geode reference: {invalid}"
            );
        }
    }

    #[test]
    fn deserialization_revalidates_references() {
        let reference: CredentialRef = serde_json::from_str("\"geode://mail/work/imap\"").unwrap();
        assert_eq!(reference.scheme(), "geode");
        assert_eq!(
            serde_json::to_string(&reference).unwrap(),
            "\"geode://mail/work/imap\""
        );

        for invalid in [
            "\"env://user:pass@example\"",
            "\"ssh-key://relative-key\"",
            "\"geode://mail/work\"",
            "\"vault://secret/router\"",
        ] {
            assert!(
                serde_json::from_str::<CredentialRef>(invalid).is_err(),
                "deserialized invalid credential reference: {invalid}"
            );
        }
    }
}
