use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::GeodeError;

/// Scheme prefix for a credential address.
pub const SCHEME: &str = "geode://";

/// Longest accepted component. Keeps references log-friendly and bounded.
const MAX_COMPONENT: usize = 64;

/// A non-secret address for one stored secret.
///
/// ```text
/// geode://<realm>/<account>/<slot>
/// ```
///
/// The reference is what configuration may carry. It cannot express userinfo,
/// a query string, a fragment, or whitespace, so a password cannot be smuggled
/// into durable configuration by formatting it as a reference.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct GeodeRef {
    realm: String,
    account: String,
    slot: String,
}

impl GeodeRef {
    pub fn new(
        realm: impl Into<String>,
        account: impl Into<String>,
        slot: impl Into<String>,
    ) -> Result<Self, GeodeError> {
        let realm = realm.into();
        let account = account.into();
        let slot = slot.into();
        for (name, value) in [("realm", &realm), ("account", &account), ("slot", &slot)] {
            validate_component(name, value)?;
        }
        Ok(Self {
            realm,
            account,
            slot,
        })
    }

    pub fn parse(value: &str) -> Result<Self, GeodeError> {
        let rest = value
            .strip_prefix(SCHEME)
            .ok_or_else(|| GeodeError::InvalidReference(format!("must start with `{SCHEME}`")))?;
        if rest.contains(['@', '?', '#']) {
            return Err(GeodeError::InvalidReference(
                "userinfo, query, and fragment syntax is not allowed".into(),
            ));
        }
        let mut parts = rest.split('/');
        let (Some(realm), Some(account), Some(slot), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(GeodeError::InvalidReference(
                "expected exactly `geode://<realm>/<account>/<slot>`".into(),
            ));
        };
        Self::new(realm, account, slot)
    }

    pub fn realm(&self) -> &str {
        &self.realm
    }

    pub fn account(&self) -> &str {
        &self.account
    }

    pub fn slot(&self) -> &str {
        &self.slot
    }

    pub fn as_reference(&self) -> String {
        format!("{SCHEME}{}/{}/{}", self.realm, self.account, self.slot)
    }
}

fn validate_component(name: &str, value: &str) -> Result<(), GeodeError> {
    if value.is_empty() {
        return Err(GeodeError::InvalidReference(format!(
            "{name} must not be empty"
        )));
    }
    if value.len() > MAX_COMPONENT {
        return Err(GeodeError::InvalidReference(format!(
            "{name} must be at most {MAX_COMPONENT} bytes"
        )));
    }
    let mut chars = value.chars();
    let starts_well = chars.next().is_some_and(|c| c.is_ascii_alphanumeric());
    let rest_well = chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'));
    if !starts_well || !rest_well {
        return Err(GeodeError::InvalidReference(format!(
            "{name} must start with an ASCII letter or digit and contain only \
             letters, digits, `.`, `_`, or `-`"
        )));
    }
    Ok(())
}

impl fmt::Display for GeodeRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.as_reference())
    }
}

impl fmt::Debug for GeodeRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // References are non-secret by construction; showing them is the point.
        write!(f, "GeodeRef({self})")
    }
}

impl FromStr for GeodeRef {
    type Err = GeodeError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

impl TryFrom<String> for GeodeRef {
    type Error = GeodeError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::parse(&value)
    }
}

impl From<GeodeRef> for String {
    fn from(value: GeodeRef) -> Self {
        value.as_reference()
    }
}
