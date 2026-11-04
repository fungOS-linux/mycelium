use mycelium_core::{CredentialRef, CredentialSet, MyceliumError, Secret};

/// Resolve a non-secret reference into the legacy driver credential shape.
/// This function lives in myceliumd so CLI clients and persisted plans never
/// receive resolved secret material.
pub fn resolve(
    reference: &CredentialRef,
    username: Option<String>,
) -> Result<CredentialSet, MyceliumError> {
    CredentialRef::parse(reference.as_str()).map_err(MyceliumError::Validation)?;
    let mut credentials = CredentialSet {
        username,
        ..CredentialSet::default()
    };
    match reference.scheme() {
        "env" => credentials.password = Some(Secret::Env(reference.location().into())),
        "ssh-key" => credentials.key_path = Some(reference.location().into()),
        "geode" => {
            // The reference is valid, but this host has no geode backend wired
            // in yet. Fail closed rather than falling back to env or a file.
            return Err(MyceliumError::Validation(
                "geode credential references need a configured geode backend; none is configured on this host"
                    .into(),
            ));
        }
        provider => {
            return Err(MyceliumError::Validation(format!(
                "unsupported credential provider `{provider}`"
            )))
        }
    }
    Ok(credentials)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_references_without_reading_secret_values() {
        let reference = CredentialRef::parse("env://ROUTER_PASSWORD").unwrap();
        let credentials = resolve(&reference, Some("operator".into())).unwrap();
        assert_eq!(credentials.username(), Some("operator"));
        assert_eq!(
            credentials.password,
            Some(Secret::Env("ROUTER_PASSWORD".into()))
        );
    }

    #[test]
    fn geode_references_fail_closed_without_a_backend() {
        let reference = CredentialRef::parse("geode://mail/work/imap").unwrap();
        let error = resolve(&reference, None).unwrap_err();
        assert!(error.to_string().contains("configured geode backend"));
    }
}
