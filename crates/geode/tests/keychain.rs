//! Integration tests for the macOS Keychain backend.
//!
//! These write real generic-password items to the login keychain, so each test
//! uses a distinctive reference and removes it before and after. On a normal
//! unlocked session the login keychain accepts adds/updates/deletes for a
//! custom service without a prompt; a locked or denied keychain makes the
//! round-trip fail, which is the behaviour worth reporting.
#![cfg(target_os = "macos")]

use std::sync::Arc;

use geode::{
    Backend, GeodeError, KeychainBackend, ManualClock, Purpose, SecretBytes, SecretMeta, Store,
};

/// A reference unlikely to collide with a real store and easy to spot in
/// Keychain Access under the `geode.credential-store` service. Each test uses a
/// distinct slot so parallel runs do not step on one another.
fn reference(slot: &str) -> geode::GeodeRef {
    geode::GeodeRef::parse(format!("geode://kctest/importer/{slot}").as_str()).unwrap()
}

fn clock(start: u64) -> (Arc<ManualClock>, Arc<dyn geode::Clock>) {
    let manual = Arc::new(ManualClock::new(start));
    let shared: Arc<dyn geode::Clock> = manual.clone();
    (manual, shared)
}

/// Remove any leftover item so a stale run never masks a fresh one.
fn sweep(reference: &geode::GeodeRef) {
    let backend = KeychainBackend::default();
    let _ = backend.delete(reference);
}

#[test]
fn keychain_round_trips_a_secret_through_the_store() {
    let reference = reference("smtp-password");
    sweep(&reference);

    let (_manual, shared) = clock(1_000_000);
    let store = Store::with_clock(KeychainBackend::default(), Arc::clone(&shared));

    let meta = store
        .insert(
            &reference,
            geode::NewCredential::opaque("s3cr3t-body")
                .with_purpose(Purpose::mail_connect())
                .with_label("smtp"),
        )
        .expect("store to the keychain");
    assert_eq!(meta.label.as_deref(), Some("smtp"));

    let lease = store
        .lease(
            &reference,
            &Purpose::mail_connect(),
            std::time::Duration::from_secs(60),
        )
        .expect("lease the stored secret");
    assert_eq!(lease.expose_str().unwrap(), "s3cr3t-body");

    // The record survives a fresh store over the same backend (process boundary
    // simulated by a second store handle).
    let store2 = Store::with_clock(KeychainBackend::default(), shared);
    let again = store2
        .lease(
            &reference,
            &Purpose::mail_connect(),
            std::time::Duration::from_secs(60),
        )
        .expect("second handle reads the same item");
    assert_eq!(again.expose_str().unwrap(), "s3cr3t-body");

    store.delete(&reference).expect("delete");
    sweep(&reference);
}

#[test]
fn keychain_backend_reports_not_found_and_updates_in_place() {
    let reference = reference("api-key");
    sweep(&reference);
    let backend = KeychainBackend::default();

    assert!(matches!(
        backend.read(&reference),
        Ok(None) | Err(GeodeError::NotFound(_))
    ));
    // A read on a missing item is reported as absent, never as an error.
    assert!(matches!(backend.read(&reference), Ok(None)));

    let meta = SecretMeta {
        kind: geode::CredentialKind::Opaque,
        label: Some("v1".into()),
        created_at: 1,
        rotated_at: 1,
        last_used_at: None,
        expires_at: None,
        purposes: std::collections::BTreeSet::from([Purpose::test()]),
    };
    meta.validate().expect("meta valid");
    backend
        .write(
            &reference,
            geode::StoredRecord::new(SecretBytes::from("one"), meta),
        )
        .expect("write");

    let first = backend
        .read(&reference)
        .expect("read present")
        .expect("present");
    assert_eq!(first.secret.expose_str().unwrap(), "one");

    // Writing again updates the same item rather than duplicating it.
    let mut meta2 = first.meta.clone();
    meta2.label = Some("v2".into());
    backend
        .write(
            &reference,
            geode::StoredRecord::new(SecretBytes::from("two"), meta2),
        )
        .expect("update");
    let second = backend
        .read(&reference)
        .expect("read present")
        .expect("present");
    assert_eq!(second.secret.expose_str().unwrap(), "two");
    assert_eq!(second.meta.label.as_deref(), Some("v2"));

    assert!(backend.delete(&reference).expect("delete exists"));
    assert!(!backend.delete(&reference).expect("delete missing is false"));
    sweep(&reference);
}
