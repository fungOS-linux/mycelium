use std::sync::Arc;
use std::time::Duration;

use geode::{
    AuditOutcome, DenyReason, EnvBackend, GeodeError, GeodeRef, ManualClock, MemoryBackend,
    Purpose, SecretBytes, Store, UnsupportedBackend,
};

fn reference() -> GeodeRef {
    GeodeRef::parse("geode://mail/work/imap").unwrap()
}

fn clock(start: u64) -> (Arc<ManualClock>, Arc<dyn geode::Clock>) {
    let clock = Arc::new(ManualClock::new(start));
    let shared: Arc<dyn geode::Clock> = clock.clone();
    (clock, shared)
}

fn store_at(
    start: u64,
) -> (
    Store<MemoryBackend>,
    Arc<ManualClock>,
    Arc<dyn geode::Clock>,
) {
    let (manual, shared) = clock(start);
    (
        Store::with_clock(MemoryBackend::new(), Arc::clone(&shared)),
        manual,
        shared,
    )
}

#[test]
fn references_round_trip_and_reject_secret_bearing_syntax() {
    let reference = reference();
    assert_eq!(reference.realm(), "mail");
    assert_eq!(reference.account(), "work");
    assert_eq!(reference.slot(), "imap");
    assert_eq!(reference.as_reference(), "geode://mail/work/imap");
    assert_eq!(GeodeRef::parse(&reference.to_string()).unwrap(), reference);

    let encoded = serde_json::to_string(&reference).unwrap();
    assert_eq!(encoded, "\"geode://mail/work/imap\"");
    assert_eq!(
        serde_json::from_str::<GeodeRef>(&encoded).unwrap(),
        reference
    );

    for invalid in [
        "mail/work/imap",
        "geode://mail/work",
        "geode://mail/work/imap/extra",
        "geode://user:pass@mail/work/imap",
        "geode://mail/work/imap?password=hunter2",
        "geode://mail/work/imap#hunter2",
        "geode:///work/imap",
        "geode://../work/imap",
        "geode://mail/work/imap ",
    ] {
        assert!(
            GeodeRef::parse(invalid).is_err(),
            "accepted invalid reference: {invalid}"
        );
    }
}

#[test]
fn secrets_redact_themselves_in_debug() {
    let secret = SecretBytes::from("hunter2");
    let shown = format!("{secret:?}");
    assert!(!shown.contains("hunter2"));
    assert!(shown.contains("redacted"));
    assert_eq!(secret.expose_str().unwrap(), "hunter2");
}

#[test]
fn store_then_lease_reveals_only_for_a_listed_purpose() {
    let (store, _manual, _shared) = store_at(1_000);
    let reference = reference();
    let meta = store
        .store(
            &reference,
            SecretBytes::from("hunter2"),
            [Purpose::mail_connect()],
            Some("work IMAP"),
        )
        .unwrap();
    assert_eq!(meta.created_at, 1_000);
    assert_eq!(meta.rotated_at, 1_000);
    assert_eq!(meta.label.as_deref(), Some("work IMAP"));

    let lease = store
        .lease(
            &reference,
            &Purpose::mail_connect(),
            Duration::from_secs(60),
        )
        .unwrap();
    assert_eq!(lease.expose().unwrap(), b"hunter2");
    assert_eq!(lease.reference(), &reference);

    let denied = store
        .lease(&reference, &Purpose::mail_submit(), Duration::from_secs(60))
        .unwrap_err();
    assert!(matches!(denied, GeodeError::PurposeNotAllowed { .. }));

    let events = store.audit();
    assert!(matches!(events[1].outcome, AuditOutcome::Issued { .. }));
    assert_eq!(
        events[2].outcome,
        AuditOutcome::Denied(DenyReason::PurposeNotAllowed)
    );
    assert_eq!(events[2].purpose, Some(Purpose::mail_submit()));
}

#[test]
fn leases_expire_on_the_injected_clock() {
    let (store, manual, _shared) = store_at(1_000);
    let reference = reference();
    store
        .store(
            &reference,
            SecretBytes::from("hunter2"),
            [Purpose::mail_connect()],
            None,
        )
        .unwrap();
    let lease = store
        .lease(
            &reference,
            &Purpose::mail_connect(),
            Duration::from_secs(30),
        )
        .unwrap();
    assert_eq!(lease.remaining(), Duration::from_secs(30));

    manual.advance(Duration::from_secs(30));
    assert!(lease.is_expired());
    assert_eq!(lease.remaining(), Duration::ZERO);
    assert!(matches!(lease.expose(), Err(GeodeError::Expired(_))));
}

#[test]
fn lease_ttl_is_bounded_in_both_directions() {
    let (store, _manual, _shared) = store_at(1_000);
    let reference = reference();
    store
        .store(
            &reference,
            SecretBytes::from("hunter2"),
            [Purpose::mail_connect()],
            None,
        )
        .unwrap();
    for ttl in [Duration::ZERO, Duration::from_secs(3_601)] {
        assert!(matches!(
            store.lease(&reference, &Purpose::mail_connect(), ttl),
            Err(GeodeError::InvalidTtl { .. })
        ));
    }
    let events = store.audit();
    assert_eq!(
        events[1].outcome,
        AuditOutcome::Denied(DenyReason::InvalidTtl)
    );
    assert_eq!(
        events[2].outcome,
        AuditOutcome::Denied(DenyReason::InvalidTtl)
    );
}

#[test]
fn missing_entries_are_not_found_and_audited() {
    let (store, _manual, _shared) = store_at(1_000);
    let error = store
        .lease(
            &reference(),
            &Purpose::mail_connect(),
            Duration::from_secs(5),
        )
        .unwrap_err();
    assert!(matches!(error, GeodeError::NotFound(_)));
    assert_eq!(
        store.audit().last().unwrap().outcome,
        AuditOutcome::Denied(DenyReason::NotFound)
    );
}

#[test]
fn rotate_preserves_identity_and_allowlist() {
    let (store, manual, _shared) = store_at(1_000);
    let reference = reference();
    store
        .store(
            &reference,
            SecretBytes::from("first"),
            [Purpose::mail_connect()],
            Some("work IMAP"),
        )
        .unwrap();

    manual.advance(Duration::from_secs(50));
    let meta = store
        .rotate(&reference, SecretBytes::from("second"))
        .unwrap();
    assert_eq!(meta.created_at, 1_000);
    assert_eq!(meta.rotated_at, 1_050);
    assert_eq!(meta.label.as_deref(), Some("work IMAP"));
    assert!(meta.purposes.contains(&Purpose::mail_connect()));

    let lease = store
        .lease(&reference, &Purpose::mail_connect(), Duration::from_secs(5))
        .unwrap();
    assert_eq!(lease.expose().unwrap(), b"second");
    assert!(matches!(
        store.rotate(
            &GeodeRef::parse("geode://mail/work/missing").unwrap(),
            SecretBytes::from("x")
        ),
        Err(GeodeError::NotFound(_))
    ));
}

#[test]
fn delete_removes_the_entry_and_records_it() {
    let (store, _manual, _shared) = store_at(1_000);
    let reference = reference();
    assert!(!store.delete(&reference).unwrap());
    store
        .store(
            &reference,
            SecretBytes::from("hunter2"),
            [Purpose::mail_connect()],
            None,
        )
        .unwrap();
    assert!(store.delete(&reference).unwrap());
    assert!(store.describe(&reference).unwrap().is_none());
    assert_eq!(store.audit().last().unwrap().outcome, AuditOutcome::Deleted);
}

#[test]
fn audit_log_is_bounded() {
    let (manual, shared) = clock(1_000);
    let store = Store::with_audit_capacity(MemoryBackend::new(), shared, 2);
    let reference = reference();
    store
        .store(
            &reference,
            SecretBytes::from("hunter2"),
            [Purpose::mail_connect()],
            None,
        )
        .unwrap();
    let _ = store.lease(&reference, &Purpose::mail_connect(), Duration::from_secs(5));
    let _ = store.lease(&reference, &Purpose::mail_submit(), Duration::from_secs(5));
    assert_eq!(store.audit_len(), 2);
    let events = store.audit();
    assert!(matches!(events[0].outcome, AuditOutcome::Issued { .. }));
    assert_eq!(
        events[1].outcome,
        AuditOutcome::Denied(DenyReason::PurposeNotAllowed)
    );
    manual.advance(Duration::from_secs(1));
}

#[test]
fn env_backend_is_read_only_and_names_the_variable() {
    let purpose = Purpose::test();
    let backend = EnvBackend::new([purpose.clone()]).unwrap();
    let reference = GeodeRef::parse("geode://dev/ci/test-secret").unwrap();
    let variable = backend.variable(&reference);
    assert_eq!(variable, "GEODE_DEV_CI_TEST_SECRET");
    std::env::set_var(&variable, "hunter2");

    let store = Store::new(backend);
    let lease = store
        .lease(&reference, &purpose, Duration::from_secs(5))
        .unwrap();
    assert_eq!(lease.expose_str().unwrap(), "hunter2");
    assert!(matches!(
        store.delete(&reference),
        Err(GeodeError::ReadOnly)
    ));
    assert!(matches!(
        store.store(&reference, SecretBytes::from("x"), [purpose], None),
        Err(GeodeError::ReadOnly)
    ));

    std::env::remove_var(variable);
}

#[test]
fn unsupported_backends_fail_closed() {
    let store = Store::new(UnsupportedBackend::new("no platform backend in this build"));
    let error = store
        .lease(
            &reference(),
            &Purpose::mail_connect(),
            Duration::from_secs(5),
        )
        .unwrap_err();
    assert!(matches!(error, GeodeError::Backend(_)));
    assert_eq!(store.backend_kind(), "unsupported");
}
