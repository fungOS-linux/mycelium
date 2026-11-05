use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use geode::{
    AuditOutcome, DiskBackend, GeodeError, GeodeRef, ManualClock, MemoryBackend, Purpose,
    SecretBytes, Store,
};

fn reference() -> GeodeRef {
    GeodeRef::parse("geode://mail/work/imap").unwrap()
}

fn clock(start: u64) -> (Arc<ManualClock>, Arc<dyn geode::Clock>) {
    let clock = Arc::new(ManualClock::new(start));
    let shared: Arc<dyn geode::Clock> = clock.clone();
    (clock, shared)
}

fn memory_store(start: u64) -> Store<MemoryBackend> {
    let (_manual, shared) = clock(start);
    Store::with_clock(MemoryBackend::new(), Arc::clone(&shared))
}

#[test]
fn revoke_tombstones_in_place_and_blocks_future_leases() {
    let store = memory_store(1_000);
    let reference = reference();
    store
        .store(
            &reference,
            SecretBytes::from("hunter2"),
            [Purpose::mail_connect()],
            Some("work IMAP"),
        )
        .unwrap();

    // Revoking succeeds, tombstones the entry, and audits the state change.
    let revoked = store.revoke(&reference).unwrap();
    assert!(revoked);
    let meta = store.describe(&reference).unwrap().expect("present");
    assert_eq!(meta.revoked_at, Some(1_000));
    assert_eq!(meta.label.as_deref(), Some("work IMAP"));
    assert_eq!(store.audit().last().unwrap().outcome, AuditOutcome::Revoked);

    // The tombstone refuses the next lease; the refusal is audited too.
    let denied = store
        .lease(&reference, &Purpose::mail_connect(), Duration::from_secs(5))
        .unwrap_err();
    assert!(matches!(denied, GeodeError::Revoked(_)));
    assert_eq!(store.audit().last().unwrap().outcome, AuditOutcome::Revoked);

    // Rotating a revoked secret succeeds but keeps the record revoked
    // (renew preserves the tombstone, so future leases are still refused).
    assert!(store.rotate(&reference, SecretBytes::from("new")).is_ok());
    assert_eq!(
        store
            .describe(&reference)
            .unwrap()
            .expect("present")
            .revoked_at,
        Some(1_000)
    );
    assert!(matches!(
        store.lease(&reference, &Purpose::mail_connect(), Duration::from_secs(5)),
        Err(GeodeError::Revoked(_))
    ));
}

#[test]
fn a_fresh_insert_at_the_same_reference_is_not_revoked() {
    let store = memory_store(1_000);
    let reference = reference();
    store
        .store(
            &reference,
            SecretBytes::from("first"),
            [Purpose::mail_connect()],
            None,
        )
        .unwrap();
    store.revoke(&reference).unwrap();

    // Reissue: a brand-new credential at the same reference starts un-revoked.
    store
        .store(
            &reference,
            SecretBytes::from("second"),
            [Purpose::mail_connect()],
            None,
        )
        .unwrap();
    assert_eq!(
        store
            .describe(&reference)
            .unwrap()
            .expect("present")
            .revoked_at,
        None
    );
    assert!(store
        .lease(&reference, &Purpose::mail_connect(), Duration::from_secs(5))
        .is_ok());
}

#[test]
fn revoke_of_a_missing_entry_is_a_noop() {
    let store = memory_store(1_000);
    let reference = reference();
    assert!(!store.revoke(&reference).unwrap());
    assert!(store.describe(&reference).unwrap().is_none());
    assert!(store.audit().is_empty());
}

#[test]
fn revoke_requires_a_writable_backend() {
    let store = Store::new(geode::EnvBackend::new([Purpose::test()]).unwrap());
    let reference = GeodeRef::parse("geode://dev/ci/test-secret").unwrap();
    assert!(matches!(
        store.revoke(&reference),
        Err(GeodeError::ReadOnly)
    ));
}

#[test]
fn revoke_persists_across_a_disk_round_trip() {
    let path = PathBuf::from(format!(
        "/tmp/geode-revoke-test-{}.json",
        std::process::id()
    ));
    let base = path.to_string_lossy();
    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(format!("{base}.jsonl"));

    let backend = DiskBackend::create(&path).unwrap();
    let (_manual, shared) = clock(1_000);
    let store = Store::with_clock(backend, Arc::clone(&shared));
    store
        .store(
            &reference(),
            SecretBytes::from("hunter2"),
            [Purpose::mail_connect()],
            Some("work IMAP"),
        )
        .unwrap();
    store.revoke(&reference()).unwrap();

    // The tombstone is written to disk, not lost on the next open.
    let reopened = DiskBackend::open(&path).unwrap();
    let store = Store::with_clock(reopened, Arc::clone(&shared));
    let meta = store.describe(&reference()).unwrap().expect("present");
    assert_eq!(meta.revoked_at, Some(1_000));

    let (manual, _) = clock(1_000);
    manual.advance(Duration::from_secs(1));
    assert!(matches!(
        store.lease(
            &reference(),
            &Purpose::mail_connect(),
            Duration::from_secs(5)
        ),
        Err(GeodeError::Revoked(_))
    ));

    let _ = std::fs::remove_file(&path);
}
