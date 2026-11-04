# geode

Owner-local credential store for fungOS hosts.

`geode` owns opaque secrets and the small amount of non-secret metadata needed to
describe them. It is not a vault: it does not parse, index, or expose the contents
of a secret, and it deliberately has no URL/subject/item-count surface.

```text
geode://<realm>/<account>/<slot>
geode://mail/work/imap
geode://mail/work/smtp
```

Configuration carries the reference. The secret crosses only the owner-local
boundary and is revealed through a short, purpose-scoped lease.

## Invariants

- References are non-secret and cannot embed userinfo, a query, or a fragment.
- `SecretBytes` has a redacting `Debug`, no `Serialize`, and zeroizes on drop.
- Every read names a `Purpose`; a purpose outside the entry's allowlist is denied.
- Every lease is bounded (`1s ..= 1h`) and refuses to expose bytes after expiry.
- Every issue, denial, rotation, and deletion is recorded in a bounded audit log.
- Backends are pluggable; the store enforces policy so a backend cannot widen it.

## Backends in this slice

| Backend | State | Notes |
| --- | --- | --- |
| `MemoryBackend` | implemented | Tests and in-process composition. |
| `EnvBackend` | implemented | Read-only developer backend with a fixed purpose allowlist. |
| macOS Keychain | not implemented | Planned: `dev.fungos.geode`, `WhenUnlockedThisDeviceOnly`, no iCloud sync. |
| Linux Secret Service | not implemented | Planned for desktop hosts. |
| `systemd-creds` / TPM | not implemented | Planned for headless fungOS hosts; see `docs/hardware-key-protection.md`. |

No platform backend is selected implicitly. An unimplemented backend must fail
closed rather than fall back to a weaker store.

## Example

```rust
use std::time::Duration;
use geode::{GeodeRef, MemoryBackend, Purpose, SecretBytes, Store};

let store = Store::new(MemoryBackend::new());
let reference = GeodeRef::parse("geode://mail/work/imap").unwrap();
store.store(
    &reference,
    SecretBytes::from("hunter2"),
    [Purpose::mail_connect()],
    Some("work IMAP"),
).unwrap();

let lease = store
    .lease(&reference, &Purpose::mail_connect(), Duration::from_secs(60))
    .unwrap();
assert_eq!(lease.expose().unwrap(), b"hunter2");
// `lease` zeroizes when dropped.

store.delete(&reference).unwrap();
```

See `docs/geode.md` for scope, threat model, and the intended follow-up slices.
