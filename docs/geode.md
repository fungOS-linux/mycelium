# Geode: owner-local credential store

Status: **scaffold (v1 slice)**. No platform backend is implemented or selected
automatically. `geode` lives at `crates/geode` so it can be extracted into its own
repository if non-Rust consumers appear.

## Why it exists

Adapters (mail, HTTP, SSH, appliance drivers) need secrets. Configurations are
durable, shared, and easy to log; a password in configuration is a password in
every backup, diff, and support bundle. Geode separates the durable *address* from
the secret *interior*:

```text
config:   credential = "geode://mail/work/imap"
runtime:  Store::lease(reference, Purpose::mail_connect(), 60s)
```

The secret never crosses Unibus, never appears in JSON, and is never printed by
`Debug`.

## What v1 stores

Opaque secret bytes plus minimal non-secret metadata:

- `label` — optional operator-facing name, bounded and control-character free.
- `created_at`, `rotated_at`, `last_used_at` — epoch seconds.
- `purposes` — the allowlist of operations that may lease the secret.

That is the whole schema. Geode does not parse the secret, count items, record a
URL, or store a subject line. A field that describes the secret's contents is a
leak, not a feature. If geode ever becomes a vault, a field-by-field metadata
review comes first.

## Invariants enforced by the store, not the backend

- **Typed address.** `GeodeRef` accepts `geode://<realm>/<account>/<slot>` with
  bounded, ASCII-safe components. Userinfo, query, and fragment syntax is
  rejected, so a reference cannot smuggle a password. References serialize;
  secrets do not.
- **Explicit purpose.** Every lease names a `Purpose` that must be in the entry's
  allowlist. Holding the IMAP connect purpose does not grant SMTP submission.
- **Bounded lease.** TTL is clamped to `1s ..= 1h`. Expiry is checked on *every*
  `expose`, not once at issue, so a long-lived lease object cannot outlive the
  decision.
- **Redaction and zeroization.** `SecretBytes` has a redacting `Debug`, no
  `Serialize`, and zeroizes on drop. `Lease` is neither `Clone` nor `Serialize`.
- **Bounded audit.** Issue, denial, store, rotation, and deletion land in a
  fixed-capacity ring. Reasons are a closed enum; audit text cannot become a
  side channel. Durable retention belongs to the host journal.
- **Fail closed.** A platform without a backend gets `UnsupportedBackend`, which
  errors on every operation. There is no `auto` mode that might pick a weaker
  store, and no plaintext-file fallback.

## Backends

| Backend | State | Notes |
| --- | --- | --- |
| `MemoryBackend` | implemented | Tests and in-process composition; never durable. |
| `EnvBackend` | implemented | Read-only; `geode://a/b/c` reads `GEODE_A_B_C`; fixed purpose allowlist supplied at construction. Development only. |
| macOS Keychain | planned | Service `dev.fungos.geode`, `WhenUnlockedThisDeviceOnly`, no iCloud sync. |
| Linux Secret Service | planned | Desktop hosts. |
| `systemd-creds` / TPM | planned | Headless hosts; require an explicit TPM backend, not `auto`. See `hardware-key-protection.md`. |

A new backend implements `Backend` (`read`, `write`, `delete`, `writable`,
`kind`) and inherits every invariant above from `Store`. A backend that cannot
write must report `writable() == false`; the store then refuses `store`,
`rotate`, and `delete` with `ReadOnly` instead of silently dropping writes.

## Threat model

Geode protects secrets **at rest and in configuration**, and bounds their
lifetime in a process. It does not protect a secret from:

- a compromised process running as the same user (it can read the lease);
- root on the same host;
- a memory dump while a lease is live (zeroization covers drops, not arbitrary
  reads);
- a backend that lies about its own guarantees.

Sealing a secret through a TPM or Secure Enclave protects against copied disks,
not against a compromised running daemon. Non-exportable signing needs a separate
signing interface and algorithm support and must not be advertised as an effect
of sealing.

## Example

```rust
use std::time::Duration;
use geode::{GeodeRef, MemoryBackend, Purpose, SecretBytes, Store};

let store = Store::new(MemoryBackend::new());
let reference = GeodeRef::parse("geode://mail/work/imap").unwrap();
store
    .store(
        &reference,
        SecretBytes::from("hunter2"),
        [Purpose::mail_connect()],
        Some("work IMAP"),
    )
    .unwrap();

let lease = store
    .lease(&reference, &Purpose::mail_connect(), Duration::from_secs(60))
    .unwrap();
assert_eq!(lease.expose().unwrap(), b"hunter2");
```

## Follow-up slices

1. **macOS Keychain backend** — the first real backend, behind an explicit
   constructor. Prove migration from `EnvBackend` does not change configuration.
2. **`mycelium-core` integration** — accept `geode://` in `CredentialRef` and
   resolve it only at the driver invocation boundary. Resolution stays lazy; the
   reference stays the durable value.
3. **`unibus-mail` integration** — `email.account.v1` carries a geode reference;
   the IMAP/POP3 adapter leases `mail.connect` for the duration of a session and
   drops it on disconnect.
4. **Linux backend** — Secret Service for desktops, `systemd-creds`/TPM for
   headless hosts, each explicitly selected and tested for cold boot, denied
   access, corrupted blob, and unavailable TPM.
5. **Optional `geoded`** — an owner-only broker on a Unix socket with peer-cred
   checks, only if multiple processes need a single audit/rotation point. The
   library boundary is the default; a daemon is a deployment decision.

## Non-goals for v1

- Secret generation, rotation scheduling, or expiry policy beyond lease TTL.
- Multi-user sharing, remote access, or network transport.
- Vault-style content indexing (URLs, subjects, item counts).
- Automatic backend selection or silent fallback.
