# geoded: owner-only broker

`geoded` serves encrypted `FileBackend` leases over a Unix socket. It exists so
adapters in other processes (Unibus mail/chat bridges, drivers) can resolve a
`geode://` reference without linking geode or reading a plaintext file.

## Broker, not a vault

- Socket mode `0600`; every accepted connection is checked for the **same UID**
  as the daemon (`getpeereid` on macOS, `SO_PEERCRED` on Linux).
- Read-only over the socket: `lease` only. Storing/rotating is an operator
  action (`--put`, or a future CLI), never a client verb.
- One JSON request per connection:

```json
{"op":"lease","reference":"geode://mail/work/imap","purpose":"mail.connect","ttl_ms":5000}
{"ok":true,"secret_b64":"...","expires_at":null}
{"ok":false,"error":"purpose `mail.submit` is not allowed for geode://mail/work/imap"}
```

The lease TTL is bounded by the store (1s–1h). Purpose allowlists, credential
expiry, audit, and redaction are unchanged from the library.

## Store

`FileBackend` keeps non-secret metadata in the clear and one AES-256-GCM
ciphertext per secret, bound to the reference as associated data. The file is
written `0600` and replaced atomically. The 32-byte key is a separate `0600`
file (raw or 64 hex characters).

```sh
geoded --socket ~/.geode/geode.sock --store ~/.geode/store.db \
       --key-file ~/.geode/store.key --init      # generates the key once
printf %s "$SECRET" | geoded --store ~/.geode/store.db \
       --key-file ~/.geode/store.key \
       --put geode://mail/work/imap --purpose mail.connect
geoded --socket ~/.geode/geode.sock --store ~/.geode/store.db \
       --key-file ~/.geode/store.key
```

## Honest limits

- The key sits next to the store. A copied disk contains both, so this protects
  against casual file reads and backups, not an attacker who takes the disk.
  It is a deliberate headless fallback, not a substitute for Keychain, Secret
  Service, or TPM sealing.
- Same-UID isolation only. Another process as the same user can connect.
- One writer process. The backend serializes in-process; do not run two daemons
  against the same store.
- Read-only over the socket. Rotation/revocation is an operator command today.

## Next

1. Platform backends behind the same broker (Keychain, Secret Service,
   systemd-creds/TPM), selected explicitly.
2. `geode` CLI with list/rotate/revoke, using the same store.
3. Optional per-client identities if a deployment needs more than same-UID.
