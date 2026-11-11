# geode-pgp

Detached OpenPGP signatures over a private key owned by `geode`.

Geode stores the armored secret key as an opaque credential. This connector
leases it for a short signing operation, imports it into an ephemeral GnuPG home,
signs, and drops both. The caller receives only the armored detached signature.

```rust
use geode::{GeodeRef, Purpose, Store, MemoryBackend};
use geode_pgp::PgpKey;

let store = Store::new(MemoryBackend::new());
let reference = GeodeRef::parse("geode://principal/alice/pgp")?;
let key = PgpKey::load(
    &store,
    &reference,
    "<40-or-64-hex-fingerprint>",
    Purpose::spore_package_sign(),
)?;
let signature = key.sign_detached(b"package bytes")?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

## Boundaries

- The key must be unprotected. Geode's encrypted backend is the at-rest
  boundary; a passphrase-protected key needs a second secret and is not in this
  slice.
- This is a software signer. It does not make the key non-exportable; hardware
  signing (TPM, Secure Enclave) is a separate interface.
- `gpg` and `gpgconf` must be on `PATH`. A missing tool fails closed.
- The temporary GnuPG home is mode `0700` and removed on drop. The key is
  imported from stdin, not written to a configuration file.

The intended purposes are `spore.package.sign` and `store.delegation.sign`.
The purpose is the grant; the connector does not use a key without a lease for
the purpose it was asked for.
