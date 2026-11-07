# SSH user CA as a delegated authority

Mycelium SSH user certificates are signed by a CA that hosts trust. Today that
CA is a single key that has to be copied, backed up, and rotated by hand — the
one trust decision still outside the shared authority graph.

This document makes the SSH user CA a **delegated capability under the existing
authority root**, so there is one long-lived trust anchor and many disposable
operational delegates.

## Model

- **Root trust anchor.** A single Ed25519 root key, private half kept offline
  and backed up (ideally `k`-of-`n`). It is configured on every peer and host as
  a public key in `MYCELIUM_AUTHORITY_KEYS` / the host `authority_roots` policy.
  It signs only `Delegate` and `Revoke` statements — never a user certificate.
- **SSH CA delegates.** Operational Ed25519 keys that sign OpenSSH user
  certificates. A delegate is authorized by a root-signed
  `AuthorityCapability::SshUserCa` delegation with a validity window and
  constraints. Delegates are short-lived and are **not** backed up.
- **Hosts pin the root, not the delegate.** The privileged host reconciler
  reads verified authority records and materializes the currently active
  delegate set into `TrustedUserCAKeys` (`/etc/ssh/mycelium/user_ca.pub` is a
  legal multi-key file). Rotating or revoking a delegate therefore needs no host
  edit — only the signed record and the next reconciliation.

### Why the host has to rewrite a file

OpenSSH has **no user-CA chaining**: `TrustedUserCAKeys` must literally list the
keys that sign certificates. "One anchor" is achieved by deriving the active
delegate set from root-signed records at reconciliation time, not by a
handshake-time chain. If the reconciler does not run, a new delegate is not
trusted — that is the main operational dependency.

### Key identity

A delegate's authority `subject` (hex Ed25519 public key) is the same key that
signs certificates. The host renders it into the OpenSSH
`ssh-ed25519 <base64(blob)>` line for `TrustedUserCAKeys`. No separate CA public
key needs to be distributed.

## Capability

```json
{
  "kind": "delegate",
  "value": {
    "delegation_id": "ssh-user-ca-2026-11",
    "subject": "<hex ed25519 public key>",
    "capabilities": [
      { "action": "ssh_user_ca", "roles": ["network-admin"], "unix_users": [] }
    ],
    "not_before": 1794000000,
    "not_after": 1796600000
  }
}
```

Constraints narrow what a delegate may certify. **An empty `roles` and empty
`unix_users` is refused, not treated as a wildcard** — unlike package
constraints. A delegation with no constraint would be a fleet-wide CA and is
rejected by both the resolver and the issuance gate.

`ssh_user_ca` deliberately does **not** imply `access_publish` (or any other
capability). An access publisher must not be able to mint a CA and bypass the
host role policy.

## Security properties

- Root compromise is catastrophic and revocation is prospective; the root stays
  offline and is the only secret that is backed up.
- Delegate compromise is bounded: publish a root-signed revocation; hosts drop
  the key on the next reconciliation. Keep delegate validity and user-certificate
  TTL short so already-issued certificates age out.
- Delegation stays one level deep (authority v1): a delegate cannot delegate.
- Hosts continue to enforce `AuthorizedPrincipalsFile` and role mapping; the CA
  set is trust material, not an access grant.

## Root rotation and recovery

- **Backup:** back up the root private key only. Restoring it lets you sign a
  fresh `ssh_user_ca` delegation; hosts keep trusting the same anchor.
- **Rotation:** pin a set of root public keys on hosts, add the successor and
  its delegations first, then remove the old root after drain. Treat this as a
  staged operation, not a single record.

## Phases

1. **Implemented (this change):** `AuthorityCapability::SshUserCa` with
   `roles`/`unix_users` constraints, `permits_ssh_user_ca`, and
   `AuthorityResolver::ssh_user_cas()` / `ssh_user_ca()` returning the active,
   unrevoked, deterministic delegate set. No behavior change on its own.
2. Host materialization: write the active delegate set into `TrustedUserCAKeys`,
   keep the legacy single `ca_public` during migration.
3. Issuance gate: only a currently authorized delegate may sign user
   certificates; bind the certificate key ID to the delegation.
4. Migrate the existing CA: keep it trusted, add the first delegate, let hosts
   reconcile, then retire the old key.
5. Backup/restore and root-rotation runbook with a scratch-host rehearsal.
