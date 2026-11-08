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

## Host policy

Add a `ssh_ca` block to the root-owned `/etc/mycelium/access.json`:

```json
{
  "version": 1,
  "authority_roots": ["ROOT_PUBLIC_KEY_HEX"],
  "accepted_roles": ["network-admin"],
  "ca_public": "/etc/ssh/mycelium/legacy-ca.pub",
  "ssh_ca": { "mode": "delegated", "keep_installed": true }
}
```

- `mode: "legacy"` (default) trusts `ca_public` verbatim — current behavior.
- `mode: "delegated"` derives the trusted CA set from active `ssh_user_ca`
  delegations and writes a root-owned
  `/var/lib/mycelium/access/ssh-user-ca.pub`, which `host-bundle` installs as
  `TrustedUserCAKeys`.
- `keep_installed: true` (default) also keeps the CA already in `ca_public`
  during migration. Set it to `false` only after the old CA is retired; with no
  active delegate the apply then **fails closed** instead of writing an empty
  trust file and locking out SSH.

## Phases

1. **Implemented:** `AuthorityCapability::SshUserCa` with `roles`/`unix_users`
   constraints, `permits_ssh_user_ca`, and `AuthorityResolver::ssh_user_cas()` /
   `ssh_user_ca()` returning the active, unrevoked, deterministic delegate set.
2. **Implemented:** host materialization. `access host apply` in `delegated`
   mode renders each delegate subject as an `ssh-ed25519` line into
   `/var/lib/mycelium/access/ssh-user-ca.pub` (unioning the legacy CA when
   `keep_installed`), and passes that file to `host-bundle`. `plan` shows the
   mode, source, and active delegates. No empty trust file is ever installed.
3. **Implemented:** issuance gate. With `MYCELIUM_SSH_CA_MODE=delegated`
   (default `legacy`), the daemon refuses to sign unless the CA public key is an
   active `ssh_user_ca` delegate and the binding's roles/users stay inside the
   delegation's constraints. The certificate `Key ID` becomes
   `mycelium:renew:<delegation_id>:<node_id>`, binding each certificate to the
   delegation that authorized it. Host reconciliation now builds the revocation
   KRL by adding a section per trusted CA (delegates, plus legacy while
   `keep_installed`) into one staged KRL.
4. **Implemented (tooling + runbook):** migrate the existing CA. Add a
   delegation for the current CA key first, enable delegated mode on hosts while
   `keep_installed` is true, then add/rotate delegates and revoke the old one.
   Actual publication needs the offline root key (below).
5. Backup/restore and root-rotation runbook with a scratch-host rehearsal.

## Migrating the existing CA

1. On the host that holds the current CA, emit a delegation statement for it:

   ```sh
   mycelium access ssh ca-delegation \
     --ca-public "$HOME/.mycelium/ssh/user_ca.pub" \
     --delegation-id ssh-user-ca-2026-11 \
     --role network-admin \
     --not-after 1825536000 \
     --path /secure/ssh-user-ca-delegation.json --write
   ```

   This derives the hex Ed25519 subject from the OpenSSH public key and writes
   an `ssh_user_ca` delegation. The example is in
   `docs/examples/authority-ssh-user-ca-delegation.json`.

2. With the **offline root key**, sign and publish it:

   ```sh
   mycelium authority delegate \
     --statement /secure/ssh-user-ca-delegation.json \
     --signing-key /secure/authority.key --write
   mycelium authority explain ssh.user-ca "$CA_PUBLIC_KEY_HEX"
   ```

3. On each Linux host, turn on delegated trust but keep the legacy CA during
   migration:

   ```json
   "ssh_ca": { "mode": "delegated", "keep_installed": true }
   ```

   ```sh
   sudo env MYCELIUM_HOME=/home/OPERATOR/.mycelium MYCELIUM_NO_AUTOSTART=1 \
     /usr/local/libexec/mycelium-access/mycelium access host plan \
     --policy /etc/mycelium/access.json
   # verify plan.ssh_user_cas and plan.ssh_ca_source, then apply --write
   ```

   Confirm a new SSH login and that `/etc/ssh/mycelium/user_ca.pub` contains the
   delegated key. Leave the legacy CA in place until every host has reconciled.

4. Only then set `MYCELIUM_SSH_CA_MODE=delegated` on the issuing daemon, so
   signing is gated by the same delegation.

5. To rotate: generate a new CA, emit/publish a delegation for it, let hosts
   reconcile, verify logins, then publish a root-signed revocation of the old
   delegation. Set `keep_installed` to `false` and re-apply once no host relies
   on the legacy key. Already-issued certificates remain valid until they
   expire; revocation is prospective.

Rollback: set `mode` back to `legacy` (or `keep_installed: true`) and re-apply.
The legacy `ca_public` was never removed.

