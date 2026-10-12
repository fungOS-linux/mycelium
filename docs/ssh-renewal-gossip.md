# Signed SSH renewal and host rollout

Renewal uses the existing access grant, not a second role database. The signed
scope `ssh-renewal:PEER_ID:MAX_CREDENTIAL_SECONDS` binds renewal to one peer and
the grant's enrolled SSH keys. Roles, Unix users, human principal, validity and
revocation remain the grant's authoritative fields.

On an authority, authorize renewal from an existing **active** grant:

```sh
mycelium access ssh renewal-authorize \
  --grant EXISTING_GRANT_ID --node PEER_ID \
  --authorization-ttl 90d --credential-ttl 7d --write
```

`--authorization-ttl` is an explicit administrator decision to extend the
authorization lease. Omit it to preserve the original grant expiry. Renewing a
certificate never extends the grant. The command publishes a new signed grant
through the shared authority resolver; only a trusted access issuer can do it.
Unsigned `ssh/renewal-bindings.json` files no longer authorize issuance.

Each peer has one retained signed request slot. An issuer returns at most 32
public deliveries in one retained batch. Requests and responses follow the
existing authenticated gossip transports—including indirect paths—rather than
requiring a direct SSH or TCP connection to an issuer. A single 30-second worker
owns renewal; requests are reused for four minutes, and unchanged deliveries
are not republished. Only renewal observations are cloned, not rich topology.

Clients verify the renewed certificate's actual signature, pinned CA, subject
key, type and validity. An expired existing certificate can still supply its
verified CA/key pin: renewal proves the persistent peer key instead of requiring
a working SSH login. The renewed certificate serial is the grant serial, so
signed grant revocation also covers all its renewed certificates in OpenSSH KRL.

Certificates carry identity-plus-role principals derived by the shared protocol
helper. New host reconciliation accepts only those identity-bound principals;
same-role operators cannot select each other's Unix accounts. A legacy role
principal is retained on certificates for compatibility with older hosts.
Upgrade/renew clients before activating the stricter host worker. Local recovery
keys and local-owner sudo remain separate, deliberately unmanaged permissions.

Managed sudo uses five-minute `NOTAFTER` leases, clamped to the signed grant's
expiry. PAM calls the fixed root bootstrap's offline `pam-check` account action,
which re-verifies retained signatures and validity at login/sudo time. It does
not contact the daemon or start an async thread pool. Thus stopping the timer
does not leave indefinitely usable managed sudo or stale PAM account approval.

At least one authorized issuer holding the existing SSH CA must be reachable
through gossip. Private CA keys are never gossiped. Existing certificates remain
usable until their own expiry during an issuer outage; choose a lifetime suited
to the fleet's offline periods, or explicitly provision redundant issuers.

## Root-owned worker rollout

The fixed root bootstrap is retained at its existing protected installation.
It first enforces access from root-retained signed evidence, then supervises the
`mycelium-host-access` package using the shared software activation/rollback
transaction. A crash or bad worker cannot replace the recovery bootstrap.

Add approved package issuer public keys to `legacy_release_keys` in the existing
root-owned `/etc/mycelium/access.json`, or use its shared `authority_roots` and
root-signed bounded package delegations. Never infer these keys from discovery.
Trusting a privileged worker's publisher authorizes root code execution.

Create root-owned `/etc/mycelium/access-updates.json`:

```json
{
  "channel": "host-access-canary",
  "minimum_age_secs": 300,
  "rollout_window_secs": 1800,
  "retry_backoff_secs": 3600
}
```

Publish a signed baseline package matching the fixed bootstrap's installed
bytes before enabling automatic upgrades. Candidate versions must be strictly
newer, authorized, compatible and digest-matching. Publisher metadata cannot
supply commands, paths or service names. Artifact bytes can come from any peer;
they are copied into the protected root cache only after bounded reading and
hash/size verification.

```sh
sudo env MYCELIUM_HOME=/home/OPERATOR/.mycelium MYCELIUM_NO_AUTOSTART=1 \
  /usr/local/libexec/mycelium-access/mycelium access host install-timer \
  --policy /etc/mycelium/access.json --daemon-home /home/OPERATOR/.mycelium \
  --updates /etc/mycelium/access-updates.json --write
```

Installation adds a **manual-activation** placement hint to the existing user
daemon policy so gossip fetches the package artifacts. That hint confers no root
authority. Root configuration decides activation; the candidate must produce
the identity-bound host plan within a bounded health check. Failed activation
uses the existing software rollback journal and retains a per-digest backoff.

First-time privileged bootstrap/admission still needs an authorized local admin
or existing management route. Peer enrollment alone must never silently install
root trust or grant sudo. macOS certificate renewal is supported; root host
reconciliation/worker supervision currently target Linux.

## Qualification

The isolated three-daemon test exercises `client → relay → issuer` with an
eight-day-expired client certificate. Only the issuer has a test SSH CA; renewed
credentials and both gossip events appear on the relay. Unit tests cover peer
and SSH-key mismatch, expiry, revocation, bad signatures, wrong CA/expiry metadata,
bounded batches and same-role account isolation. Production rollout remains a
separate staged qualification, not implied by passing the source tests.
