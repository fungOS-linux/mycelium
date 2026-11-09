# Mycelium access control

Mycelium separates four concerns so no peer becomes a mandatory central
control plane:

1. Peer mTLS authenticates mesh transport.
2. An offline access authority signs grants and revocations.
3. Peers gossip and converge those signed records.
4. OpenSSH and OIDC adapters translate at narrow system boundaries.

OIDC tokens and SSH CA private keys are never gossiped. A node may transport an
access record, but only an authority in `MYCELIUM_ACCESS_KEYS` can create one.
Revocations are durable and win regardless of message arrival order.

## Manual runbook

Create the two independent authorities:

```sh
mycelium access keygen --path .mycelium/access.key --write
mycelium access ssh ca-init --path .mycelium/ssh/user_ca --write
```

Back up both private keys offline. Ordinary peers receive only the access
signer ID through `MYCELIUM_ACCESS_KEYS` and the SSH CA public key through a
host bundle.

Publish a signed grant whose `principal` is stable. For OIDC identities,
Mycelium derives `oidc:<issuer>#<subject>` after verifying the provider token.
The grant must contain a unique SSH certificate `serial`, at least one
`unix_users` principal, validity bounds, and the permitted `ssh_public_keys`.
Start from [`examples/access-grant.json`](examples/access-grant.json), replace
the example key with the exact contents of the user's `.pub` file, and choose
fresh validity timestamps and a never-reused serial.

```sh
mycelium access publish \
  --statement docs/examples/access-grant.json \
  --signing-key .mycelium/access.key \
  --write

OIDC_TOKEN='...' mycelium access oidc verify \
  --issuer https://identity.example \
  --audience mycelium \
  --token-env OIDC_TOKEN \
  --json

mycelium access ssh issue \
  --grant grant-1 \
  --public-key ~/.ssh/id_ed25519.pub \
  --ca .mycelium/ssh/user_ca \
  --path ~/.ssh/id_ed25519-cert.pub \
  --ttl 8h \
  --write
```

The verify result and the grant are deliberately separate. Compare the
returned `principal` with the grant's `principal`, then let the access
authority publish the policy decision. Mycelium does not currently exchange a
verified OIDC token for a grant automatically. The grant's `oidc_audiences`
must contain the exact client audience accepted for SSH exchange. Set
`oidc_ssh_key_exchange` to `false` to require a pre-enrolled public key, or to
`true` to let a holder of a valid bound JWT certify the key presented during
that exchange.

Once the signed grant has converged, the trusted access authority can exchange
the user's current JWT and public key for a short-lived OpenSSH certificate.
The command runs where the SSH CA private key is held; the user never receives
that key:

```sh
OIDC_TOKEN='...' mycelium access oidc ssh-issue \
  --issuer https://identity.example \
  --audience mycelium \
  --token-env OIDC_TOKEN \
  --public-key ~/.ssh/id_ed25519.pub \
  --ca .mycelium/ssh/user_ca \
  --path ~/.ssh/id_ed25519-cert.pub \
  --ttl 1h \
  --write
```

Issuance verifies discovery, JWKS signature, algorithm, key ID, issuer,
audience, subject, and expiry. It then requires one active signed grant for
the normalized issuer/subject and audience. The JWT must be valid at exchange
time, but the resulting SSH certificate is an independent credential whose
lifetime is capped by the requested TTL and grant expiry. This deliberately
lets already-authenticated operators retain bounded access during an IdP
outage without creating a permanent credential. Neither the JWT nor
the IdP signing keys enter Mycelium gossip or persistent state.

For self-service use, run `mycelium access oidc gateway` on the authority host
behind HTTPS, then run `mycelium access oidc join` on the user's machine. The
gateway binds only to loopback, reloads converged access state per request, and
returns only the signed user certificate. The README contains the complete
operator and user commands.

Certificate lifetime is capped by the signed grant. Issuance fails if the
grant is missing, inactive, expired, revoked, has no Unix principal, or does
not contain the presented public key.

Publish a revocation, then deterministically derive an OpenSSH KRL and a host
configuration bundle from the converged state:

```sh
mycelium access publish \
  --statement docs/examples/access-revocation.json \
  --signing-key .mycelium/access.key \
  --write

mycelium access ssh krl \
  --ca-public .mycelium/ssh/user_ca.pub \
  --path .mycelium/ssh/revoked.krl \
  --write

mycelium access ssh host-bundle \
  --ca-public .mycelium/ssh/user_ca.pub \
  --krl .mycelium/ssh/revoked.krl \
  --path .mycelium/ssh/host-bundle \
  --write
```

The host bundle is deployment-driver-neutral. Its manifest maps inputs to
`/etc/ssh`, requires `sshd -t`, and allows reload only after validation. It
does not disable existing authentication methods in this first slice.

### Install or roll back a host bundle

On an enrolled Linux host, apply the bundle transactionally:

```sh
sudo -E mycelium access ssh host-apply --bundle /path/to/host-bundle --write
```

### Answer which hosts a principal can reach

Grants say what roles a principal holds. Hosts say which roles each Unix
account accepts. `directory` joins the two and lists only the targets where
both agree, so a caller never sees a host it cannot open a shell on.

Collect the host side once per rollout; it reads
`/etc/ssh/mycelium/principals/<user>` through the same non-interactive `sudo -n`
contract `host-apply` uses:

```sh
mycelium access ssh directory collect \
  --target agora-one --target pris \
  --site wagar-house \
  --path ~/.mycelium/ssh/directory.json --write
```

Then query it for a principal. `--principal` defaults to the SSH client
profile; OIDC principals such as `oidc:https://sso.fpl.dev#<subject>` work
unchanged.

```sh
mycelium access ssh directory --json
mycelium access ssh directory --principal 'oidc:https://sso.fpl.dev#abc' --json
mycelium access ssh directory --all --json   # include targets with shell=false
```

The JSON carries the `soil:mycelium` directory target shape (`id`, `label`,
`kind`, `site`, `shell`) plus the roles and Unix accounts that matched. A grant
whose signature does not verify contributes nothing and is reported under
`unverified` instead of silently shrinking the directory. A target that cannot
be read fails `collect`; it is never recorded as an empty, misleading entry.

## Automatic certificate renewal

The invitation is a one-time enrollment mechanism, not a renewable bearer
token. After enrollment, authorize the stable peer identity at the SSH
authority:

```sh
mycelium access ssh renewal-authorize \
  --node PEER_NODE_ID --unix-user USER --role ROLE \
  --credential-ttl 7d --write
```

The peer signs renewal requests with its persistent Ed25519 mesh identity and
sends them through the existing mTLS peer connection. Possession of a node TLS
certificate alone is insufficient because the request signature must match the
explicitly authorized node ID. The authority keeps the OpenSSH CA private key;
no CA material is copied to clients. Renewal is attempted at two thirds of the
issued lifetime, with node-derived startup jitter and bounded mesh reconnect
backoff. A laptop that sleeps past expiry renews after reconnecting because the
peer identity is independent of the short-lived SSH certificate.

This retains a rollback copy, validates with `sshd -t`, reloads only after
validation, and restores prior files if installation fails. The equivalent
manual procedure is:

```sh
bundle=.mycelium/ssh/host-bundle
sudo install -d -m 0755 /etc/ssh/mycelium /etc/ssh/sshd_config.d
sudo cp -a /etc/ssh/mycelium /etc/ssh/mycelium.pre-mycelium
sudo install -m 0644 "$bundle/user_ca.pub" /etc/ssh/mycelium/user_ca.pub
sudo install -m 0644 "$bundle/revoked.krl" /etc/ssh/mycelium/revoked.krl
sudo install -m 0644 "$bundle/60-mycelium-access.conf" \
  /etc/ssh/sshd_config.d/60-mycelium-access.conf
sudo sshd -t
sudo systemctl reload sshd || sudo systemctl reload ssh
```

Keep the current SSH session open and establish a second certificate-backed
session before considering the change complete. If validation or the second
login fails, remove `60-mycelium-access.conf`, restore the saved
`/etc/ssh/mycelium` directory, run `sshd -t`, and reload SSH again. A driver
must implement the same order: stage, validate, atomically install, reload,
then probe a new session; never reload an invalid configuration.

Inspect an issued certificate and confirm a revoked certificate is present in
the KRL with:

```sh
ssh-keygen -L -f ~/.ssh/id_ed25519-cert.pub
ssh-keygen -Q -f .mycelium/ssh/revoked.krl ~/.ssh/id_ed25519-cert.pub
```

The KRL query exits successfully when the certificate is not revoked and
non-zero when it is revoked.

### Configure the user's SSH client

The normal client path needs no OpenSSH configuration:

```sh
mycelium ssh mycelium-lab
mycelium ssh mycelium-lab -- hostname
```

Mycelium resolves the host, Unix user, port, and optional ProxyJump from
inventory and selects a device-specific certificate when one exists, otherwise
the shared managed certificate. Generate a narrowly scoped client fragment
only when direct `ssh` compatibility is desired:

```sh
mycelium access ssh client-config \
  --host mycelium-lab \
  --hostname lab.example.net \
  --user buddy \
  --identity ~/.ssh/id_ed25519 \
  --certificate ~/.ssh/id_ed25519-cert.pub \
  --path ~/.ssh/mycelium-lab.conf \
  --write
```

Add `Include ~/.ssh/mycelium-lab.conf` to `~/.ssh/config`. The target Unix
account must already exist; its username must be listed in the signed grant's
`unix_users`. Mycelium's host bundle trusts the SSH CA and KRL but deliberately
does not create OS accounts or change shells, groups, or sudo policy.

## OIDC boundary

`access oidc verify` uses standard discovery and JWKS. It accepts any provider
that supplies a matching issuer and asymmetric signing key, then validates
signature, key ID, issuer, audience, subject, and expiry. The only output is a
normalized identity contract (`principal`, issuer, subject, optional email,
groups, and expiry). The access authority remains responsible for policy and
signing; the OIDC adapter cannot mint a grant by itself.
