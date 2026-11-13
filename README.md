# Mycelium

**A distributed control plane for the networks and hardware you already own.**

Mycelium discovers physical topology, normalizes devices from different vendors,
and coordinates health, releases, and bounded access without requiring a central
controller. It is Rust-first, scriptable, and designed to fail closed around
mutating operations.

The project boundary is documented in [the Unix-style scope audit](docs/scope-audit.md):
Mycelium owns access, trusted self-updates, topology, resource observation, and
movement detection; adjacent systems remain replaceable adapters.

Optional [Iroh peer sync](docs/iroh-sync.md) carries existing authenticated
gossip over QUIC, with expiring public rendezvous QR codes for enrolled peers.

Desired state follows one boundary: intent produces read-only proposals, and
supported proposals lower into the single vendor-neutral `ActionPlan` executor.
Applied plans have canonical identities and durable per-action receipts. See
[`docs/changesets.md`](docs/changesets.md).

> Mycelium is usable today, but it is still pre-1.0. Read operations are the
> safest place to begin. Every mutation requires an explicit `--write`, and
> supported operations offer `--dry-run` so the proposed action is visible first.

## What works today

| Area | Current support |
| --- | --- |
| Discovery | SNMP, mDNS/DNS-SD, SSDP/UPnP, Linux, Darwin, and Tailscale observations; bounded Bambu, HomeKit/Hue, AirPlay, and print/scan recognition |
| Topology | Multi-site/LAN inventory, physical switch-port attachment, services, routes, link transport, and bounded advertisement recognition |
| Managed targets | NETGEAR FastPath, EdgeOS, UniFi AP/controller, Redfish/iLO, Linux, and Darwin drivers |
| Resources | Provider-neutral GPU and storage profiles with expiring host attachments |
| Desired state | Stable logical networks, imported allocations, drift reports, VLAN and forwarding primitives |
| Peer mesh | Signed observations, mTLS transport, health streaming, and target-aware P2P updates |
| Access | Signed grants/revocations, OIDC verification, short-lived OpenSSH certificates, and KRL generation |
| Early boot | PXE/NBDE reachability planning for Tang/Clevis deployments |

Replacement firmware remains experimental research and is not part of the
supported host build.

## fungOS

Mycelium is also the enrollment and update layer for [fungOS](fungOS/README.md),
a Debian-based distribution integration with optional Canvas/Unibus edge profiles.
The [public website repository](https://github.com/ajmwagar/fungos-web) contains
the real QEMU desktop captures. The distribution source now lives in
[ajmwagar/fungos](https://github.com/ajmwagar/fungos); remaining qualification
and integration work is being migrated from this checkout's `fungOS/` directory.

## Quick start

One installer builds the core binaries, enrolls the node, and prompts for the
optional pieces (IPv6 VPN, VFS, Soil + `fungOS.app`, build offload, operator
frontdoor). It supports macOS and systemd-based Linux; `fungOS.app` is macOS-only.
It is safe to re-run: binaries are backed up before replacement and existing
enrollment is repaired in place. Use `--yes` for recommended defaults.

```sh
curl --proto '=https' --tlsv1.2 -fsS \
  https://raw.githubusercontent.com/fungOS-linux/mycelium/master/install.sh | bash
```

After you accept the VPN component, the installer asks for sudo before the core
build because macOS and Linux need root to create the tunnel device. It reuses
that authorization for the DNS resolver service; declining the VPN with
`--no-vpn` does not remove the DNS service's root requirement. See
[docs/install.md](docs/install.md) for the full component and root-service
model. `MYCELIUM_GATEWAY` can select any compatible enrollment deployment. The
installer disables automatic updates for a local build by default; pass
`--enable-updates` to keep them enabled.

The native component inventory and the no-GitHub-Actions release path are in
[docs/native-components.md](docs/native-components.md) and
[docs/releasing.md](docs/releasing.md).

After installation, enrollment can be repeated explicitly with
`mycelium setup --gateway https://sso.fpl.dev`.

On a workstation that should expose local capability names such as `ai.myc`
and `mcp.myc`, the operator component installs the loopback HTTPS frontdoor after
enrollment. The `--trust-cert` flag adds the generated local CA to the login
keychain so the browser accepts the names. The same steps can be run directly:

```sh
mycelium setup --claim "$CLAIM" --local-frontdoor --trust-cert
# or, on an already-enrolled workstation:
mycelium frontdoor install --write --trust-cert
mycelium doctor
```

`mycelium doctor` checks the daemon, `.myc` resolution, the frontdoor services,
the frontdoor listeners, certificate trust, HTTPS health, whether the installed
release is the latest signed release for the channel, and the macOS
signature/notarization status. It exits non-zero when a check fails, so it can
gate automation. `--json` is available for scripts; `--fix --trust-cert`
repairs the local frontdoor installation. The lifecycle supports macOS
LaunchAgents and Linux systemd units; on Linux the installer needs
passwordless sudo. See [docs/releases.md](docs/releases.md).

`ai.myc` is the single AI endpoint: clients that used to be configured with a
provider URL point here instead. It serves from this machine first, then a
UMIE lease on the mesh, then `https://ai.fpl.dev`, and counts tokens at that one
hop so usage can be rolled up across the fleet:

```sh
mycelium frontdoor usage          # this machine
mycelium frontdoor usage --fleet  # gossiped totals from every peer
```

See [docs/ai-endpoint.md](docs/ai-endpoint.md) for the route, credential and
accounting rules, and for client configuration.

### Shell completion

Completion definitions are generated from the CLI's usage contract, so newly
documented subcommands appear without maintaining a second command list:

```sh
# Zsh (current shell)
source <(mycelium completions zsh)

# Bash (current shell)
source <(mycelium completions bash)

# Fish (persistent)
mycelium completions fish > ~/.config/fish/completions/mycelium.fish
```

An administrator can instead run a temporary pairing listener when OIDC is not
appropriate. The self-contained claim carries the rendezvous URL and a
high-entropy secret; the authority stores only its hash. The listener exits
after successful redemption or expiry. Private-network HTTP is supported for
direct pairing, while public rendezvous URLs must use HTTPS.

```sh
# Authority host; keep this process open while the other user joins:
mycelium pair --name buddy --unix-user operator \
  --ttl 15m --credential-ttl 8h

# New user machine:
curl --proto '=https' --tlsv1.2 -fsS \
  https://raw.githubusercontent.com/fungOS-linux/mycelium/master/install.sh | \
  bash -s -- --yes --claim MYC1-REPLACE-WITH-THE-PAIRING-CLAIM
```

Peer membership is separate from SSH access. A peer claim creates its private
key on the joining machine, sends only a CSR to the temporary authority, and
installs the returned mTLS identity plus mesh seeds:

```sh
mycelium pair --kind peer --name james --site mames-house \
  --peer 100.120.101.5:7443 --unix-user mames --role home-operator \
  --advertise http://100.120.101.5:8788 --ttl 15m
```

The recipient passes the printed claim to `mycelium setup --claim ...` (or the
installer's `--claim` option). Joining as a peer does not itself grant SSH.
Unattended provisioning should place the claim in an owner-only file and avoid
process arguments:

```sh
chmod 600 /run/fungos/claim
mycelium setup --claim-file /run/fungos/claim
```

The file is removed only after successful redemption. A failed attempt retains
it for a bounded retry; group- or world-accessible claim files are rejected.
Roles are carried as signed SSH certificate principals; each host opts into
roles with `host-bundle --allow USER=ROLE`. A host with no mapping denies all
Mycelium certificate roles while leaving its pre-existing SSH methods intact.

Setup does not report success until the managed service owns the local daemon
socket and listens on port 7443. An already-enrolled machine can reconstruct
and verify its native service without consuming another claim:

```sh
mycelium setup --repair --site mames-house
```

Requirements: a current stable Rust toolchain and the native tools required by
the drivers you choose (for example OpenSSH and SNMP utilities).

Install directly from GitHub:

```sh
cargo install --git https://github.com/ajmwagar/mycelium.git \
  mycelium-cli --locked
mycelium drivers
```

For a pinned checkout, build `mycelium-cli` as shown below and place
`target/release/mycelium` on `PATH`.

```sh
git clone https://github.com/ajmwagar/mycelium.git
cd mycelium
cargo build --release -p mycelium-cli -p mycelium-frontdoor

# The CLI starts its local daemon on demand.
./target/release/mycelium drivers
./target/release/mycelium targets
./target/release/mycelium topology
```

Add read-only observation points, scan, and inspect the unified map:

```sh
mycelium add pris --driver linux --user ajmwagar
mycelium add 192.168.1.2 --driver snmp \
  --credential-ref env://SNMP_COMMUNITY
mycelium scan
mycelium map
```

Credentials use typed, non-secret references and are resolved by the local
daemon only when it invokes a driver. Use `env://VARIABLE_NAME` for a secret in
the daemon environment or `ssh-key:///absolute/path` for an SSH private key.
Secret values are never persisted in inventory or gossiped. The legacy
`--password-env` and `--key` flags remain readable during migration. Use a
dedicated `MYCELIUM_HOME` when evaluating against a test network.

For automatic managed-target discovery, configure credential selectors rather
than a static device list. Addresses are derived from the converged topology;
the selected drivers identify the device, and Mycelium derives a healthy peer
on the matching LAN as an SSH jump when the local node is not attached:

```sh
install -m 600 .env ~/.mycelium/credentials.env

mycelium credentials map set network-appliances \
  --driver edgeos \
  --cidr 192.168.0.0/16 \
  --user ubnt \
  --credential-ref env://GATEWAY_PASS \
  --write

# Reused RFC1918 addresses remain distinct by network vantage point.
mycelium credentials map set lab-gateway \
  --driver edgeos --address 192.168.1.1 --site pris \
  --user ubnt --credential-ref env://LAB_GATEWAY_PASS --write

mycelium scan
mycelium targets
```

The credential map persists selectors and typed credential references, never
secret values. Unsupported providers and secret-bearing URI syntax fail
loudly. A mapping authorizes an authentication attempt; driver
recognition still determines what the endpoint is. Successful discoveries are
persisted as managed targets, while failures appear in scan warnings instead of
being silently classified. Service credentials belong in the owner-only
`~/.mycelium/credentials.env`; node/service settings remain separately in
`~/.mycelium/node.env`. The daemon reads both owner-only files on every
platform, including Darwin where launchd has no `EnvironmentFile` directive.

## Design

- One shared representation; vendor drivers translate capabilities at the edge.
- Integrate existing systems instead of replacing or reimplementing them.
- Derive topology and configuration from observed source data whenever possible.
- Keep workflows deterministic; Lua plugins run through bounded host APIs.
- Treat Lua as a vendor-dialect boundary, not a second orchestration runtime;
  see [the Lua plugin boundary audit](docs/lua-plugin-audit.md).
- Require explicit authorization for mutations and preserve a human-readable plan.
- Treat overlapping private address space as site-scoped, not globally unique.

## Early-boot paths and NBDE

Mycelium can evaluate whether observed topology supports an early-boot path
to Tang endpoints. It distinguishes direct, routed, and unverified paths; a
routed path remains a warning until initramfs addressing and firewall policy
are verified. Planning is read-only and does not execute Clevis:

```sh
mycelium boot-path <device> --target http://192.168.20.8:7500
mycelium nbde plan <device> \
  --tang http://192.168.20.8:7500 \
  --tang http://192.168.99.8:7500 \
  --threshold 2
```

Tang endpoints currently use literal IP addresses deliberately: boot-time DNS
is not assumed. A later enrollment workflow will call the system Clevis/Tang
tools and retain a passphrase recovery slot rather than reimplementing NBDE.
The proposed standalone provisioning service, first-contact enrollment flow,
and Mycelium driver boundary are documented in
[Genesis: machine provisioning and first contact](docs/genesis.md).

## Intelligent SSH hops

For a service reachable through an inventory gateway, Mycelium derives the
hop from the target's observed segment and gateway:

```sh
# Plan only.
mycelium tunnel 192.168.99.12:80 --local-port 8080

# Open in the foreground; Ctrl-C closes it.
mycelium tunnel 192.168.99.12:80 --local-port 8080 --write
```

The daemon returns SSH arguments and an environment-variable name only. The
secret stays in the CLI environment and is passed to `sshpass` via `SSHPASS`,
never argv. `--via DEVICE` overrides inference when multiple paths are valid.

## Peer mesh

Every `myceliumd` is a symmetric peer. It collects local Linux or Darwin
health, signs observations with a persistent Ed25519 identity in
`$MYCELIUM_HOME/peer.key`, and answers `mycelium peers` from its locally
converged view. There is no required controller.

Successful scans also publish a signed, schema-versioned snapshot of the
observer's local topology. Other peers merge those snapshots when rendering
`mycelium topology` or `mycelium map`; they do not persist or re-publish the
merged view, so discovery from multiple LAN vantage points converges without
recursive gossip amplification. Scan credentials and execution remain local.

For retained integrations, stream complete content-addressed generations as
newline-delimited JSON instead of repeatedly treating one-shot output as an
event source:

```sh
mycelium topology watch
mycelium topology watch --since 1842
mycelium topology watch --once
```

Each line carries `schema_version`, a `sha256:` generation digest, a monotonic
sequence, observation time, provenance, and the complete converged topology.
The daemon retains and atomically persists the latest 32 changed generations;
unchanged polling produces no new event. `--since` resumes exclusively after a
previous sequence. If that cursor predates retention, the CLI reports the gap
on stderr before continuing with the oldest available complete generation.
Here `complete` means the topology is an atomic projection rather than a
fragment; provenance and timestamps remain the honest account of which
observers contributed and how fresh their evidence is.

Direct peer links are optional and mutually authenticated. Configure any node
as a listener, a dialer, or both:

```sh
export MYCELIUM_PEER_LISTEN=0.0.0.0:7443       # optional
# Optional seeds. Prefix a seed with the name the peer's certificate carries so
# the seed survives the peer changing networks: name@address:port.
export MYCELIUM_PEERS=pris.lab.myc@pris.example:7443,neo.example:7443
export MYCELIUM_PEER_CA=/etc/mycelium/ca.pem
export MYCELIUM_PEER_CERT=/etc/mycelium/node.pem
export MYCELIUM_PEER_KEY=/etc/mycelium/node-key.pem
# Optional comma-separated Ed25519 node IDs allowed as observation origins.
export MYCELIUM_PEER_ALLOW=0123abcd...,4567efab...
mycelium daemon start
mycelium peers
```

## Peer enrollment and updates

Enrollment uses one locally held CA to issue a distinct mutual-TLS identity for
each peer. Every certificate carries the peer's stable fleet name,
`<name>.<site>.myc`, alongside the addresses known at issuance; peers verify
that name, so gossip keeps working after a node moves networks. Bundles contain
no CA signing key. Installation stages the peer and its native user-service
definition, but deliberately does not start it:

```sh
mycelium enroll init --write
mycelium enroll issue pris --site lab --address pris \
  --target x86_64-unknown-linux-gnu --binary ./mycelium \
  --peer neo.example:7443 --write

# Multi-homed peers carry every address used by another peer. The first
# address remains the inventory address; additional SANs are transport names.
mycelium enroll issue beachhead-1 --site beachhead \
  --address 203.0.113.10 --san 10.118.0.11 \
  --target x86_64-unknown-linux-musl --binary ./mycelium --write

# On pris, after transferring its bundle:
mycelium enroll install --bundle ./pris --write
systemctl --user daemon-reload
systemctl --user enable --now mycelium
```

Darwin installations write `~/Library/LaunchAgents/dev.fpl.mycelium.plist`
instead. Release manifests and artifacts are signed independently of the mesh
CA, so transport membership does not grant permission to publish executable
code. Peers fetch verified artifacts from one another, and `mycelium update
apply --write` retains and automatically restores the prior executable if the
new daemon fails its health check.

Compilation belongs to the external build pipeline (for example Fab). The
pipeline hands Mycelium a JSON release-set manifest whose relative binary paths
are resolved from the manifest's directory:

The centrally managed Fab workflow builds static-musl artifacts for both Linux
architectures. Linux peers treat musl and GNU releases as compatible while
preferring musl at the same version, allowing an existing GNU installation to
migrate onto the portable artifact. Fab emits `dist/release-set.json` and
`dist/SHA256SUMS`; release signing and publication remain an offline authority
operation.

```json
{
  "version": "0.1.1",
  "channel": "canary",
  "artifacts": [
    { "target": "aarch64-apple-darwin", "binary": "dist/mycelium-darwin-arm64" },
    { "target": "aarch64-unknown-linux-gnu", "binary": "dist/mycelium-linux-arm64" },
    { "target": "x86_64-unknown-linux-musl", "binary": "dist/mycelium-linux-x86_64" }
  ]
}
```

`mycelium releases publish-set --manifest release-set.json --signing-key
release.key --write` validates, hashes, and signs every artifact before
publishing any target. Peers may cache and relay every artifact, while update
selection remains target-specific.

### Capability-placed software

The same content-addressed peer transport can distribute first-party tools
without pretending each one is a Mycelium daemon release. A package manifest
signs the package name, version, channel, target triple, size, and SHA-256:

```sh
mycelium packages publish \
  --name unibus --binary ./dist/unibus-linux-arm64 \
  --signing-key /secure/mycelium-release.key \
  --version 0.4.0 --channel stable \
  --target aarch64-unknown-linux-musl --write
```

Peers relay the signed manifest. A node fetches verified bytes only when its
installed software policy assigns that package and channel. Placement remains
a separate desired-state policy, so possession of an artifact never grants it
permission to run. [`docs/examples/software-policy.json`](docs/examples/software-policy.json)
shows a base Unibus assignment, Raspberry Pi media nodes, GPU/Metal compute
nodes, and explicit Jarvis and Shroud roles:

```sh
mycelium software plan docs/examples/software-policy.json
mycelium software policy set docs/examples/software-policy.json --write
mycelium software status
mycelium software reconcile --dry-run
mycelium software reconcile --write
mycelium software activate unibus --channel stable --dry-run
mycelium software activate unibus --channel stable --write
```

Selectors consume derived facts such as `platform.linux`, `arch.aarch64`,
`site.wagar-house`, `resource.gpu`, `metal`, and `node.raspberry-pi`.
Operational roles that cannot be inferred safely are explicit node facts, for
example `MYCELIUM_NODE_FACTS=role.jarvis,role.shroud`. Conflicting channels for
the same package and node fail the plan. Activation verifies the signature,
size, and digest again, writes a versioned executable below
`$MYCELIUM_HOME/software`, and atomically switches `current`; it never executes
publisher-supplied installation commands. Service orchestration remains outside
Mycelium. Mycelium verifies and caches immutable artifacts, maintains a
versioned package directory, atomically advances the `current` pointer, and
writes `$MYCELIUM_HOME/software-state.json` for any local consumer. A bounded
systemd, launchd, or other explicit native adapter may restart the affected
unit, validate its health, and roll back the selection; Mycelium does not
become a general process supervisor.

For Debian-owned executables, the manual [APT update path](docs/apt-updates.md)
uses exact plan digests, stages recovery archives and reuses those local service
health checks. It is separate from native binary activation and does not yet
participate in automatic placement or rollout.

Update policy is resolved per package. A document-level `defaults.updates`
applies when a package has no override; an override may select `manual` or
`automatic` with its own cache soak, deterministic rollout window, and retry
backoff. Automatic updates require one manually selected version and accept
strictly newer versions only. `software auto-run` performs one bounded pass; a
systemd timer, launchd agent, cron, or another scheduler may invoke it without
transferring service ownership to Mycelium.

## Distributed access state

Access authorities are independent from peer and release identities. Peers
accept access statements only from public keys listed in
`MYCELIUM_ACCESS_KEYS`, then relay those signed statements unchanged. Grants
can represent multiple people, devices, roles, scopes, Unix accounts, and SSH
public keys. Revocations are durable statements rather than deletion events;
matching revocations always make a grant inactive regardless of gossip order.

```sh
mycelium access keygen --path .mycelium/access.key --write
export MYCELIUM_ACCESS_KEYS=<reported-signer-id>
mycelium access publish --statement grant.json \
  --signing-key .mycelium/access.key --write
mycelium access publish --statement revocation.json \
  --signing-key .mycelium/access.key --write
mycelium access list
```

For new deployments, use the shared delegated authority model instead of
separate feature roots. `MYCELIUM_AUTHORITY_KEYS` identifies offline root public
keys which can delegate access publication, Mycelium release publication, or
constrained package promotion. See [Shared authority](docs/authority.md).

OIDC-backed grants bind issuer, subject, and audience to Unix principals and
optionally permit a valid JWT holder to certify a presented SSH key. The
JWT must be valid during exchange. The resulting SSH certificate is an
independent, bounded credential that never outlives its requested TTL or the
signed grant, so an IdP outage does not immediately terminate existing access.

### Join with OIDC

The SSH CA stays on an authority host. Run the gateway on loopback and expose
it only through an HTTPS reverse proxy:

```sh
mycelium access oidc gateway \
  --listen 127.0.0.1:8787 \
  --issuer https://identity.example \
  --audience mycelium \
  --client-id mycelium \
  --client-secret-env MYCELIUM_OIDC_CLIENT_SECRET \
  --callback-url https://mycelium-access.example/v1/oidc/callback \
  --ca "$MYCELIUM_HOME/ssh/user_ca" --write
```

After an administrator publishes the user's signed grant, the user installs
the CLI and exchanges a current ID token plus their public key:

```sh
mycelium access oidc join \
  --gateway https://mycelium-access.example \
  --public-key ~/.ssh/id_ed25519.pub \
  --certificate ~/.ssh/id_ed25519-cert.pub \
  --ttl 8h --write

mycelium access ssh client-config \
  --host mycelium-lab --hostname lab.example --user buddy \
  --identity ~/.ssh/id_ed25519 \
  --certificate ~/.ssh/id_ed25519-cert.pub \
  --path ~/.ssh/mycelium-lab.conf --write
```

Include the generated fragment from `~/.ssh/config`. Provider configuration,
client credentials, grants, CA material, certificates, and runtime inventory
belong in deployment state, never the source tree. The gateway reloads current
grant/revocation state for every request and never returns the CA key.

An existing login CLI can supply the token through a provider-neutral
credential process. Store this deployment configuration outside the repository
at `$MYCELIUM_HOME/auth-providers.json`:

```json
{
  "providers": {
    "company-sso": {
      "issuer": "https://identity.example",
      "audience": "mycelium",
      "credential_process": [
        "fpl", "auth", "token", "--audience", "mycelium", "--json"
      ]
    }
  }
}
```

Then use `mycelium access oidc join --provider company-sso ...`. Mycelium runs
the argv array directly without a shell and independently verifies the returned
JWT against discovery, JWKS, issuer, and audience before sending it to the
certificate gateway.

### Enable certificate SSH on a host

Once an enrolled host trusts the Mycelium SSH CA and the user has a current
certificate at `$MYCELIUM_HOME/ssh/user-cert.pub`, normal access is one command:

```sh
mycelium access ssh profile set --principal ajmwagar \
  --unix-user ajmwagar --role fleet-admin --write
mycelium ssh lab-node
mycelium ssh lab-node -- uname -a
mycelium exec lab-node -- systemctl is-active mycelium
```

The persisted profile supplies the per-person Unix username for every
inventory and peer target. It takes precedence over a device's bootstrap or
management username; an explicit `--user` takes precedence over the profile.
Mycelium never infers a shared `fpladmin` fallback.

The daemon derives the destination, Unix user, port, and optional ProxyJump
from inventory targets such as `host:2222@gateway`. The CLI prefers the current
personal `$MYCELIUM_HOME/ssh/user-cert.pub`; a device-specific certificate is
a legacy fallback only. It uses only the selected identity and
certificate, so missing material fails loudly instead of silently falling back
to unrelated agent keys. Override paths with `--key` and `--certificate`, or
set `MYCELIUM_SSH_IDENTITY` and `MYCELIUM_SSH_CERTIFICATE`.
`mycelium exec` requires a command and enables SSH batch mode, making the same
derived route suitable for scripts, health checks, and one-shot agents.

File transfer uses that identical route plan in either direction:

```sh
mycelium scp ./agent dgx-spark:/tmp/agent --preserve
mycelium scp dgx-spark:/var/log/mycelium.log ./logs/
mycelium scp ./bundle dgx-spark:/tmp/bundle --recursive
```

Exactly one operand must be a Mycelium `DEVICE:PATH`; remote-to-remote copies
are rejected because they do not have one unambiguous identity and route.

Linux hosts can also reconcile accounts, SSH principals, sudo and PAM account
authorization from signed grants. The privileged helper independently verifies
the shared authority graph and retains signed evidence for offline expiry;
joining as a peer does not confer grant-issuing authority. See the
[host access runbook](docs/host-access-grants.md) for root-owned policy,
periodic enforcement and recovery. Local administrator ownership remains
separate from fleet signing authority.

## Allocation-backed logical networks

Allocation evidence is persisted separately from logical network ownership.
Externally managed networks can record an IaC-backed subnet without inventing
a VLAN, then adopt that stable receipt:

```sh
mycelium allocations record --site beachhead --subnet 10.118.0.0/20 \
  --gateway 10.118.0.1 --source shared-infra:projects/beachhead --write
mycelium networks adopt beachhead-vpc --site beachhead \
  --subnet 10.118.0.0/20 --write
```

Tagged networks add a separate VLAN receipt and pass `--vlan ID` during
adoption. Re-recording the same fact is idempotent; a new evidence source is
merged into the receipt and advances its generation.

Host CA trust is a privileged bootstrap/reconciliation action. Mycelium
generates the host bundle and an optional narrowly scoped client fragment; it
does not silently modify `sshd` or `~/.ssh/config`. Keep an existing SSH session
open while installing the bundle, validate before reload, and prove a second
certificate-only connection before closing the original session.

```sh
# Authority: create these once, then keep the private keys off ordinary peers.
mycelium access keygen --path "$MYCELIUM_HOME/access.key" --write
mycelium access ssh ca-init --path "$MYCELIUM_HOME/ssh/user_ca" --write

# Publish a grant prepared from docs/examples/access-grant.json, then issue.
mycelium access publish --statement grant.json \
  --signing-key "$MYCELIUM_HOME/access.key" --write
mycelium access ssh issue --grant GRANT_ID \
  --public-key ~/.ssh/id_ed25519.pub \
  --ca "$MYCELIUM_HOME/ssh/user_ca" \
  --path "$MYCELIUM_HOME/ssh/user-cert.pub" --ttl 8h --write

# Derive the host trust bundle from the same converged authorization state.
mycelium access ssh krl --ca-public "$MYCELIUM_HOME/ssh/user_ca.pub" \
  --path "$MYCELIUM_HOME/ssh/revoked.krl" --write
mycelium access ssh host-bundle \
  --ca-public "$MYCELIUM_HOME/ssh/user_ca.pub" \
  --krl "$MYCELIUM_HOME/ssh/revoked.krl" \
  --allow mames=home-operator \
  --path "$MYCELIUM_HOME/ssh/host-bundle" --write
```

Instead of repeating `USER=ROLE`, an authority can derive personal accounts
from active signed grants while selecting only the roles accepted by that host:

```sh
mycelium access ssh host-bundle --from-access --role fleet-admin \
  --ca-public "$MYCELIUM_HOME/ssh/user_ca.pub" \
  --krl "$MYCELIUM_HOME/ssh/revoked.krl" \
  --path "$MYCELIUM_HOME/ssh/fleet-admin-bundle" --write
```

Each Linux host can persist the roles it accepts and reconcile them from the
same signed grants after gossip convergence:

```sh
sudo -E mycelium access ssh host-policy set \
  --role home-operator --role network-admin \
  --ca-public "$MYCELIUM_HOME/ssh/user_ca.pub" --write
sudo -E mycelium access ssh host-policy reconcile --dry-run
sudo -E mycelium access ssh host-policy install-timer --write
```

The timer runs every two minutes with a small herd-avoidance delay. It does not
autostart a daemon as root. It consumes the existing user's converged,
signature-verified access view, derives the KRL and personal account mappings,
and reloads `sshd` only when the effective bundle changes.

Each `--allow USER=ROLE` is both an authorization projection and a local
account requirement. On Linux, `host-apply` creates a missing unprivileged
account with a home directory, `/bin/bash`, a locked password, and no
supplementary groups before enabling the role. Existing UID 0 accounts and
unsafe account intents are rejected. Removing a role removes its accepted SSH
principal; Mycelium deliberately preserves the account and home directory.

After agents have the current binary, one validated bundle can converge
multiple hosts without repeating the manual copy/apply runbook:

```sh
mycelium access ssh host-rollout \
  --bundle "$MYCELIUM_HOME/ssh/host-bundle" \
  --target pris --target home-pi --target agora-one \
  --write
```

Enrolled peers can renew role-bound SSH certificates without reusing an invite
or depending on a still-valid SSH login. The authority explicitly binds the
peer's stable node identity to its Unix account and role once:

```sh
mycelium access ssh renewal-authorize \
  --node PEER_NODE_ID \
  --unix-user mames \
  --role home-operator \
  --credential-ttl 7d \
  --write
```

An authority is simply an enrolled peer whose Mycelium home contains both
`ssh/user_ca` and `ssh/renewal-bindings.json`. Ordinary peers never receive the
CA private key. Their daemon signs a renewal request with its persistent peer
identity and sends it over the existing mutually authenticated mesh. The
authority issues only the roles in the binding. The client atomically replaces
`ssh/user-cert.pub` after two thirds of its lifetime; if the machine is asleep
or disconnected, normal mesh reconnect backoff retries renewal when it returns.
An expired SSH certificate therefore does not prevent renewal.

The peer setup flow records the public half of the SSH identity at
`ssh/public-key.pub`. Existing installations fall back to
`~/.ssh/id_ed25519.pub`, so they can adopt renewal during a binary update without
being paired again.

Rollout is fail-fast: each target must accept key-based bootstrap SSH and
passwordless invocation of the narrow host-apply command. Every target still
validates locally and retains its own rollback copy before sshd reload.

Copy the bundle to an enrolled Linux or macOS host, then apply it in one command:

```sh
sudo -E mycelium access ssh host-apply \
  --bundle "$MYCELIUM_HOME/ssh/host-bundle" --write
```

The command retains a rollback copy under `/etc/ssh`, runs `sshd -t`, reloads
only a valid configuration, and restores the prior files if validation or
reload fails. The equivalent manual break-glass procedure is documented in
[`docs/access-control.md`](docs/access-control.md#install-or-roll-back-a-host-bundle).

`mycelium ssh` does not require OpenSSH client configuration. If direct
`ssh mycelium-lab` compatibility is useful, generate an optional alias:

```sh
mycelium access ssh client-config \
  --host mycelium-lab --hostname lab-node.example.net --user operator \
  --identity ~/.ssh/id_ed25519 \
  --certificate "$MYCELIUM_HOME/ssh/user-cert.pub" \
  --path ~/.ssh/mycelium-lab.conf --write

# One-time client integration; Mycelium prints this instruction too.
printf '%s\n' 'Include ~/.ssh/mycelium-lab.conf' >> ~/.ssh/config
ssh -o BatchMode=yes -o PasswordAuthentication=no mycelium-lab
```

After that optional one-time `Include`, `ssh mycelium-lab` selects the
configured key and current Mycelium certificate. Certificate renewal replaces
the certificate at the same path; the SSH fragment does not need regeneration.

The authority private key stays off ordinary peers. Membership in the mTLS
mesh permits transport only; it does not permit creating access statements.

### Peer-bound transport credentials

One persistent Ed25519 key identifies a Mycelium peer. Transport private keys
remain separate and local: Mycelium signs bindings from that peer identity to
the public WireGuard, mTLS, DERP, or SSH credential instead of deriving or
reusing private keys across protocols.

WireGuard publications use this common binding directly. Upgraded mTLS peers
also gossip a signed SHA-256 fingerprint of their leaf certificate and advertise
the `transport.identity-binding` capability. Sensitive operations on such a
connection are accepted only after the presented certificate matches that
peer-signed binding. Peers without the capability remain compatible during a
rolling upgrade, but receive only the legacy CA-membership guarantee.
After all peers have been upgraded, set
`MYCELIUM_REQUIRE_TRANSPORT_BINDING=true` to reject that legacy downgrade path.
See [`docs/access-control.md`](docs/access-control.md) for the OIDC verification,
SSH certificate issuance, host installation, validation, and rollback runbook.

The TLS CA authorizes direct peers. Signed observation envelopes preserve
their originating node identity when relayed, use monotonic sequence numbers,
and deterministically retain the newest event per origin. Back up `peer.key`:
it is the node identity and is created with owner-only permissions. A future
Unibus carrier can exchange the same envelopes without changing their trust or
merge semantics.

### Signed peer updates

Release authorization is separate from peer transport identity. Generate an
offline release key, configure its returned public key on peers, then publish a
binary for one target and rollout channel:

```sh
mycelium releases keygen --path /secure/mycelium-release.key --write
export MYCELIUM_RELEASE_KEYS=<public-key-from-keygen>
mycelium releases publish \
  --binary ./target/release/mycelium \
  --signing-key /secure/mycelium-release.key \
  --version 0.2.0 --channel canary \
  --target aarch64-apple-darwin --write
```

Peers exchange only anti-entropy metadata until an authorized release is
missing locally. They then fetch bounded chunks from any connected peer,
resume by offset, and promote the artifact only after verifying its signed
size and SHA-256 digest.

Any peer that already has an exact published binary can seed it without a
release signing key. The digest must already belong to a trusted, converged
release manifest; target, version, channel, and size are derived from that
manifest rather than supplied again:

```sh
mycelium releases seed \
  --binary ./mycelium \
  --digest <published-sha256> \
  --write
```

The verified bytes enter the content-addressed cache and are immediately
available to connected peers. This lets, for example, an ARM64 Linux Pi and
DGX share one build when the signed target triple and bytes are identical.

```sh
mycelium update status --channel canary
mycelium update apply --channel canary --write
```

Activation preserves the prior executable, starts the candidate as a daemon,
and requires the local peer RPC to become healthy within ten seconds. Failure
automatically restores and starts the previous executable. Distribution peers
never possess or imply release authority.

Automatic activation is a separate, local authorization. Enabling it installs
an external launchd agent or systemd user timer; the updater therefore survives
the daemon restart it coordinates and reuses the same verified activation and
rollback path as the manual command:

```sh
mycelium update policy enable \
  --channel canary \
  --minimum-age 15m \
  --rollout-window 30m \
  --retry-backoff 1h \
  --write
mycelium update policy status
```

The minimum age lets a bad publication be revoked before activation. A stable
per-node offset spreads restarts across the rollout window, failures enter
backoff, and a candidate must pass the existing self-check and daemon health
check or the previous executable is restored. A node needs one successful
manual signed activation before unattended updates begin, and automatic policy
refuses same-version replacements and downgrades. `update policy disable
--write` stops activation without disabling signed artifact distribution.

The fleet projection flags hosts whose recorded release is behind the latest
signed release for their target:

```sh
mycelium update status --fleet
mycelium update status --fleet --json
mycelium update report
mycelium update report --json
mycelium update report --fail-on-updates
```

Rows include `latest_version` and `needs_update`; unrecorded/local builds are
reported separately rather than assumed current. `update report` adds local
binary state, summary counts, and an explicit `need update` / `unknown` section;
`--fail-on-updates` gates automation. The JSON shape also carries a `spores`
section, currently `supported: false` until the Spore Store lands. `mycelium doctor` makes the
same comparison locally and adds `codesign`/`spctl` checks on macOS. Release
selection is semantic-version based and the latest manifest's signature is
verified before it is offered. See [docs/releases.md](docs/releases.md) for the
signing boundary and current notarization gap.

## SSH observation points

Ordinary Linux hosts can contribute their interfaces, connected routes, and
neighbor tables without becoming network appliances themselves:

```sh
mycelium add pris --driver linux --user ajmwagar
mycelium add lab-node.example.net --driver linux --user operator
mycelium scan
```

The Linux driver runs a fixed, read-only `iproute2` probe over SSH. It uses
OpenSSH configuration and agent credentials when no password or key is given.
Each observer hostname is also its site identity, so overlapping private
networks are stored separately (`pris/192.168.1.0/24` and
`lab/192.168.1.0/24`) instead of producing false address conflicts.

## Redfish servers

Redfish management controllers expose identity, power state, and thermal
telemetry. Power-on is write-gated and supports dry-run:

```sh
mycelium add 192.168.20.11 --driver redfish --user Administrator --password-env ILO4_PASS
mycelium call ilo-mxq33702q8 server.power-state
mycelium call ilo-mxq33702q8 server.thermal
mycelium call ilo-mxq33702q8 server.power-on --write --dry-run
mycelium console ilo-mxq33702q8
```

Controller passwords remain env-backed; inventory persists only the variable
name. Self-signed controller certificates are accepted, but transport remains
HTTPS-only.

`mycelium console` opens the HPE iLO4 SSH text console in the current terminal.
It accounts for iLO4's legacy SSH algorithms while preserving normal terminal
ownership, so boot prompts such as LUKS can be answered interactively. Press
`Esc` then `(` to leave `textcons` and return to the iLO CLI.

## UniFi access points

The built-in bounded Lua AP dialect uses the Rust-owned SSH transport for local
AP recovery and status. The native controller driver owns site-wide WLAN, AP,
and client state through the UniFi Network API. Controller credentials remain
environment-backed:

```sh
mycelium add 192.168.20.12:8443 --driver unifi-controller \
  --user "$UNIFI_CONTROLLER_USER" --password-env UNIFI_CONTROLLER_PASS
mycelium call <controller-id> wlan.list-ssids
mycelium call <controller-id> unifi.list-aps
mycelium call <controller-id> unifi.list-clients
mycelium call <controller-id> wlan.guest-enable \
  --param 'ssid=Guest' --param enabled=true --write --dry-run
```

The API projection deliberately excludes WLAN passphrases and unrelated
private controller fields. Guest-policy changes require `--write`; dry-run
resolves and displays the exact site and WLAN object without applying it.

Controller-managed UniFi APs also expose a local recovery surface over SSH.
The AP driver reads identity, adoption status, radio/SSID state, and associated
stations. Controller reassignment and reboot are mutations and require both
`--write` and an optional dry run first:

```sh
mycelium add 192.168.99.11 --driver unifi --user "$AP_USER" --password-env AP_PASS
mycelium call <ap-id> unifi.status
mycelium call <ap-id> wlan.list-ssids
mycelium call <ap-id> wlan.list-stations
mycelium call <ap-id> unifi.set-inform \
  --param url=http://192.168.99.20:8080/inform --write --dry-run
```

The saved inventory contains the environment-variable name, never the AP
password. UniFi network-wide configuration remains controller-owned; the AP
driver is for observation, recovery, and explicit adoption operations.

## Topology and resources

Enrolled peers publish public interface facts—interface names, IP addresses,
and MAC addresses—as part of their signed identity observation. A receiving
peer separately gossips the source address it observed on an authenticated mTLS
connection. The topology projection correlates those independent facts with
ARP, DHCP, mDNS, switch, and controller observations:

- Matching MAC evidence merges an anonymous discovered node into the stable
  peer identity.
- Receiver-observed addresses provide reachability evidence when DNS is absent.
- Conflicting IP/MAC evidence remains separate and produces a topology
  conflict; it is never silently merged.
- These are public inventory facts. They contain no credentials and grant no
  access or authority.

SSH planning prefers a correlated RFC1918 address, then another reachable
address, and only falls back to the hostname when no address evidence exists.

WireGuard site-link plans treat routed LAN prefixes as explicit exports. They
reject overlapping prefixes, preserve source addresses by default, and report
whether the planned path is direct, requires NAT traversal, or needs a relay.
One stable public endpoint is sufficient for a direct WireGuard relationship;
gateways behind NAT can initiate toward it without exposing their own listener.
Source NAT is an explicit compatibility choice (`--left-translation` or
`--right-translation source-nat`), never inferred from discovery. Prefix-based
1:1 translation remains a future intent because it requires an explicit mapped
prefix rather than a boolean switch.

Each peer periodically publishes a signed, bounded hardware graph covering
PCIe, USB, storage, and accelerators. Stable identities derive from the peer
identity plus the platform locator; raw device serial numbers are never
gossiped and are represented only by SHA-256 fingerprints.

```sh
mycelium topology
mycelium topology watch
mycelium resources
mycelium resources --kind gpu
mycelium resources --kind storage --node home-pi
mycelium resources show gpu/RESOURCE_ID
mycelium resources watch
mycelium services
mycelium services --kind mcp
mycelium services --kind adb --node agora-one
mycelium services watch
```

Topology answers where things are and how they connect. Resources answer what
usable things exist and what they can do. The topology projection carries only
resource attachment edges, so refreshing GPU or storage facts does not create a
new topology generation unless placement actually changes. Resource facts use
the provider-neutral `fpl-resource-observation` contract; Mycelium is one
optional producer, and discovery never grants authority.

Services are a separate projection of lightweight topology evidence. Mycelium
currently recognizes explicit MCP, DCP, Unibus, Isochrone, ADB, PostgreSQL,
MySQL/MariaDB, SQL Server, Redis, and IPFS/Kubo service or product names. Standard TCP
ports are treated only as derived-confidence evidence.
Recognition performs no additional network I/O. Endpoints, protocols, formats,
freshness, and provenance use the same provider-neutral observation envelope,
while each protocol retains its own session behavior and authorization.

For Kubo, Linux SSH observers additionally query `/api/v0/version` on already
observed loopback TCP listeners (5001, commonly remapped 5002, or a custom port
owned by a visible `ipfs`/`kubo` process). At most four probes run per scan,
each capped at two seconds and 4097 output bytes. Ports alone never identify
IPFS. Verified responses project `kind: ipfs`, `role: rpc`, Kubo version,
provenance and expiry. RPC access is administrative: these records have
`endpoint_scope: host-local` and **no invented LAN endpoint**. No pins, content,
keys, config or swarm changes are made. An IPFS process hint has unknown
endpoint scope; a gateway or reachable swarm endpoint is not inferred from it.
The observer needs `curl`; it never installs tools or elevates privileges.
Inspect with `mycelium scan --json` followed by `mycelium services --json`.

`mycelium targets` lists appliances explicitly enrolled behind management
drivers. The former `mycelium devices` spelling remains a compatibility alias;
it does not mean discovered hardware or usable resources.

Linux reads kernel facts from sysfs, including PCI IDs and drivers, negotiated
and maximum PCIe links, NUMA and IOMMU placement, USB port ancestry and speed,
and block-device/partition relationships. Darwin uses `system_profiler`'s JSON
interface. Apple integrated GPUs are represented as accelerators on an
`integrated` bus with a `metal` capability—not as discrete PCIe GPUs. Raw bus
enumeration remains available for troubleshooting through:

```sh
mycelium debug hardware
mycelium debug hardware agora-one --json
```

`mycelium hardware` remains a compatibility alias but is not the public
resource contract. Raw USB and PCI nodes are not promoted into usable resources
until a function probe identifies storage, camera, audio, or another typed
profile.

Linux inventory also reports registered TPMs as security modules. This is
read-only presence evidence, not attestation or proof that peer keys are protected.
See [hardware-backed peer secrets](docs/hardware-key-protection.md) for the sealing
boundary, recovery requirements and mixed-version rollout caveat.

## Owner-local credentials

Adapters that need a password or key hold a `geode://<realm>/<account>/<slot>`
reference, not the secret. `crates/geode` stores the opaque secret plus a purpose
allowlist and reveals it only through a bounded lease; secrets have a redacting
`Debug`, no `Serialize`, and zeroize on drop. Credential kind and credential
expiry are metadata, and no platform backend is selected automatically.

`geoded` serves `geode://` leases to other processes over an owner-only Unix
socket; the library remains the default for in-process use. See
[geoded](docs/geoded.md).

Optional connectors keep protocol behaviour out of the store:
`geode-passkey` (software WebAuthn/ES256), `geode-otp` (TOTP/HOTP 2FA), and
`geode-oauth` (PKCE, refresh, device authorization, OIDC discovery). Composio and
fpl-auth are reference profiles, not provider OAuth implementations. See
[geode](docs/geode.md) and [geode connectors](docs/geode-connectors.md).

## Security posture, STIG, and SIEM events

Every agent periodically publishes a bounded security-posture observation
signed by its existing node identity. Peers gossip the summary—not full scan
artifacts—and converge the latest report for each node:

```sh
mycelium security status
mycelium security events
mycelium security scan
```

On Debian-family Linux hosts the lightweight scan reports cached package
updates and reboot state. Scanner availability is explicit, so an absent CVE
or compliance backend is never represented as a clean result. Normalized,
bounded security events form the transport-neutral SIEM feed; a future sink
can export those records without changing the peer protocol. Linux observers
also normalize a bounded 15-minute journal window for SSH authentication,
sudo, kernel faults, and OOM events. Raw journals remain on the node; signed
gossip carries at most 128 normalized events with stable deduplication IDs.

OpenSCAP can run an explicit DISA STIG evaluation when compatible SCAP content
is installed:

```sh
mycelium security scan \
  --stig-content /usr/share/xml/scap/ssg/content/ssg-ubuntu2404-ds.xml \
  --stig-profile xccdf_org.ssgproject.content_profile_stig

# Generate a content-addressed remediation plan:
mycelium security scan \
  --stig-content /usr/share/xml/scap/ssg/content/ssg-ubuntu2404-ds.xml \
  --stig-profile xccdf_org.ssgproject.content_profile_stig \
  --remediation-plan

# Review, explicitly apply, and independently rescan the exact reviewed plan:
mycelium security remediation list
mycelium security remediation apply <plan-sha256> --write
mycelium security remediation verify <plan-sha256>
```

### SIEM export (JSONL and Loki)

Security events are signed and gossiped independently of SIEM delivery. An
authorized node can export its converged view through a durable, bounded spool;
an event is marked delivered only after the sink confirms it. Credentials are
never written to sink configuration—Loki stores only the name of an environment
variable containing its bearer token.

```bash
# Portable/manual runbook sink (also useful for testing parsers).
mycelium security sinks add jsonl local \
  /var/log/mycelium/security.jsonl --write

# Loki's native push endpoint. Tenant is optional.
export FPL_LOKI_TOKEN='...'
mycelium security sinks add loki central \
  https://loki.example.net/loki/api/v1/push \
  --token-env FPL_LOKI_TOKEN --tenant fpl --write

# Publish QoS 1 events to the nearest broker. Existing unibus-mqtt adapters
# redistribute the topic; Mycelium does not depend on Unibus internals.
mycelium security sinks add mqtt unibus-local 127.0.0.1 \
  --topic mycelium/security/events/v1 \
  --client-id mycelium-neo --write

mycelium security sinks list
mycelium security export run --dry-run
mycelium security export run --sink central --write
mycelium security export status
```

Configured sinks run automatically after the daemon's bounded 15-minute
security collection. `export run` is the deterministic manual runbook and
retry path.

The MQTT sink waits for a QoS 1 acknowledgement for every event before
advancing its durable spool. Broker credentials are referenced by environment
variable name using `--username-env` and `--password-env`; use `--tls` for a
server-authenticated TLS connection. The default topic is
`mycelium/security/events/v1`, which can be included in an `unibus-mqtt`
subscription filter without any Mycelium-specific code in Unibus.

Loki labels are deliberately low-cardinality: `site`, `hostname`, `category`,
`severity`, and `outcome`. Node and event IDs plus arbitrary event fields remain
in the structured JSON log line. Sink configuration and delivery state live in
`$MYCELIUM_HOME/security/siem/`; the spool refuses new events at its bound rather
than silently dropping them.

Network inspection placement is engine-neutral: coverage intent and observed
candidate facts produce a deterministic plan with scored placements and blind
spots. Suricata is not required. See
[`docs/inspection-placement.md`](docs/inspection-placement.md) for the candidate
contract and CLI runbook.

Fleet operations are projections over the same converged peer state. Node
classes are derived from signed platform, architecture, and site identity
rather than duplicated in a second inventory:

```sh
mycelium fleet status
mycelium fleet status --site wagar-house --platform linux
mycelium fleet exec --site wagar-house --platform linux -- uptime
```

Signed release manifests select artifacts by the peer's compatible Rust target.
Peers fetch matching bytes from any peer that has the same authorized SHA-256;
`MYCELIUM_ARTIFACT_REQUEST_SECS` can tune the idle retry interval (five seconds
by default) without changing chunk integrity or release authority.

Network intent uses the same vendor-neutral `ActionPlan` for EdgeOS, NETGEAR,
Linux, and future drivers. Generate JSON for review, preflight it without
writes, then explicitly apply the exact file:

```sh
mycelium networks plan cctv --json > cctv-plan.json
mycelium networks apply --plan cctv-plan.json --dry-run
mycelium networks apply --plan cctv-plan.json --write
```

Physical placement is a separate durable fact, not embedded in the logical
network or credentials. A binding can be reviewed before it is persisted:

```sh
mycelium networks bind cctv --device netgear-titan --port 1/g8 --tagged --dry-run
mycelium networks bind cctv --device netgear-titan --port 1/g8 --tagged --write
mycelium networks bindings cctv
```

DHCP policy declares only choices that cannot be inferred. The subnet,
prefix, gateway, and VLAN remain derived from allocation receipts:

```sh
mycelium networks dhcp set cctv --device edge-router --pool CCTV \
  --range 192.168.30.100-192.168.30.220 --dns 192.168.30.1 --dry-run
mycelium networks dhcp set cctv --device edge-router --pool CCTV \
  --range 192.168.30.100-192.168.30.220 --dns 192.168.30.1 --write
mycelium networks plan cctv --json > cctv-plan.json
mycelium networks apply --plan cctv-plan.json --dry-run
```

The daemon validates every action and read-only verification capability before
the first mutation. It stops at the first failed action or postcondition.
Plans with drift blockers cannot execute; unsupported DHCP, VLAN, or trunk
ownership remains visible rather than being guessed.

Full XCCDF evidence and generated plans remain local under
`$MYCELIUM_HOME/security/evidence/`; gossip carries their SHA-256 digests and
pass/fail/error/not-applicable counts. Mycelium refuses remediation-plan
generation when every rule is inapplicable to the host. Apply re-hashes the
script immediately before execution and refuses any bytes other than the
reviewed content-addressed plan. Verification is a separate operation and only
marks a plan verified when its post-apply scan has passing rules with no failed
or errored rules. Fleet drain and reboot policy remain separate orchestration
steps rather than being hidden inside a compliance script.

## Agent skills

The release binary carries the repo-owned skills under `skills/`, so the same
operational guidance can travel with a signed Mycelium update. Inspect or
install them without cloning the repository:

```sh
mycelium skills list
mycelium skills sync --dry-run
mycelium skills sync --write                       # Codex default
mycelium skills sync --target agents --write
mycelium skills install mycelium-network-operator --target claude --write
```

`--path DIR` supports another compatible agent. Installation writes the
standard `SKILL.md` plus optional `agents/openai.yaml` metadata atomically.
The repository files remain the sole source of truth; the CLI uses
`include_str!` rather than maintaining a second embedded copy.

## Development

```sh
cargo check --workspace
cargo test --workspace
```

Small, focused pull requests are welcome. Please include tests for behavioral
changes and keep device mutations behind the existing plan/`--write` boundary.

## License

Licensed at your option under either the [Apache License, Version 2.0](LICENSE-APACHE)
or the [MIT license](LICENSE).
