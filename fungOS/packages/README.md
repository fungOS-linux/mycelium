# Signed APT package qualification

The maintained publisher now lives in [`mycelium-linux/fungos/packages`](https://github.com/mycelium-linux/fungos/tree/main/packages).
Its migration and signed-generation improvements are committed locally as
`470591d` in that repository, pending push. This directory retains historical
qualification tooling and evidence; do not extend this legacy publisher in
parallel. FPL Cloud preparation lives in `shared-infra/projects/fungos/apt`.

Debian continues to supply the OS. Component owners build their `.deb` payloads;
this small Rust publisher calls `dpkg-scanpackages`, `apt-ftparchive` and GnuPG
to create a new signed repository generation. It does not build packages,
provision hosting, create production keys, or implement an APT replacement.

```sh
cargo check --locked --all-targets --manifest-path fungOS/packages/Cargo.toml
cargo test --locked --manifest-path fungOS/packages/Cargo.toml
cargo build --locked --release --manifest-path fungOS/packages/Cargo.toml
GNUPGHOME=/path/to/authorized/signing-home \
  fungOS/packages/target/release/fungos-apt-repository --write \
  /new/unpublished/generation FULL_SIGNING_FINGERPRINT testing package.deb
```

Run on Linux with `dpkg-dev`, `apt-utils`, GnuPG and GNU date. Use a writable
`TMPDIR` if the host's `/tmp` is quota-limited. Output must not exist. Package
names, versions and architectures come from `dpkg-deb`, not input filenames;
architecture filters otherwise silently omit files such as `core.deb`.
Only amd64/arm64 are supported in this first slice. Empty indexes fail closed.
The publisher keeps every supplied version, signs `InRelease` with SHA-256,
sets seven-day metadata expiry, verifies the signature and writes `READY` last.
Failure leaves an unpublished directory for inspection. Publish only complete
generations through the hosting owner's atomic promotion mechanism; retain
previous generations. No hosting or DNS endpoint is established here.

Clients use a repository-specific `Signed-By` keyring, never `trusted=yes` or
global `apt-key`. APT authenticates signed repository metadata and package
hashes, not individual embedded package signatures. See
[Debian's apt-secure documentation](https://manpages.debian.org/trixie/apt/apt-secure.8.en.html).
Production key admission/rotation must use the existing authority policy;
the disposable qualification key below must never be installed on fleet nodes.

## Qualification, 2026-10-06

Agora built/tested the publisher and a statically linked Rust test client.
The existing Unibus owner package fixtures and fungOS qualification image were
reused, not reimplemented. A fresh persistent ext4 image booted in QEMU/KVM,
one CPU/1 GiB, no NIC, no imported fleet identity or credentials.

The [serial evidence](qualification-20261006.log) records:

- Signed index accepted, altered Packages index rejected after clearing cached
  indexes. No insecure APT overrides.
- APT install `0.1.0`, upgrade `0.1.1`, recovery downgrade `0.1.0`.
- Operator conffile bytes retained; package operations did not restart the
  service. Explicit operator restarts passed TCP/systemd readiness checks.
- Actual disk reboot retained the package/configuration and started Unibus.
  Successful second-boot verification powered off only this disposable guest.

These are package lifecycle fixtures, not a claim about different production
Unibus implementations or application-state migration rollback. Readiness is
local socket presence plus active systemd state, not authenticated end-to-end
delivery. The guard requires root, the exact disposable DMI product and runtime
marker; never copy that marker to a real managed node.

Input fixture SHA-256:

- core: `e51125ac5f8644e57a2794fd839d5dd578c7a0d41962336e8b8e74ca7748b69a`
- upgrade: `4dc1e2e1a85d98819e0e8021de8c09e938c10858496e5dd2ae6ac9eba2de0aa7`

Raw work lives on Agora in
`/home/ajmwagar/.cache/fungos-apt-test-20261006`; test-only signing fingerprint
`BEEE083E596D124F6D00D7DB09288F49CB919396`. Private key stayed on the build
host; only its public export entered the guest. The failed empty-index attempt
is retained separately; `console-v3.log` is the successful run.

Repeat using the existing Unibus `docs/linux-core-package.md` clean-image
assembly runbook. Overlay this directory's `fungos-qemu-proof.service`, the
musl `apt-smoke` executable, signed generation and exported public key under
`/opt/fungos-apt`. Use the existing fungOS initramfs builder with a fresh
`ROOTFS_IMAGE_OUTPUT`; boot with `fungos.root=LABEL=FUNGOS_ROOT` and the exact
qualification DMI product. Do not use a running peer's disk.

## Ownership boundary

See [native update safety](update-safety.md) for dependency admission, durable
interruption recovery and application-level health checks. These do not change
APT's package ownership or imply an APT rollout backend exists.

No Mycelium APT backend is implemented yet. Fleet adoption needs an explicit
installer choice per component: APT or native binary activation, never both.
Version selection, staged rollout, drain, health verification and recovery
belong to Mycelium; dependency/file/conffile ownership belongs to APT/dpkg.
The running edge guest's native Unibus installation was left untouched.
