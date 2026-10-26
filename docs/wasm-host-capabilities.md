# WASM host capabilities: BLE, Unibus streams, signed modules

**Status:** design + inventory, 2026-10-26. No code in this unit: no
`Cargo.toml` change, no WIT file, no backend, no firmware blob.
**Scope:** one plan for three streams that were being designed separately:

1. absorb the COLMI BLE reversal host (`ring-host`) into the fleet wasmtime host;
2. expose Unibus streams to wasm guests with Mycelium controlling grants/ACL;
3. sign modules with Mycelium fleet identity.

**Why this file, not `host-access-grants.md`.** `docs/host-access-grants.md`
begins "`mycelium access host` reconciles local accounts, OpenSSH principals/KRL,
sudoers and PAM" (`docs/host-access-grants.md:1-5`). That document is the Linux
account reconciler. A wasm host is a *consumer* of the same authority graph, not
another reconciler, so extending that runbook would conflate two system
boundaries. `docs/access-control.md:1-10` is likewise the SSH/OIDC adapter.
This document is the missing consumer-side design and links back to both.

**Source legend.** Paths are relative to the repository named by the prefix:

| Prefix | Checkout | Mutability here |
|---|---|---|
| *(none)* | `ajmwagar/mycelium`, branch `pi/fungos-wasm-host` | this unit's only write target |
| `canvas:` | `~/src/fpl/canvas-current-workspace` @ `61cce16` (and its `.worktrees/`) | read-only |
| `neo:` | `averys-macbook-neo:~/Documents/src/reversal/colmi` | read-only over ssh |

Unibus references (`DESIGN.md`, `crates/unibus/...`) are `~/src/fpl/unibus`,
also read-only here.

Confidence tags are the ones the reversal tree already uses
(`neo:docs/host-vs-firmware-gap.md:7-8`): **[C]** confirmed from an artifact in
the repo, **[I]** inferred from code/structure but not exercised on hardware,
**[?]** open, needs the ring on a bench (or a second host).

---

## A. BLE facts inventory, with provenance

### A.1 The contract that exists today

`neo:host/wit/ring.wit` is a real component-model contract, but its package name
and function count do not match the prose around it.

| Fact | Value | Tag | Source |
|---|---|---|---|
| Package id | `ring:ble@0.1.0` | **[C]** | `neo:host/wit/ring.wit:10` |
| World | `ring-guest { import ble; export run }` | **[C]** | `neo:host/wit/ring.wit:66-72` |
| Types | `device-info{address,name,rssi}`, `characteristic{uuid,readable,writable,notifiable}`, `service{uuid,characteristics}`, `event{notification(list<u8>) \| disconnected}` | **[C]** | `neo:host/wit/ring.wit:12-38` |
| Verbs (actual) | **8**: `scan`, `connect`, `disconnect`, `services`, `read`, `write`, `subscribe`, `next-event` | **[C]** | `neo:host/wit/ring.wit:44-63` |
| Error type | `result<_, string>` — unstructured text | **[C]** | `neo:host/wit/ring.wit:8-9,44-63` |
| "five BLE verbs" | prose claim only; the WIT has 8 functions | **[C] mismatch** | `neo:host/README.md:38`, `neo:host/host/src/main.rs:1` vs `neo:host/wit/ring.wit:44-63` |

The five-vs-eight discrepancy matters: a design that promises "exactly five
verbs" and then links eight is exactly the kind of confident-wrong statement
that costs a hardware pass. Section B keeps all eight and names the capability
for each instead of preserving a slogan.

### A.2 What the guest actually implements

`neo:host/guest/src/lib.rs` is a protocol proof, not a complete ring stack.

| Fact | Value | Tag | Source |
|---|---|---|---|
| Frame size | exactly 16 bytes; any other length is rejected | **[C]** | `neo:host/guest/src/lib.rs:31-34` |
| Command byte | `raw[0] & 0x7f` | **[C]** | `neo:host/guest/src/lib.rs:37` |
| Error bit | `raw[0] & 0x80` | **[C]** | `neo:host/guest/src/lib.rs:38` |
| Checksum | `sum(raw[0..15]) == raw[15]` (additive, wrapping) | **[C]** | `neo:host/guest/src/lib.rs:35,40` |
| Payload | `raw[1..15]` (14 bytes) | **[C]** | `neo:host/guest/src/lib.rs:6,39` |
| DIS UUIDs | firmware `2a26`, hardware `2a27`, serial `2a25` | **[C]** constants; **[?]** readable on RT12CR2 | `neo:host/guest/src/lib.rs:11-13,73-75` |
| Notify characteristic | `6e400003-b5a3-f393-e0a9-e50e24dcca9e` | **[C]** | `neo:host/guest/src/lib.rs:82` |
| Bulk (`0xBC`) path | **not implemented in the guest**; the 16-byte decoder rejects it | **[C]** | `neo:host/guest/src/lib.rs:31-34` |
| DFU (`de5bf728`) path | **not implemented in the guest** | **[C]** | absent from `neo:host/guest/src/lib.rs` |
| Command/service semantics beyond DECODE + identity reads | not implemented; the guest ends after a notification drain | **[C]** | `neo:host/guest/src/lib.rs:80-114` |

So the statement "the guest owns the wire protocol" is true of the 16-byte
command frame only. The variable-length `0xBC`/DFU frames are still prose in
`neo:host/README.md:34-35` and Python in the tooling.

### A.3 Transport implementation facts (desktop)

| Fact | Value | Tag | Source |
|---|---|---|---|
| Backend crate | `btleplug = "0.11"` (BlueZ / CoreBluetooth) | **[C]** | `neo:host/host/Cargo.toml:13` |
| Runtime | `wasmtime = "34"`, `wasmtime-wasi = "34"`, tokio multi-thread | **[C]** | `neo:host/host/Cargo.toml:10-12` |
| Linker | `ring::ble::ble::add_to_linker::<State, HasSelf<State>>` | **[C]** | `neo:host/host/src/main.rs:135-139` |
| Adapter choice | first adapter only | **[C]** | `neo:host/host/src/ble.rs:61-65` |
| Writes | always `WriteType::WithoutResponse` | **[C]** | `neo:host/host/src/ble.rs:181` |
| Notification pump | one channel for **all** characteristics; UUID discarded | **[C]** | `neo:host/host/src/ble.rs:115-131` |
| `event.disconnected` | declared in WIT, **never emitted** by the host | **[C]** | `neo:host/host/src/main.rs:100-108` vs `neo:host/wit/ring.wit:36` |
| `connect` idempotence | WIT says "replaces the link error"; code disconnects then reconnects | **[C] mismatch** | `neo:host/wit/ring.wit:46-47` vs `neo:host/host/src/ble.rs:92-95` |
| WASI imports | dependency present, but not added to the linker | **[C] dead dep, ambient-authority hazard** | `neo:host/host/Cargo.toml:11`, `neo:host/host/src/main.rs:131-139` |
| Android backend | **not written**; JNI plan only | **[C]** | `neo:host/README.md:73,76-93` |
| Unibus publishing | **not written**; events are local | **[C]** | `neo:host/README.md:74` |
| Desktop backend "working" | means implemented, not proven against RT12CR2 | **[I]** | `neo:host/README.md:67-74` |

### A.4 Proven ring/wire facts

| Fact | Value | Tag | Source |
|---|---|---|---|
| First ring | COLMI Ring 2, `RT12CR2`, fw `RT12CR2_1.00.02_260929`, hw `RT12CR2_V1.0` | **[C]** | `neo:docs/rt12cr2-target.md:5-12,58-59` |
| Silicon family | Realtek RTL87xx / Bee2 AppPatch, **not** BlueX RF03 | **[C]** | `neo:docs/rt12cr2-target.md:23-25`; `neo:docs/firmware-ecosystem.md:64-118` |
| GATT services seen | `6e40fff0…` command, `de5bf728…` DFU, `180a` DIS, `fee7` Tencent | **[C]** | `neo:docs/rt12cr2-target.md:14-21` |
| HID side effect | macOS binds the ring as a mouse; it stops advertising until disconnected/forgotten | **[C]** | `neo:docs/rt12cr2-target.md:39-47` |
| Vendor command table | 72 `CMD_*` names over 66 ids, `0x01`–`0x78` | **[C]** | `neo:docs/host-vs-firmware-gap.md:14-43` |
| Tier A/B (app-only) coverage | time, battery, steps, sleep, HR, SpO2, BP, ECG presence, alarms, notifications, music, dials, OTA | **[C] presence**, **[?]** whether this image answers each | `neo:docs/host-vs-firmware-gap.md:62-107` |
| Raw memory read/write primitive | **absent** from the RT12CR2 image | **[C]** | `neo:docs/host-vs-firmware-gap.md:56` |
| DFU/OTA support | present; vendor `0x0F` hand-off and `de5bf728` | **[C]** | `neo:docs/host-vs-firmware-gap.md:57` |
| R11 code cave `0x00848052` | **not in this image** (payload ends `0x00847b3b`) | **[C]** | `neo:docs/host-vs-firmware-gap.md:58` |
| Bootloader integrity | ROM validates SHA-256; stale/incorrect digest bricks the ring | **[C]** | `neo:docs/host-vs-firmware-gap.md:123,126-129` |
| Secure boot signature | RSA fields zero, encryption flags clear on Realtek images | **[C]** integrity only, not a signature | `neo:docs/firmware-ecosystem.md:96-110` |
| DFU service/write/notify UUIDs | `de5bf728…` / `de5bf72a…` / `de5bf729…` | **[C]** APK decompile | `neo:docs/ota-apk-findings.md:15-18` |
| DFU frame | `[0xBC][cmd][len u16 LE][CRC-16/MODBUS u16][payload]` | **[C]** | `neo:docs/ota-apk-findings.md:20-26`; `neo:tools/ota_flash.py:36-41` |
| DFU commands | 5: start, init `[0x01][len u32][crc16][sum16]`, data `[block u16][≤1024 B]`, check, finish | **[C]** | `neo:docs/ota-apk-findings.md:28-38`; `neo:tools/ota_flash.py:7-12` |
| Block index | one-based, 1024-byte blocks, split again by negotiated MTU `0x2F` | **[C]** | `neo:docs/ota-apk-findings.md:40-43` |
| Notification capture evidence | `evidence/tap-capture-20261025T172014.log` is **0 bytes** | **[C] empty** | `neo:evidence/` listing |
| Multi-host lease behaviour | designed, not exercised on two hosts | **[I]** | `neo:host/README.md:40-58`; `neo:host/host/src/session.rs:40-51,110-138` |
| `ring.dis` / `ring.health.sample.v1` kinds | prose in the host README only; no publisher code | **[C] not implemented** | `neo:host/README.md:28,57-58,74` |

### A.5 We can build this today vs needs the ring on a bench

**Buildable today (no radio, no firmware):**

- the `fleet:ble@1.0.0` WIT contract and a fake backend behind a trait;
- all 8 verbs against a `BleBackend` mock, including named denials;
- the 16-byte frame codec, checksum/error-bit tests, DIS parsing, and the
  `0xBC`/DFU frame **builder** (the Python already proves the bytes:
  `neo:tools/ota_flash.py:36-41`);
- the Unibus stream bridge, backpressure/credit, cancellation, and kind-scoped
  authority against an in-process fake hub;
- signed manifests, generation floors, revocation, and reject-before-instantiate;
- the lease **schema** and verifier, with a fake clock and two fake host IDs.

**Needs the ring on a bench:**

- any GATT read/write against RT12CR2, including the DIS identity reads
  (`neo:host/guest/src/lib.rs:73-75` is unproven on this image);
- whether `0x03`, `0x15`, `0x69`, `0x6c` and friends answer on this build
  (`neo:docs/host-vs-firmware-gap.md:143-149` says labeling the 57 dispatch
  slots is the gating task);
- notifications: rate, framing, multi-frame reassembly, and the empty capture
  (`neo:evidence/tap-capture-20261025T172014.log`);
- DFU against hardware, rollback/dual-bank behaviour, and any flash;
- lease contention between two real hosts;
- macOS CoreBluetooth address stability and HID interference;
- the `0xBC` bulk path (read or write) end to end.

`neo:docs/custom-firmware-plan.md:193-208` already gates all flashing on a
read-twice full dump and a successful restore. Nothing in this design relaxes
that.

---

## B. One host ABI: `fleet:ble@1.0.0`

### B.1 Namespace decision

Rename `ring:ble@0.1.0` to **`fleet:ble@1.0.0`**. Reasons:

- `fleet:gpu@1.0.0` and `fleet:audio@1.0.0` already define the shape: one
  self-contained package, one interface, a per-interface typed error, no
  `world`, limits in the header comment rather than WIT
  (`canvas:.worktrees/gpu-audio-wit/crates/canvas-model-host/wit/fleet-gpu.wit:1-15`,
  `canvas:…/fleet-audio.wit:1-13`).
- `ring:ble` names a device family in the capability namespace. The host does
  BLE; the ring is one device on it. A second BLE device must not need a
  second package.
- The `fleet:` namespace is the allowlisted capability vocabulary the manifest
  validator already understands (`canvas:.worktrees/wasm-caps-manifest/crates/canvas-model-host/src/caps.rs:30-37`).

The ring-specific protocol stays in a guest, not in the package name.

### B.2 Why transport stays in the host and protocol stays in the guest

- **Transport is local and OS-specific.** Desktop is btleplug/BlueZ/CoreBluetooth
  (`neo:host/host/Cargo.toml:13`), Android is a JNI GATT callback
  (`neo:host/README.md:76-93`). A guest cannot hold a radio handle, a Bluetooth
  permission, or a JNI reference.
- **Protocol is device-specific and changes often.** The 16-byte frame, `0x80`
  error bit, `0xBC` bulk path, and `de5bf728` DFU are the ring's, not the OS's
  (`neo:host/README.md:32-38`). One `.wasm` then ships to desktop and Android
  unchanged when the protocol changes.
- **Capability surface is auditable at the seam.** The guest sees eight verbs
  and bytes; it never sees a MAC, a path, a socket, a clock, or an environment
  variable. That is the same argument as `fleet:gpu`/`fleet:audio`
  (`canvas:…/wit/README.md:9-13`).
- **No callbacks.** The guest polls `next-event`; the host never re-enters wasm
  from a radio callback. This avoids re-entrancy and matches the "no per-frame
  callbacks" rule (`canvas:…/fleet-gpu.wit:14`).

### B.3 The contract

```wit
// fleet:ble@1.0.0 — DEFINED, NOT SHIPPED until slice S1.
//
// Limits (host-enforced, not expressible as WIT types):
// - at most 64 devices per scan, 8 subscribed characteristics per link
// - scan ≤ 30 s; next-event ≤ 1 s per call; every host call has a deadline
// - read ≤ 512 B per call; write ≤ 512 B per call; the guest chunks longer frames
// - at most one link and one live radio lease per host
// - device handles are host-issued; no MAC/UUID path is accepted from a guest
// - no fs, net, clock, env, or device enumeration beyond scan results
package fleet:ble@1.0.0;

interface types {
  /// Host-issued handle for a scan result. Opaque; not an address.
  type device-handle = u32;

  record device {
    handle: device-handle,
    name: option<string>,
    rssi: option<s16>,
    /// Stable cross-host identity once the host has read DIS; absent until then.
    ring-id: option<string>,
  }

  record characteristic { uuid: string, readable: bool, writable: bool, notifiable: bool }
  record service { uuid: string, characteristics: list<characteristic> }

  variant event {
    /// The characteristic is included: today's host discards it.
    notification(char-uuid: string, data: list<u8>),
    disconnected(reason: string),
  }
}

interface ble {
  use types.{device, service, event};

  enum error {
    denied,        // capability or lease not granted to this module
    not-found,     // unknown/stale device handle or characteristic
    not-connected, // no live link
    leased,        // another authenticated host holds a live radio lease
    timeout,       // a bounded host call hit its deadline
    over-budget,   // frame/queue/scan limit exceeded
    not-ready,     // adapter or link is still coming up
    invalid,       // malformed argument (e.g. empty UUID)
    io,            // backend failure; text is logged host-side, not echoed raw
  }

  scan: func(timeout-ms: u32) -> result<list<device>, error>;
  connect: func(device: device-handle) -> result<_, error>;
  disconnect: func() -> result<_, error>;
  services: func() -> result<list<service>, error>;
  read: func(char-uuid: string, max-bytes: u32) -> result<list<u8>, error>;
  write: func(char-uuid: string, data: list<u8>) -> result<_, error>;
  subscribe: func(char-uuid: string) -> result<_, error>;
  next-event: func(timeout-ms: u32) -> result<option<event>, error>;
}
```

**What each verb requires.**

| Verb | Capability | Notes |
|---|---|---|
| `scan` | `fleet:ble.observe` | host returns handles; raw addresses never leave the host |
| `connect` | `fleet:ble.connect` | host mints/binds the radio lease to the module's authenticated signer |
| `disconnect` | `fleet:ble.connect` | releases only the caller's lease |
| `services` | `fleet:ble.observe` | GATT discovery on the current link |
| `read` | `fleet:ble.observe` | bounded; `max-bytes` is a request, host may return less |
| `write` | `fleet:ble.write` | bounded; the only mutating verb |
| `subscribe` | `fleet:ble.observe` | enables notifications; no callback |
| `next-event` | `fleet:ble.observe` | poll with a short deadline; `none` = deadline, not error |

`fleet:ble.connect` is separate from `fleet:ble.observe` because connecting
*owns the radio* (the exclusive lease), while observing a link the module
already owns is cheaper. A case that only consumes Unibus `ring.*` events needs
**no BLE capability at all**.

**Deliberate differences from `ring:ble@0.1.0`:**

1. `address: string` → `device-handle` + optional `ring-id`. This is the BLE
   analogue of "CIDs never paths": a guest cannot target an arbitrary MAC, and
   the host keys its session store on the stable `ring-id`
   (`neo:host/host/src/session.rs:29-37`), not the platform address.
2. `result<_, string>` → typed `error`. `fleet:gpu`/`fleet:audio` already
   require this (`canvas:…/fleet-gpu.wit:63-73`).
3. `event.notification(list<u8>)` → `notification(char-uuid, data)`. The
   current host multiplexes all notifications into one channel and drops the
   UUID (`neo:host/host/src/ble.rs:115-131`), so a guest cannot tell the command
   service from DFU. The current `disconnected` variant is unreachable
   (`neo:host/host/src/main.rs:100-108`); this contract makes it real.
4. `write` may need `with-response` for some characteristics. v1 keeps one
   `write` and makes the host choose (without-response where supported,
   with-response otherwise), because exposing the GATT write type is a
   transport detail. If hardware proves otherwise, add
   `write-with-response` in `fleet:ble@1.1.0`; do not smuggle it as a bool.
5. No `world`. `fleet:gpu`/`fleet:audio` deliberately omit one because grants
   are per manifest (`canvas:…/wit/README.md:20-24`). The ring guest keeps its
   own local world (`import fleet:ble/ble; export run(...)`) until a shared
   `fleet:app@1` runner world exists. Putting `run` in the capability package
   would make every BLE consumer export the ring's entry point.

### B.4 Lease: an authenticated claim, not a guest field

The current lease is a local JSON record keyed on the platform address
(`neo:host/host/src/session.rs:40-45,110-130`; `neo:host/host/src/main.rs:45-48`).
Two problems:

- it is keyed on `address`, contradicting the same file's advice to key on
  `hardware_version + serial` (`neo:host/host/src/session.rs:29-37`) — macOS
  CoreBluetooth addresses are per-host UUIDs;
- it is not signed, so another host can mint one by editing JSON.

The design replaces it with a signed record under the fleet identity domain:

```text
Lease {
  fleet_id, ring_id, holder_peer_id, holder_endpoint_generation,
  claimed_at, expires_at, nonce, generation
}
signed by the holder's fleet identity key, domain "mycelium/fleet-identity"
```

Rules:

- the **host**, not the guest, signs and publishes the lease;
- `fleet:ble.connect` fails `leased` unless the caller holds the newest valid
  lease for that `ring_id`; expiry is checked against local time;
- the host that reads `ring.dis` verifies the lease before treating the
  publisher as the radio owner;
- a guest can neither read nor write the lease record. It only observes the
  typed outcome `leased`.

This is the mechanism that makes "radio ownership is a lease, not a cluster"
(`neo:host/README.md:40-48`) safe across hosts. It does not change the local
advisory behaviour until S3 wires signing; until then, the lease is explicitly
**local and unsigned**, and tools must say so.

---

## C. Unibus streams in wasmtime

### C.1 What Unibus already guarantees

From `~/src/fpl/unibus/DESIGN.md` and `crates/unibus/src/grants.rs`:

- every message kind maps to exactly one QoS class: command, stream, snapshot
  (`DESIGN.md:66-79`);
- **stream** means latency over completeness; stale bytes are dropped, never
  queued (`DESIGN.md:71`);
- kinds are namespaced, lowercase, at least two dot-separated segments
  (`grants.rs:87-106`); a kind cannot contain a space;
- capabilities are namespaced strings; unknown grant fields are rejected
  (`DESIGN.md:49-57`; `grants.rs:33-62`);
- a receiver capability does not imply publish authority (`DESIGN.md:55-57`).

**Kind-string correction.** `neo:host/README.md:28` writes
`ring.dis device.v1`, which reads like one kind. It cannot be: Unibus rejects a
space (`grants.rs:89-93`). The only consistent reading is kind `ring.dis` with
schema/version `device.v1`; likewise kind `ring.health.sample` with schema
`sample.v1`. The reversal author must confirm which of `ring.dis` or
`ring.dis.device` is intended; until then, treat `ring.dis` as **[I]** and do
not publish it. This document assumes kind + separate schema field.

### C.2 The contract

```wit
// fleet:stream@1.0.0 — DEFINED, NOT SHIPPED until slice S2.
//
// Limits (host-enforced):
// - at most 8 live subscriptions per module
// - chunk ≤ 64 KiB; read ≤ 64 KiB per call; write ≤ 64 KiB per call
// - per-stream queue ≤ 1 MiB, per-module ≤ 4 MiB (configurable downward)
// - stream QoS: oldest bytes are dropped, never queued behind new ones
// - no callbacks, no clock, no socket, no endpoint, no producer enumeration
package fleet:stream@1.0.0;

interface stream {
  enum mode { read, write, read-write }

  record chunk {
    kind: string,
    schema: string,
    /// Monotonic per stream; lets a consumer detect drops without a clock.
    sequence: u64,
    data: list<u8>,
  }

  enum error {
    denied,          // kind/mode not granted to this module
    unknown-stream,  // stale or foreign handle
    closed,          // peer closed or the stream was cancelled
    over-budget,     // chunk/queue/module limit exceeded
    stale,           // QoS dropped the window; caller should resync from a snapshot
    not-ready,       // host is reconnecting to the bus
    invalid,         // malformed kind/schema/payload
  }

  /// The only way to name a stream. Authority is checked here.
  subscribe: func(kind: string, schema: string, mode: mode) -> result<subscription, error>;

  resource subscription {
    read: func(max-bytes: u32) -> result<option<chunk>, error>;
    /// Returns bytes accepted, which may be less than offered (backpressure).
    write: func(data: list<u8>) -> result<u32, error>;
    /// Bytes that can be written now without blocking.
    credit: func() -> result<u32, error>;
    close: func() -> result<_, error>;
  }
}
```

`resource subscription` is deliberate. A `u64` handle can be guessed or reused
after close; a component-model resource is unforgeable, owned by the store, and
dropping it is cancellation. That satisfies the hard constraint "a guest cannot
obtain a stream it was not granted" structurally, not by convention.

### C.3 Where authority is checked

Three places, in this order:

1. **Link time.** The host builds the linker from `EffectiveCaps`. If
   `fleet:stream` is not effective, the `fleet:stream/stream` import is not
   added, and instantiation fails with the normal "unknown import" path. This
   is the same pattern `caps.rs` is designed for: it is a pure decision, and
   the linker is its only consumer (`canvas:…/src/caps.rs:7-14`).
2. **`subscribe`.** Even with `fleet:stream`, the guest may only subscribe to a
   kind/schema/mode named in its signed manifest and permitted by the principal
   grant and host policy. The host maps the Unibus kind to the module's granted
   set; a mismatch is `denied`, not an empty stream.
3. **Per call.** `read`/`write` re-check that the resource is still live, the
   module's caps have not been revoked, the lease (for radio-owned kinds) is
   still valid, and the quota is not exceeded.

### C.4 How a guest names a stream, and why it cannot forge it

- The guest passes a **kind and schema** to `subscribe`; it never passes a
  producer id, endpoint, token, zone, or lease.
- The host owns the Unibus connection and the producer identity. A module is a
  sub-tenant of the host, not a bus peer. It cannot register, heartbeat, or
  publish under the host's producer id unless the host's policy explicitly
  allows that kind for it.
- For `ring.dis`, the host publishes only while it holds a **verified signed
  lease**. A guest that wants to write ring commands needs
  `fleet:ble.write` plus `fleet:stream` for the command kind plus the lease;
  a guest that merely reads `ring.dis` needs the read grant, not the radio.
- The lease is never a WIT field. It is an authenticated host-side claim
  (Section B.4). A guest cannot mint one because it cannot sign with the host's
  identity key and cannot reach the bus.

**Decision to confirm:** should a wasm module ever be a first-class Unibus
producer with its own `producer_id` and grant? The recommendation is **no for
S2**: the host is the producer, modules are sub-tenants. That keeps Unibus L1
ignorant of wasm, avoids a second grant database, and gives one revocation
point per host. If modules later need independent producer identity, extend
Unibus grants from the same authority records rather than teaching the hub
about wasm.

### C.5 Backpressure and cancellation

- The host keeps one bounded ring per stream. `read` copies at most
  `max-bytes`; if the guest is slow, the **oldest** stream bytes are dropped and
  `sequence` records the gap (`DESIGN.md:71`).
- `credit` is the only backpressure signal; `write` returns accepted bytes so a
  guest must handle partial acceptance. There is no blocking write.
- Dropping the `subscription` resource cancels; `close` is explicit and
  idempotent. No host callback ever re-enters wasm.
- A module that exceeds its budget gets `over-budget`; it is not silently
  throttled into looking healthy.

---

## D. Grants are Mycelium authority, not a new store

### D.1 What already exists and must be reused

| Primitive | Where | What it gives us |
|---|---|---|
| Root-signed authority graph, one delegation level | `docs/authority.md:1-24`; `crates/myceliumd/src/authority.rs:51-181` | trust root, `access.publish`/`release.publish`/`package.promote`, revocation wins regardless of arrival order |
| `AuthorityResolver` | `crates/myceliumd/src/authority.rs:56-63,78-131` | pure, offline, caller-supplied `now`; invalid records ignored; auditable `AuthorityDecision` |
| Fleet identity records | `crates/mycelium-peer-protocol/src/identity.rs:14-49,99-192` | Ed25519 records under `mycelium/fleet-identity`, bounded ASCII labels, canonical lowercase hex |
| Generations + revocations | `identity.rs:199-291` | validity intervals, retired generations, permanent revocations, authority-vs-peer revocation rights |
| Capability intersection | `canvas:…/src/caps.rs:130-197` | manifest ∩ grants ∩ policy, default deny, clamp only downward |
| Host access qualification | `docs/host-access-grants.md:7-19,98-113` | the signed-grant/revocation/evidence discipline this consumer must copy |

The identity library is explicitly **not wired**: "It is a library foundation,
not an active replacement for the daemon's inner mTLS. Enrollment issuance,
persistent verification state, gossip distribution and runtime Iroh handshake
integration remain to be wired" (`docs/fleet-identity.md:3-6`). The wasm host
must not pretend otherwise. It consumes the records; it does not invent a
second identity service, a second grant database, or a second revocation list.

### D.2 Resolution path

```text
module bytes ──sha256──┐
                       ├─> signed ModuleManifest ──> fleet-identity verify
manifest fields ───────┘         │                         │
  module_cid, caps,              │                         ├─ fleet match
  streams, version,              │                         ├─ issuer in trust set
  fleet, generation,             │                         ├─ generation floor
  abi, signer, signature         │                         └─ not revoked
                                 v
                    effective_caps(manifest, grants, policy)
                                 │
                    ┌────────────┴────────────┐
                    v                         v
          Linker exposes only        per-call checks: kind,
          effective imports          lease, quota, revocation
```

Concretely:

1. Read the manifest and wasm bytes from the module source.
2. Reject if `sha256(wasm) != manifest.module_cid` or size differs.
3. Verify the manifest signature with `manifest.signer`'s Ed25519 key under the
   `mycelium/fleet-identity` domain.
4. Verify the signer's **membership** record: same fleet, issuer in
   `membership_issuers`, `now` inside validity, generation ≥ persisted floor,
   credential not revoked. This is `verify_iroh_peer`'s logic without the Iroh
   handshake (`identity.rs:210-291`); factor the membership check so both
   callers share it.
5. Verify the signer may publish modules: root, or an active root-signed
   delegation carrying the new `module.publish` capability (Section E).
6. Verify the module's own generation ≥ the persisted floor for `module_id`,
   and that `credential_id` is not revoked.
7. Run `effective_caps`. The new caps are `fleet:ble.observe`,
   `fleet:ble.connect`, `fleet:ble.write`, and `fleet:stream`; the manifest also
   carries a `streams` map (Section C.3) and per-interface limits.
8. Build the linker from the effective set. Build the store with the effective
   limits (fuel, epoch, memory), reusing the canvas host's existing budgets
   (`canvas:…/src/wasm.rs:44-82,287-322`).

### D.3 What must be built to wire it

1. **Identity issuance/persistence.** The library returns an authenticated peer
   id; it does not issue, persist, or distribute records
   (`docs/fleet-identity.md:28-46`). The host needs a durable store for
   revocations and generation floors, and a policy-freshness bound for offline
   operation.
2. **`module.publish` authority.** Add a narrow `AuthorityCapability` variant
   and its resolver check next to `access`/`release`/`package`
   (`crates/myceliumd/src/authority.rs:133-181`;
   `crates/mycelium-peer-protocol/src/lib.rs:824-840`). Do not reuse
   `release.publish`: publishing a host release and authorizing arbitrary module
   caps are different blast radii.
3. **Module statement.** Add a `Module` variant to `IdentityStatement`
   (or a sibling record with the same domain and envelope). Adding a variant is
   a protocol-version change; old verifiers reject unknown `kind` because the
   enum is tagged (`identity.rs:17-38`), which is the correct fail-closed
   behaviour.
4. **Per-module generation floors.** `IdentityTrust` today has one membership
   floor and one endpoint floor (`identity.rs:199-206`); module rollback needs a
   map keyed by `(fleet_id, module_id)`.
5. **Manifest fields in `caps.rs`.** Add `streams`, `abi`, `module_cid`,
   `fleet`, `generation`, `signer`, `signature` to `AppManifest`; keep
   `deny_unknown_fields` so a typo fails parsing (`caps.rs:62-69`). Add the four
   new caps to `KNOWN_CAPS` (`caps.rs:30-37`).
6. **A grant source adapter.** `PrincipalGrants` is currently a struct supplied
   by the caller (`caps.rs:71-77`); populate it from converged Mycelium
   authority records/Unibus grants, never from a module-provided file.
7. **A lease signer/verifier** using the host's fleet identity key, with a
   persisted generation and revocation check (Section B.4).
8. **One wasmtime version.** Canvas is on 24 (`canvas:…/Cargo.toml:20`);
   `ring-host` is on 34 (`neo:host/host/Cargo.toml:10`). The component-model
   linker API differs (the `HasSelf` note at `neo:host/host/src/main.rs:132-138`).
   Pick one before S1, or the host pays for two APIs and two audits.

---

## E. Module signing

### E.1 Decision: sign the manifest, bind the bytes by digest

**Sign the manifest.** Do not sign the wasm bytes separately, and do not sign
only the bytes.

Justification:

- The authority-bearing fields are not in the bytes: caps, stream kinds, ABI
  version, fleet, generation, version, limits, module id. Signing only the bytes
  authenticates code that could be paired with any manifest, including one with
  `fleet:ble.write` and `fleet:stream` for every kind.
- Signing only the manifest without binding the bytes lets an attacker swap the
  wasm under a valid manifest. The manifest therefore contains
  `module_cid = "sha256:<64 hex>"` and `size`; the loader recomputes the digest
  before compiling. That is the same content-addressing discipline as
  `PackageManifest` (`crates/mycelium-peer-protocol/src/lib.rs:732-816`).
- A separate signature over the bytes adds a second key/rotation surface with
  no additional guarantee once the digest is checked. If a registry ever stores
  bytes and manifest in different trust domains, a detached signature can be
  added as a future field; it is not needed for v1.

### E.2 Signature domain and statement

Use the existing `mycelium/fleet-identity` domain
(`crates/mycelium-peer-protocol/src/identity.rs:14`). Concretely:

```json
{
  "kind": "module",
  "credential_id": "org.fpl.ring-protocol:g1",
  "module_id": "org.fpl.ring-protocol",
  "module_cid": "sha256:<hex>",
  "size": 123456,
  "abi": "fleet:ble@1.0.0",
  "version": "0.1.0",
  "generation": 1,
  "caps": ["fleet:ble.observe", "fleet:stream"],
  "streams": {"ring.dis": "read"},
  "limits": {"memory_mb": 16, "fuel": 50000000, "epoch_ms": 1000}
}
```

wrapped in the existing `IdentityRecord` envelope (`protocol_version`,
`fleet_id`, `signer`, `statement`, `signature`). `fleet_id` is on the envelope,
not in the statement. `credential_id` is unique per (module, generation) so an
existing `Revoke { peer_id, credential_id, revoked_at }` tombstone can retire one
build without inventing a module-specific revocation type; `module_id` is the
stable name used for the generation floor. Reusing the envelope and domain
means generation, validity, revocation, canonical hex, and signature verification
are the same code path, not a parallel crypto implementation.

### E.3 Verify before instantiate

Order is part of the security property; no step is advisory:

1. parse manifest with `deny_unknown_fields`;
2. recompute `sha256(bytes)` and compare to `module_cid` and `size`;
3. verify the record signature (`verify_signature`);
4. require `record.fleet_id == local fleet`;
5. require `manifest.abi` is an ABI this host implements;
6. require the signer's membership is currently valid and not revoked;
7. require the signer is authorized for `module.publish`;
8. require `manifest.generation >= persisted floor(module_id)`;
9. require the module credential id is not revoked;
10. run `effective_caps`; any requested cap that is unknown, ungranted, or
    policy-denied rejects the module;
11. only now compile and instantiate.

Revocation and generation floors are persisted across reboot, as the identity
doc requires (`docs/fleet-identity.md:41-46`). A disconnected host accepts only
within its policy-freshness bound; it does not trust stale state forever.

### E.4 What a rejected module looks like

Loud, named, no fallback, exit 1. Mirror the scene path's stable error codes
(`canvas:…/src/wasm.rs:114-165,180-205`) rather than printing "invalid module":

| Code | Meaning |
|---|---|
| `module_unsigned` | no manifest/signature and the host is not in explicit dev mode |
| `module_signature` | bad signature or malformed record |
| `module_fleet` | manifest fleet != local fleet |
| `module_unsupported_abi` | `abi` not implemented by this host |
| `module_signer` | signer is not a valid fleet member or lacks `module.publish` |
| `module_generation` | generation below the persisted floor |
| `module_revoked` | module credential revoked |
| `module_digest` | bytes do not match `module_cid`/`size` |
| `module_caps` | caps unknown/ungranted/policy-denied |

Example:

```text
canvas-model-host: module rejected: module_signature (signer=3f2a…, "not a fleet member")
```

A dev mode that loads unsigned modules must be a build feature and must print
`module_unsigned` plus the module path, never silently proceed. The default
binary refuses.

### E.5 Trust root and who may sign

- **Trust root:** the configured Mycelium authority roots, by public key id
  (`docs/authority.md:4-24`), plus the enrollment bundle's membership issuers.
  This is the same root the fleet already uses for access and release records.
  No new PKI, no module-specific root.
- **Who may sign:** the root, or a delegated **module publisher** key carrying
  the new `module.publish` capability, one level deep like every other
  delegation (`docs/authority.md:22-24`). The publisher key must also have a
  valid fleet membership in the target fleet. Recommended practice: one
  delegated publisher per build system/fleet, not every peer; rotate by
  publishing a new delegation and revoking the old one.
- **What a verifier trusts locally:** fleet id, issuer set, revocation set, and
  generation floors from its own enrollment/policy state — never from the module
  or the connecting peer (`docs/fleet-identity.md:29-39`).

**Alternative to reject:** "any enrolled peer may sign modules." It makes every
compromised machine a module publisher. Membership authenticates a machine; it
does not authorize publishing code (`docs/fleet-identity.md:15-18`).

---

## F. Sequencing and done-means

The order is chosen by dependency, not by enthusiasm:

```text
S0  freeze contract + capability vocabulary (this doc)
S1  fleet:ble ABI + BLE backend behind a trait
S2  fleet:stream bridge to Unibus
S3  signed manifests, generations, revocation
```

S2 and S3 both depend on S1's capability vocabulary; they are otherwise
independent and can run in parallel. **S3 must land before any module is
fetched from a peer, the network, or a shared store.** Until then, S1/S2 only
load modules from an explicitly local path in a dev build.

### S0 — contract freeze (docs only)

- **Deliver:** this document; the `fleet:ble`/`fleet:stream` decisions; the
  kind/schema correction; the signing-scope decision.
- **Prove:** `git log --oneline -1` on `pi/fungos-wasm-host`; review sign-off
  from the human on the three decisions at the end.
- **Not in slice:** any WIT file, any code, any dependency change, any firmware
  or private artifact.

### S1 — host ABI + BLE backend behind a trait

- **Deliver:** `crates/canvas-model-host/wit/fleet-ble.wit`;
  `BleBackend` trait + mock backend; a `fleet-ble` feature (off by default);
  linker gating from `EffectiveCaps`; typed errors; host-call deadlines; the
  scene path stays import-free.
- **Prove:**

  ```sh
  cargo test -p canvas-model-host fleet_ble -- --nocapture
  cargo test -p canvas-model-host wasm_scene
  ```

  The first runs a fixture guest through all eight verbs against the mock,
  including: `write` denied without `fleet:ble.write`; `connect` denied without
  `fleet:ble.connect`; `leased` with a fake second host; `timeout`; and
  `over-budget`. The second proves the scene world still rejects any import
  (`canvas:…/src/wasm.rs:303-305`) and still passes fuel/epoch/memory limits.
- **Not in slice:** Android JNI, any real BLE pass, DFU, `0xBC` bulk, Unibus,
  signing, multi-host lease signing. A hardware run is **blocked** on a ring or
  the CAT S22; see G.2.

### S2 — Unibus stream bridge

- **Deliver:** `fleet-stream.wit`; host-side Unibus client; kind/schema →
  capability check; per-stream credit/backpressure; cancellation; signed lease
  plumbing behind a feature; fake hub for tests.
- **Prove:**

  ```sh
  cargo test -p canvas-model-host stream_bridge
  ```

  Cases: granted kind reads a bounded chunk; ungranted kind is `denied`; a
  forged/foreign resource is `unknown-stream`; a slow reader loses the oldest
  bytes and sees a `sequence` gap; `write` returns partial acceptance; drop
  cancels; module budget is enforced. An optional live test is gated by
  `UNIBUS_ENDPOINT` and `#[ignore]`, so CI never needs a bus.
- **Not in slice:** modules registering as Unibus producers, new hub/QUIC
  behaviour, cross-host lease proof (needs two hosts and a ring), QoS changes.

### S3 — signed manifests

- **Deliver:** module manifest schema; `module.publish` authority capability;
  `IdentityStatement::Module`; per-module generation floors; revocation
  persistence; verify-before-instantiate; the named rejection codes.
- **Prove:**

  ```sh
  cargo test -p canvas-model-host module_manifest
  cargo run -p canvas-model-host -- wasm scene /tmp/unsigned.wasm --assets ...
  ```

  The test table covers: tampered signature, wrong fleet, unsupported ABI,
  untrusted signer, missing `module.publish`, replayed generation, revoked
  module, digest mismatch, unknown/ungranted cap. The second command must exit
  1 with `module_unsigned`; a signed positive fixture must run. Authority
  explainability is shared with the existing CLI:

  ```sh
  mycelium authority explain module.publish <signer-id>
  ```
- **Not in slice:** key ceremony/HSM, key distribution service, automatic
  rotation, Android packaging, a module registry.

---

## G. Risks, recorded not hidden

### G.1 3.8 GB untracked research tree (one disk from loss)

`neo:~/Documents/src/reversal/colmi` is untracked in its parent repo
(`git status --porcelain colmi` → `?? colmi/`) and is 3.9 GB. The breakdown
matters more than the total: `private/` 2.2 GB (vendor firmware, decompiled APK,
SDK repos), `host/` 1.8 GB (mostly `target/` build artifacts), `ghidra/` 8.3 MB,
`docs/` 56 KB, `tools/` 112 KB, `evidence/` 16 KB. The **unique, unbacked**
content is the private tree, the Ghidra project, the docs, the tools, and the
firmware hashes — not the build cache.

- **Commit policy question:** the tree's own rule is that vendor firmware and
  downloaded SDK source live in git-ignored `private/`
  (`neo:README.md` "Ground rules"). The `.gitignore` ignores `private/`,
  `__pycache__/`, `*.pyc` (`neo:.gitignore`) but **not** `host/target/`. A
  blanket `git add colmi` would commit 1.8 GB of build artifacts and still not
  commit the firmware. Recommendation: add `host/target/` to `.gitignore`,
  commit docs/tools/evidence/host **source** (a few MB, no binaries), keep
  `private/` ignored, and put `private/` + `ghidra/` on an actual backup target.
  This needs an explicit owner decision; this unit cannot make it from here.
- **Evidence gap:** `evidence/tap-capture-20261025T172014.log` is 0 bytes. Do not
  cite it as notification evidence.
- **Licensing:** the vendor images and decompiled app are not ours to
  redistribute. Commit hashes, sizes, container fields, and factual notes
  (`neo:evidence/firmware-inventory.json`) — not images. The inventory already
  carries SHA-256 and sizes, which is enough to prove provenance without
  shipping bytes.

### G.2 No BLE hardware on this host

There is no ring and the CAT S22 is detached; the `bt-hardware-pass` work is
blocked. Consequences:

- S1's hardware half cannot be proven here; only the mock/contract half can.
- macOS CoreBluetooth is the likely first path (`btleplug`), but macOS binds the
  ring as a HID mouse and stops it advertising until forgotten
  (`neo:docs/rt12cr2-target.md:39-47`). Any "just scan on the laptop" plan must
  account for that.
- CoreBluetooth exposes a per-host UUID, not the printed MAC; the stable
  `ring_id` must come from DIS hardware/serial, which is itself **[?]** on this
  image. The current prototype keys the lease on the address
  (`neo:host/host/src/main.rs:45-48`), which will not roam correctly.
- Do not schedule a firmware flash on the strength of this document. The
  safety gates remain `neo:docs/custom-firmware-plan.md:193-208`.

### G.3 macOS/CoreBluetooth behaviour generally

- Adapter selection is "first adapter" today (`neo:host/host/src/ble.rs:61-65`);
  a machine with a dongle and a built-in radio needs explicit policy.
- Always `WithoutResponse` (`ble.rs:181`) is wrong for characteristics that
  require an acknowledged write; the ABI must not expose the GATT write type,
  but the backend must choose correctly.
- Notification attribution is lost (`ble.rs:115-131`); the new ABI includes the
  characteristic UUID, but the backend must actually carry it.
- Host calls can block. A wasm fuel/epoch budget does not preempt a blocking
  `connect`/`read` (`canvas:…/src/wasm.rs:69-82`). Every BLE host call therefore
  needs its own deadline and must never hold a lock across a call. This is a
  design requirement, not an optimisation.

### G.4 Python tooling vs the fleet's bash/Lua-only policy for new glue

The reversal tree's executable glue is Python (`ota_flash.py`,
`pack_bx_ota.py`, `inventory_firmware.py`), and it already produces verified
bytes (`neo:tools/ota_flash.py:36-41`; `neo:evidence/README.md:32-42`). The fleet
policy constrains **new** glue to bash/Lua, not historical research tooling.

Recommendation: leave the working Python as a reference implementation and a
test oracle; do not rewrite it in this program. Any glue that the host runs in
production goes in Rust (or bash for setup), not in new Python. Port the two
formats that must execute in the host — the 16-byte codec and the `0xBC` DFU
frame builder — to Rust with the Python outputs as golden vectors. Do not
introduce a Python runtime dependency into the host.

### G.5 Firmware image licensing and provenance

- Vendor firmware/SDK/APK remain vendor property; no redistribution.
- The Realtek images are unsigned and unencrypted but still integrity-checked
  (`neo:docs/firmware-ecosystem.md:100-110`). "Unsigned" does not mean "ours".
- Any custom image must be built from the SDK under that SDK's licence, and the
  ring remains a one-way door until a verified recovery path exists
  (`neo:docs/custom-firmware-plan.md:193-208`).
- This design does not need firmware changes. Everything in S1–S3 is host-side.
  Reserve firmware work for the three Tier C items
  (`neo:docs/host-vs-firmware-gap.md:109-129`), on a sacrificial unit.

### G.6 Two wasmtime hosts existing at once

Today there are two hosts with different assumptions:

| | `canvas-model-host` | `ring-host` |
|---|---|---|
| wasmtime | 24 | 34 |
| module model | core wasm, no component model | component model |
| imports | **none, by design** | `ring:ble` |
| budgets | fuel, epoch, store limits, module cap (`canvas:…/src/wasm.rs:44-82`) | none visible in `main.rs` |
| role | scene transform + video producer | ring protocol runner |

Keeping both costs: two wasmtime APIs (the `HasSelf` linker shape changed), two
audit surfaces for sandboxing, two sets of limits (only one is real), and a
drift risk where the capability host is the one without budgets. The
recommendation is **one runtime crate** with two binaries/backends: port the
`ring-host` BLE backend and WIT ideas into `canvas-model-host`'s runtime and
retire its wasmtime layer. That means picking a single wasmtime version
(upgrade canvas to 34, or port the backend to 24). This is a human decision
because it changes the canvas dependency graph.

**Non-negotiable safety rule:** adding imports must not weaken the scene path.
The scene `Module` check that rejects any import
(`canvas:…/src/wasm.rs:303-305`) stays. Capability modules use a **separate**
component world and a separate loader entry point; a scene `.wasm` still cannot
import `fleet:ble`, and an app module cannot claim to be a scene.

---

## Decisions a human must confirm

1. **Host target.** One runtime crate, with `canvas-model-host` as the surviving
   wasmtime host and `ring-host`'s BLE backend ported into it; single pinned
   wasmtime version (24 or 34). Reject "keep both hosts".
2. **Signing scope and trust root.** Sign the manifest containing
   `module_cid`; verify the digest before compile. Trust the existing
   `MYCELIUM_AUTHORITY_KEYS` root and a new, narrowly delegated
   `module.publish` capability — not "any enrolled peer".
3. **What lands first.** S1 (ABI + mock BLE backend, no hardware) first; S2 and
   S3 in parallel after S1; S3 must gate any non-local module.
4. **Lease authority.** The radio lease becomes a signed fleet-identity record
   keyed on `ring_id`, minted by the host, never a guest field or an unsigned
   local JSON file.
5. **Module/Unibus identity.** In S2 a wasm module is a sub-tenant of the host,
   not a first-class Unibus producer. Confirm, or schedule the larger grant
   extension explicitly.
