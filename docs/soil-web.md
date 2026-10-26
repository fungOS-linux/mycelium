# Soil on the web: host mapping and three-way auth

**Status:** design + target assessment, 2026-10-26. **Docs only.** No code, no
`Cargo.toml` change, no JavaScript package, no build, no deployment. This unit
does not create a browser host; it defines what one would have to be and what
would remain unproven.

**Scope.** Make the browser a sixth Soil target without weakening the existing
security model. The existing design in
[`docs/soil-capabilities.md`](soil-capabilities.md) defines the `soil:*`
capabilities, signed Spore manifests, fleet identity, grants through
`AuthorityResolver`, generations/revocations, and the five native targets. This
document adds:

1. a browser primitive mapping for every existing `soil:*` package;
2. a three-way separation of **human session**, **signed Spore**, and the
   **capability ticket** that binds them;
3. enforcement, revocation, and fail-closed behaviour;
4. SSO/session handling without turning the browser into a signing authority;
5. the honest ways soil-web is *not* wasmtime and *not* native Soil;
6. four bounded slices, W1–W4, with explicit non-goals and proof commands.

**Non-goals.** This is not a new capability ABI, a second grant store, a new
identity provider, a Web Bluetooth product commitment, a browser sandbox
replacement, a File System Access design, or a Spore Store implementation. It
does not modify the existing target decisions; the one-row link in
`docs/soil-capabilities.md` is the only edit to that file.

**Confidence tags** are the same as the Soil capabilities document: **[C]**
confirmed from an artifact or a shipping platform contract; **[I]** inferred
from the platform shape but not exercised here; **[?]** open, needs W2/W3/W4 or
a real browser/engine qualification run.

**Engine support ages badly.** Every availability statement below is a
2026-10-26 snapshot, not a promise. A browser host must feature-detect and
record the actual engine and version; a User-Agent string is not evidence.

---

## 1. Host mapping: one row per `soil:*` package

The browser is not a smaller native host. It is a host with **different
ownership**: the tab owns the window, the document owns input focus, the browser
owns permission and lifecycle, and the GPU/audio/BLE devices are behind
user-visible or policy-visible gates that native Soil never has. The mapping
therefore preserves the WIT-level contract, not the native implementation.

| Soil capability | Native Soil host | Browser primitive | Chromium | Firefox | Safari / WebKit | User gesture / permission | Honest unavailable cases |
|---|---|---|---|---|---|---|---|
| `soil:gpu` | wgpu device, bounded draw/compute lists | **WebGPU** (`GPUAdapter`, `GPUDevice`, pipelines, buffers) | Stable desktop and Android Chromium. Linux Chromium is not a dependable target (rollout/flags vary). | Windows stable in current releases. macOS/Linux still version- or flag-dependent; do not promise. | Safari 26+ on macOS 26/iOS/iPadOS 26. Older Safari and all older iOS WebKit: no. | No ordinary permission prompt. Secure context required. Adapter/device request can still fail (blocklisted GPU, no adapter, headless, low-power policy). | No WebGPU in older Safari, most Firefox configurations, some Linux Chromium, some locked-down/enterprise browsers. `soil:gpu` has **no WebGL fallback**: falling back silently would change shader/pipeline semantics. |
| `soil:audio` | bounded PCM sink/source, host clock | **Web Audio API** (`AudioContext`, `AudioWorklet`, `AudioBufferSourceNode`) | Yes. | Yes. | Yes, including iOS WebKit, with the strictest autoplay rules. | `AudioContext` starts suspended; `resume()` needs transient user activation. Output device selection (`setSinkId`) is not uniform. Microphone input would need `getUserMedia` and is **not** part of `soil:audio` here. | No true exclusive/low-latency realtime guarantee; sample rate and render quantum are engine/browser/device dependent. Background tabs may suspend audio. No raw device enumeration parity. |
| `soil:ble` | CoreBluetooth/BlueZ + the ring host | **Web Bluetooth** (`navigator.bluetooth.requestDevice`, GATT) | Chrome/Edge desktop on macOS/Windows/ChromeOS and Chrome on Android. Linux Chromium is not a dependable Web Bluetooth target. | **No.** Firefox has not shipped Web Bluetooth. | **No.** Safari/WebKit has not shipped Web Bluetooth; on iOS every browser is WebKit, so there is no iOS path. | Secure context **and** transient user activation. A user-visible device chooser runs per request; the origin gets access to the selected device, not ambient scanning. Permission can be revoked. | No passive/background scanning, no raw advertising reports, no Classic Bluetooth, no L2CAP, no pairing/bonding API, no reliable background operation, no continuous scan. Only GATT operations the chooser exposes. A COLMI ring may be unreachable depending on the GATT profile and the browser's chosen device. **This is the largest target gap.** |
| `soil:surface` | platform window/compositor; Soil owns the window | **Canvas / DOM**: host-owned canvas or DOM subtree; `requestAnimationFrame`, `ResizeObserver`, pointer/key/focus/visibility events | Yes. Canvas 2D and WebGL2 broadly; WebGPU optional for a GPU-backed implementation. | Yes. | Yes. | Canvas creation needs no prompt. Fullscreen, pointer lock, and audio resume need transient activation. `getUserMedia` is unrelated and not needed. | The tab is not a window manager: no window creation/move/resize, no display enumeration, no global shortcuts, no z-order control, no raw keycodes, no input outside the tab. Background/occluded tabs pause `requestAnimationFrame` and throttle timers. Mobile Safari may discard the tab. |
| `soil:stream` | Unibus bridge over host transports | **WebTransport over HTTP/3**, else **WebSocket** | WebTransport stable in current Chromium/Edge. | WebTransport is version/build dependent; probe rather than assume. | WebTransport is present in current Safari but has narrower HTTP/3, certificate, and datagram behaviour; probe. | Secure context. No gesture for the stream itself. Local/private endpoints trigger CORS/Private Network Access (or browser Local Network Access) checks and may show a site permission. | WebTransport needs an HTTP/3 origin and a valid certificate; it is not a raw QUIC socket. WebSocket fallback is reliable/ordered, not multiplexed, and has no unreliable datagrams or stream reset. **Fallback is not silent:** a ticket/stream declaration must allow it, otherwise the capability is unavailable. |

### 1.1 What the mapping means

- **The WIT is the same; the binary host is not.** A browser has no native
  WebAssembly component-model linker and no WASI preview-2 host. The `soil:*`
  WIT packages remain the source contract, but a browser artifact is a core
  wasm module plus host glue (or a component transpiled to that shape). The
  signed manifest must cover the artifact the browser actually loads. This is a
  target-specific artifact, not a second ABI.
- **`soil:gpu` is not required for `soil:surface`.** A browser surface can be
  implemented with Canvas 2D/WebGL2 while `soil:gpu` remains denied because
  WebGPU is absent. That is not a silent downgrade of `soil:gpu`; it is a
  different capability.
- **Capability availability is a host probe, not a manifest wish.** A Spore
  that asks for `soil:ble` on Firefox gets `denied`, with a named reason. It
  does not get a "best effort" BLE shim.
- **Browser permission is not the authority.** Section 2 and 3 make this
  explicit; the table only describes the second, weaker gate.

### 1.2 The two crux rows

**Web Bluetooth is not a web-wide capability.** There is no Web Bluetooth in
Firefox, Safari, or any iOS browser. Chromium's implementation is GATT and
chooser-based; it is not a replacement for the native ring host's scan/connect/
subscribe loop. If the ring requires passive advertising, Classic Bluetooth,
L2CAP, or background discovery, Web Bluetooth cannot do it even in Chromium.
The honest web target therefore either (a) excludes BLE, or (b) ships BLE as a
Chromium-only, foreground, user-selected-device capability. It cannot be
"the same ring experience" on the web.

**WebGPU is now plausible but not universal.** Current Chromium and current
Safari have shipping WebGPU; Firefox has a real shipping path on Windows but is
not uniform across macOS/Linux. The web target can support `soil:gpu` only where
WebGPU is present and the Shader/pipeline subset used by the Spore is
supported. There is no AOT shader story equivalent to `.cwasm`; pipeline
compilation happens in the browser process and can stall, fail, or be lost.
W2/W4 must test the actual adapter limits, not just `navigator.gpu !== undefined`.

---

## 2. Three-way auth separation (never conflated)

The existing constraint is absolute: **OIDC authenticates people separately; it
does not become a device signing key**
([`docs/access-control.md`](access-control.md), "OIDC boundary"). The web target
adds a browser, so it adds a third thing — a binding — without collapsing the
other two.

| Layer | Question it answers | Artifact | Signed by | Browser holds |
|---|---|---|---|---|
| **(a) Human SSO / OIDC** | Who is the person using this tab? | OIDC authorization-code + PKCE exchange; normalized `oidc:<issuer>#<subject>`, mapped through a signed access grant to the stable session principal `buddy:<human>` | IdP for authentication; **fleet access authority** for the principal mapping/grant | A session cookie, not an IdP token after exchange and **never a signing key** |
| **(b) Spore manifest** | What code is this, what may it request, and which target/engine? | Signed `IdentityRecord` containing `module_cid`, `size`, `abi`, `target`, `engine`, `caps`, `streams`, `generation`, `credential_id`, `signer` | Existing `mycelium/fleet-identity` publisher trust root (`spore.publish`) | Nothing it can mint; it verifies before instantiation |
| **(c) Capability ticket (the binding)** | May *this session* exercise *these capabilities* for *this exact Spore*? | Short-lived signed capability extension: `{spore_cid, principal, capabilities, issued_at, expires_at, generation, reason, audience}` | Fleet-side ticket authority after the OIDC session; narrow `spore.ticket` delegation, resolved through `AuthorityResolver` | A short-lived ticket in memory, audience-bound to the origin; no long-lived secret |

**They are not interchangeable.** A valid OIDC session without a ticket does
not authorize a Spore. A signed Spore without a ticket does not run with
capabilities. A ticket for Spore A does not run Spore B. A ticket for origin A
is rejected at origin B. A browser permission prompt does not create a ticket.

### 2.1 (a) Human SSO → `buddy:<human>`

Flow:

1. The browser starts an authorization-code + PKCE flow at the fleet's OIDC
   gateway. State and nonce are checked; the callback is same-origin.
2. The gateway verifies discovery/JWKS/signature/issuer/audience/subject/
   expiry exactly as `mycelium access oidc` does today.
3. The verified `oidc:<issuer>#<subject>` is mapped to `buddy:<human>` only by
   a converged, signed access grant. No unsigned email, display name, group
   header, query parameter, or client-supplied hint may create the mapping.
4. The fleet creates a server-side session and returns an opaque
   `__Host-soil_session` cookie: `HttpOnly`, `Secure`, `SameSite=Lax` (or
   `Strict` if the login round-trip allows it), host-only, no `Domain`, no
   `Path` escape. The browser never receives the IdP access/refresh token after
   the exchange and never receives an authority signing key.
5. Session lifetime is capped by the grant. A revoked grant or revoked session
   stops ticket re-minting immediately, even if the cookie is still present.

The browser holds **a session, not a signing key**. The cookie authenticates a
request to the ticket endpoint; it does not authenticate a Spore and cannot be
presented to a Soil capability as authority.

### 2.2 (b) Spore manifest → verified before instantiation

The browser host MUST perform the same ordered verification as native Soil,
with the same failure semantics. It is not enough to verify the manifest after
the module starts, or to verify only the outer script's SRI.

1. Parse the manifest with `deny_unknown_fields`.
2. Recompute `sha256(artifact bytes)` and compare to the artifact CID/size.
3. Verify the `mycelium/fleet-identity` record signature.
4. Require `fleet_id == local fleet`.
5. Require `abi` is a WIT set this host implements.
6. Require `target` is the web target/profile this host implements.
7. Require `engine` is compatible with this browser host ABI. Browser engine
   family/version is probed and audited; a manifest does not get to claim a
   browser version it was not tested on.
8. Require the signer's membership is valid and not revoked.
9. Require the signer is authorized for `spore.publish` (root or active
   one-level delegation).
10. Require `generation >= persisted floor(spore_id)`.
11. Require the Spore `credential_id` is not revoked.
12. Run `effective_caps(manifest, grants, policy)`; reject unknown/ungranted caps.

Only then compile/instantiate. The web-specific contract freeze is the exact
spelling of the web `target` and host `engine` values; the direction is fixed:
**same `soil:*` WIT packages, target-specific artifact, exact-match selection,
no fallback to a native artifact.** Because browsers do not load component
binaries natively, the web artifact is a derived core-wasm artifact (plus host
glue) and must be listed in the manifest's artifact list, covered by the same
signature and digest discipline as the AOT artifacts in
`docs/soil-capabilities.md` §H.6. If the Spore publisher only signed a
wasmtime component and did not publish a web artifact, the web host rejects it;
it does not transpile unverified bytes at runtime and pretend that is the same
signed artifact.

### 2.3 (c) Capability ticket → the binding

A ticket is a **signed, time-bound capability extension**, not a grant and not
a bearer password in a URL. It reuses the existing delegated sub-identity shape
used by `agent:<name>@<delegator>`: a bounded extension from a human principal
to a short-lived session, resolved through the same authority graph. It does
not create a second grant store.

Canonical statement (inside the existing `IdentityRecord` envelope, kind
`spore-ticket`; field spelling is a W2/W3 contract-freeze item):

```json
{
  "kind": "spore-ticket",
  "ticket_id": "st_01J...",
  "spore_cid": "sha256:<hex>",
  "spore_id": "org.fpl.ring-protocol",
  "principal": "buddy:<human>",
  "session_id": "sess_<opaque>",
  "capabilities": ["soil:surface"],
  "issued_at": "2026-10-26T12:00:00Z",
  "expires_at": "2026-10-26T12:05:00Z",
  "generation": 7,
  "reason": "interactive session; user opened the Soil web app",
  "audience": "https://soil.example.net",
  "delegator": "buddy:<human>",
  "signer": "<ticket-authority-key-id>"
}
```

Rules:

- **Minted fleet-side only after** the OIDC session exists and the principal's
  signed grants are active. The browser asks for a ticket; it does not mint
  one, and it cannot add capabilities.
- **Audience-bound to the exact origin** (`scheme + host + port`, no wildcard).
  A ticket minted for `https://soil.example.net` is rejected by
  `https://evil.example.net`, by a different port, and by a `file:` page.
- **Short TTL.** Target 60–300 seconds. The host re-mints silently while the
  session lives, before expiry, using the cookie + CSRF token. Re-minting is
  silent to the user but never silent about failure.
- **In memory only.** No `localStorage`, `sessionStorage`, IndexedDB, URL,
  `document.cookie`, referrer, log, or `postMessage` to another origin. A
  reload re-mints; a copied ticket dies at expiry/audience/origin.
- **No ticket → inert.** The Spore may be instantiated with deny-only host
  imports so it can receive a named `denied` result, or it may not be
  instantiated at all. It never runs with ambient authority and it never
  silently loses a capability. The host displays a named reason and emits an
  audit row.
- **Ticket capabilities are a subset.** The effective set is
  `manifest caps ∩ ticket capabilities ∩ host policy ∩ browser availability`.
  Browser permission is a separate, weaker gate; it can only subtract from the
  ticket, never add to it.

Named inert/deny reasons (stable strings, audited, visible):

| Reason | Meaning |
|---|---|
| `web_ticket_missing` | No ticket was supplied; Spore is inert. |
| `web_ticket_expired` | Ticket expired before this capability check. |
| `web_ticket_audience` | Ticket audience does not match this origin. |
| `web_ticket_signature` | Ticket signature or envelope is invalid. |
| `web_ticket_generation` | Ticket generation is below the persisted floor or was superseded. |
| `web_ticket_revoked` | Ticket/session/credential revoked. |
| `web_capability_not_ticketed` | Spore asked for a capability the ticket did not carry. |
| `web_spore_cid_mismatch` | Ticket is bound to a different Spore CID. |
| `web_host_unsupported` | This browser host cannot provide the capability (e.g. no Web Bluetooth). |
| `web_permission_denied` | The browser/user denied the second gate. |

`web_permission_denied` and `web_host_unsupported` are not the same as
`web_capability_not_ticketed`. The first two say "the platform/user said no";
the last says "the fleet never authorized it". They must not be collapsed.

---

## 3. Enforcement and revocation

### 3.1 Three gates, one intersection

```text
signed Spore manifest ──> requested caps
fleet ticket         ──> authorized caps     ──> intersection ──> host import check
browser capability   ──> available caps                              │
browser permission   ──> user-visible gate                           v
                                                           capability or named denial
```

- **Fleet-side ticket issuance is the authority.** The ticket endpoint checks
  the live session, active grants, Spore manifest/effective caps, revocation
  state, and generation floors. It clamps downward. It never trusts a requested
  capability list from the page.
- **The browser permission prompt is a second, weaker, user-visible gate.**
  For Web Bluetooth it chooses a device; for fullscreen/pointer lock it grants
  a UI mode; for local network access it may grant a network reach. None of
  these create a Soil capability. A user who grants fullscreen to a Spore
  without `soil:surface` gets no surface. A user who selects a ring without
  `soil:ble.connect` gets no BLE import.
- **The host checks at the import boundary.** Every `soil:*` call that crosses
  the wasm boundary checks: ticket present/valid/audience/CID/generation/
  revocation, capability in the intersection, and browser availability. The
  check is not performed only once at page load.
- **A Spore can never obtain a capability its ticket did not carry.** The
  browser is not allowed to "upgrade" a ticket by asking the user, by calling a
  different endpoint, by embedding an iframe with broader permissions, or by
  reusing a ticket from another Spore/origin. The ticket is the ceiling.

### 3.2 Revocation and generation changes

Revocation is not a UI state. It changes the authority answer.

- **Ticket revocation / session revocation / Spore credential revocation /
  membership revocation / generation bump** is checked at the next capability
  check. The host does not honour a ticket merely because its `expires_at` has
  not passed.
- The host maintains a bounded freshness window for revocation and generation
  floors (initial target: ≤30 s, configurable per deployment, never unlimited).
  Within the window, a local cached "not revoked" answer is allowed. Outside
  it, the host fails closed: new capability calls are denied, and long-lived
  streams are closed.
- Long-lived WebTransport/WebSocket streams subscribe to a revocation/control
  channel. On revocation or generation bump the host:
  1. marks the ticket dead immediately;
  2. resets/closes in-flight WebTransport streams with a named application
     error, or closes WebSocket streams with a named close code;
  3. rejects new calls with `web_ticket_revoked` / `web_ticket_generation`;
  4. emits audit rows for the revocation decision and each closed stream.
- A Spore cannot suppress, catch-and-ignore, or outlive this: the close/reset
  happens at the host boundary, not in Spore code. A Spore may observe the
  named error and render it; it does not get to keep using the capability.
- If the host cannot establish freshness (offline, IdP/gateway unreachable,
  clock skew beyond policy), it fails closed rather than trusting stale state
  forever. This mirrors the fleet-identity rule that disconnected consumers are
  bounded by proof expiry and policy freshness.

### 3.3 The audit row

Both ticket issuance and capability decisions write a server-side audit row.
Browser console logging is not the authority. The required keys are
`principal`, `spore_cid`, `capability`, `decision`, and `rule`; the rest make
"what did this tab do, on whose authority" answerable.

```json
{
  "ts": "2026-10-26T12:01:02.345Z",
  "principal": "buddy:<human>",
  "session_id": "sess_<opaque>",
  "ticket_id": "st_01J...",
  "origin": "https://soil.example.net",
  "spore_cid": "sha256:<hex>",
  "spore_id": "org.fpl.ring-protocol",
  "generation": 7,
  "capability": "soil:surface",
  "decision": "allow",
  "rule": "ticket.granted+manifest.requested+host.available",
  "reason": null,
  "request_id": "req_...",
  "engine": "chromium/<major>",
  "host_abi": "soil-web/<rev>"
}
```

Decisions are `allow`, `deny`, and `revoke` (revocation/closure). `rule` names
the actual conjunction, e.g. `ticket.missing`, `ticket.capability_absent`,
`host.unsupported`, `permission.denied`, `revocation.generation_floor`. The
audit must not record the ticket value, session cookie, IdP token, or device
address; identifiers are opaque references.

---

## 4. SSO without capture

### 4.1 Cookies vs bearer tickets

| Thing | Form | Where it lives | Why |
|---|---|---|---|
| OIDC exchange | Authorization code + PKCE | Same-origin callback | No implicit flow, no token in fragment, no token in referrer. |
| Session | `__Host-` cookie, `HttpOnly`, `Secure`, `SameSite=Lax/Strict`, host-only | Browser cookie jar, sent only to the ticket endpoint | JavaScript cannot read it; it authenticates the session, not a Spore. |
| Ticket | Signed short-lived bearer value | Page memory only, sent to the Soil capability endpoint as `Authorization: Bearer` (or a same-origin header) | Bearer semantics are explicit; it is audience-bound and expires fast. Never in a URL or storage. |
| CSRF token | Random per-session value, double-submit or synchronizer token | Page memory + cookie-bound | Ticket mint/re-mint is a state-changing request; it must not be a simple cross-site form POST. |
| Spore manifest | Signed record + artifact CID | Fetched from Store/repo; verified locally | Not a session credential; it is code provenance. |

No `Authorization` header is forwarded to arbitrary origins. No ticket is put in
a query string, `postMessage` payload, `window.name`, `Referer`, or a service
worker cache. The ticket endpoint requires `Origin` to match the session origin,
rejects `null` origins, and requires the CSRF token.

### 4.2 Origin isolation and headers

- **One Soil origin owns one session and one ticket audience.** Do not share a
  ticket across subdomains or ports. `audience` is exact origin. CORS is not
  used to export authority; the ticket endpoint is same-origin only.
- **Framing.** `Content-Security-Policy: frame-ancestors 'none'` by default.
  If embedding is ever required, the embedder is a separate, explicitly
  designed trust boundary; it does not get the soil cookie or the ticket.
- **CSP.** `script-src 'self' 'wasm-unsafe-eval'` (browser wasm compilation
  needs it; prefer nonce/hash for scripts), `worker-src 'self'` (and `blob:`
  only if blob workers are truly required), `connect-src` limited to the Soil
  gateway, Store, and explicitly declared stream origins. No `eval`, no
  remote script tags, no wildcard connect-src.
- **COOP/COEP.** `Cross-Origin-Opener-Policy: same-origin` and
  `Cross-Origin-Embedder-Policy: require-corp` (or `credentialless` where the
  deployment accepts its semantics) are required for `SharedArrayBuffer` and
  therefore for threaded wasm. Without cross-origin isolation, the host must
  run single-threaded or deny threading; it must not silently pretend threads
  exist. Every fetched subresource needs CORS/CORP under COEP.
- **Private Network Access / Local Network Access.** Requests from a public
  origin to `localhost`, the LAN, or a mesh address are subject to browser
  private/local-network checks: secure context, CORS preflight,
  `Access-Control-Allow-Private-Network: true` where the browser requires it,
  and a possible user permission. WebTransport to a private endpoint has the
  same class of policy and certificate problems. The host must detect failure
  and report `web_host_unsupported`/network reason, not loop forever.
- **Certificates and secure contexts.** Web Bluetooth, WebGPU, WebTransport,
  and local-network access are secure-context features (or effectively are).
  `http://localhost` is a development exception, not a production model.
  Self-signed mesh certificates require an explicit trust bootstrap; they do
  not become valid because the Spore is signed.
- **Service workers.** A service worker must not become a ticket cache. If used
  for offline shell/Store delivery, it may serve code and manifests only; it
  must not serve an old ticket, an old revocation state, or an old manifest as
  "fresh". A service worker update is a code change and is audited like one.

### 4.3 Audit and provenance chain

Ticket mint and capability decisions are audited fleet-side. The chain is:

```text
IdP assertion (issuer, subject, audience, nonce, expiry)
  -> signed access grant (oidc:<issuer>#<subject> -> buddy:<human>)
  -> server-side session
  -> signed ticket (spore_cid, principal, capabilities, generation, audience)
  -> host capability check (intersection, revocation freshness, browser gate)
  -> audit row
```

An operator can answer: which human, which session, which Spore CID, which
capability, which rule allowed or denied it, on which origin/engine, at what
generation, and whether a revocation/closure followed. A browser log is
supplementary, never the source of truth.

---

## 5. Honest breaks: soil-web is not wasmtime

The browser is not a wasmtime replacement. The same WIT source does not mean
the same binary semantics, and pretending otherwise is how the ABI gets
rewritten twice.

| Claim to avoid | What is actually true | Consequence for the target |
|---|---|---|
| "Same `.wasm`, same runtime." | Browsers execute core wasm (V8/SpiderMonkey/JavaScriptCore). There is no native component-model linker or WASI preview-2 host. A web artifact is core wasm + JS/host glue, or a component transpiled to that shape. | The signed manifest needs a web artifact and exact target/engine selection. A wasmtime component is not directly loadable; no runtime transpile of unverified bytes. |
| "Fuel/epoch determinism carries over." | There is no wasmtime fuel or epoch interruption. A Worker can be terminated as a coarse timeout, but that is not deterministic fuel and does not give the same preemption or accounting. | Budgets are best-effort and engine-specific. A Spore that is CPU-bound may stall the tab/worker until the host's watchdog kills it. No cross-engine reproducibility claim. |
| "AOT `.cwasm` is available." | Browsers do not deserialize wasmtime `.cwasm`. They JIT core wasm (or use engine-internal caching that is not a portable artifact). | No precompiled Spore artifact for web. The same Spore may start differently on each engine. tvOS-style AOT reasoning does not transfer. |
| "Memory limits are the same." | wasm32 has a 4 GiB address space in principle, but per-tab/per-engine practical limits, `WebAssembly.Memory` maxima, ArrayBuffer/string bridging, and mobile Safari limits are lower and engine-specific. | Manifest `memory_mb` is enforced as a best-effort cap (memory maximum + host checks), not a wasmtime store limiter. The host must reject declared maxima it cannot honour. |
| "Filesystem access still works." | No filesystem is exposed to the Spore. OPFS/File System Access are host privileges not in the `soil:*` grants. Paths are not CIDs. | Assets arrive through host-resolved CIDs; a Spore cannot read local files, env, args, or arbitrary URLs. No WASI fs. |
| "BLE is just a shim." | Web Bluetooth is Chromium-only, GATT-only, chooser-gated, foreground-oriented, with no passive advertising/Classic/L2CAP/background. Firefox/Safari/iOS have none. | BLE is a Chromium-only, user-selected, foreground capability at best. Scope decision required (see PR decisions). |
| "Time behaves like native." | The only time a Spore sees is host-supplied `soil-time-ms`/tick. Background tabs throttle timers and pause `requestAnimationFrame`; audio can suspend; device/BLE operations time out; engine clocks differ. | No realtime guarantees, no wall-clock reads, no assumption that a 16 ms tick happens in a hidden tab. Long-running work must be resumable or explicitly denied in background. |
| "Streams are equivalent." | WebTransport is HTTP/3, not raw QUIC; WebSocket fallback is reliable/ordered, not multiplexed, and lacks datagrams/reset. | A stream declaration/ticket must choose the transport or allow fallback explicitly. Silent fallback is a bug. |
| "Store delivery needs only SRI." | SRI binds a fetched response to a digest declared by the page; it does not authenticate the manifest, capabilities, publisher, or generation. The signed manifest binds bytes to caps but still needs a trusted manifest fetch. | Spore Store delivery requires **both**: SRI/digest verification of the bytes actually loaded **and** signed-manifest verification (publisher, CID, target, caps, generation, revocation). One does not replace the other. The store never re-signs and never issues tickets/grants. |
| "CSP is an implementation detail." | `wasm-unsafe-eval` (or equivalent), worker sources, connect-src, COOP/COEP, and Trusted Types determine whether the host can run at all. | A deployment's CSP can make a capability unavailable. That is a named host/configuration denial, not a Spore bug. |

### 5.1 Store delivery: both checks, in this order

1. Fetch the signed manifest and the target-specific artifact. Pin/fetch the
   manifest through a trusted channel (TLS + configured Store trust), then
   verify its `mycelium/fleet-identity` signature and publisher authority.
2. Verify the artifact digest/`module_cid` against the signed manifest. If the
   browser supports `fetch(..., { integrity })`, use it as an additional
   transport-level check; do **not** rely on `compileStreaming` having checked
   more than the HTTP response.
3. Verify `target`/`engine`/`abi`, membership, generation, revocation, and
   effective caps before compile/instantiate.
4. Fetch only the artifact the signed manifest names. A Store response that
   "helpfully" substitutes a newer build, a different target, or a differently
   capped manifest is rejected. The Store is a distributor, not an authority.

### 5.2 What is unproven

- **[?]** Whether the COLMI ring's GATT profile can be driven through Web
  Bluetooth at all (device chooser, notification sizes, reconnect behavior).
- **[?]** Whether the ring's protocol needs passive advertising/Classic/L2CAP
  or background scanning, any of which rules out Web Bluetooth.
- **[?]** WebGPU parity for the actual `soil:gpu` shader/pipeline subset on
  Chromium, Safari, and Firefox; adapter limits, device loss, and shader
  compilation stalls.
- **[?]** WebTransport datagram/reset semantics and HTTP/3 availability on the
  deployed origins, especially to private/mesh endpoints.
- **[?]** Whether the component toolchain can produce a web artifact from the
  same WIT without changing observable behavior, and how that artifact is
  signed/selected. This is a W2 contract-freeze item.
- **[?]** Ed25519 verification in browser WebCrypto on every target engine
  (support is not uniform); if absent, a vetted wasm verifier is required, and
  it must not become a second trust implementation.
- **[?]** COOP/COEP, SAB/threads, and Private Network Access behavior across
  Chromium/Firefox/Safari and mobile WebKit.
- **[?]** Revocation freshness latency and stream-close behavior under real
  network partition, sleep/wake, and background-tab throttling.

---

## 6. Slices W1–W4

These are sequential, independently landable slices. Each names what it does
**not** include and the command that is allowed to claim it is done. W1 is the
only slice in this unit. W2–W4 commands are target commands: they are not
runnable yet, and a slice does not merge until its command exists and passes in
CI (or a documented qualification run for browser-only checks).

### W1 — docs only (this unit)

**Deliver:** this document; one matrix row + link in
`docs/soil-capabilities.md`.

**Explicitly not in W1:** no browser host, no wasm artifact, no WIT change, no
ticket endpoint, no OIDC/session change, no JavaScript/TypeScript package, no
dependency, no build, no deployment, no BLE/WebGPU qualification.

**Proof command (run in this worktree):**

```sh
git diff --check
test -f docs/soil-web.md
test "$(git diff --name-only origin/master...HEAD | grep -vE '^docs/(soil-web|soil-capabilities)\.md$' | wc -l)" -eq 0
```

The last check is expected to be evaluated **after PR #2 (which introduces
`docs/soil-capabilities.md`) is merged**; this PR is stacked on that document
and must not add any other path.

### W2 — browser host verifies a signed manifest and enforces ONE capability (`soil:surface`)

**Deliver:**

- a minimal browser host (same `soil:surface@1.0.0` WIT source) that loads a
  web-target Spore artifact;
- manifest verification in the exact order from §2.2, including digest,
  signature, publisher authority, target/engine/ABI, generation, revocation;
- one capability only: `soil:surface` (open/submit/poll-event/close) mapped to
  a host-owned canvas/DOM surface;
- a test page served from a secure-context/localhost origin with a fixture
  Spore that requests `soil:surface` and at least one capability it was **not**
  granted (e.g. `soil:ble`), plus a fixture ticket;
- named inert/deny output for missing/expired/wrong-audience ticket;
- feature detection for the browser APIs used, with an explicit unavailable
  message.

**Explicitly not in W2:** no ticket minting endpoint or OIDC session (fixture
ticket only); no W3/W4; no `soil:gpu`, `soil:audio`, `soil:ble`, or
`soil:stream`; no BLE hardware; no WebGPU renderer; no Store/service worker;
no production origin, deployment, or multi-user session; no revocation channel
(fixture-generation test only); no component-model runtime; no claim that the
native surface backend is reused.

**Proof commands (target):**

```sh
cargo test -p soil-web-host --lib manifest_
wasm-pack test --headless --chrome crates/soil-web-host --test w2_surface
```

The test page must demonstrate all three at once: granted `soil:surface`
works, unticketed `soil:ble` is denied with `web_capability_not_ticketed`, and
a missing ticket leaves the Spore inert with `web_ticket_missing`.

### W3 — ticket issuance against an OIDC session

**Deliver:**

- a fleet-side ticket endpoint that accepts only a live `__Host-` session +
  CSRF token + exact `Origin`;
- OIDC authorization-code + PKCE session establishment; verified
  issuer/audience/subject/nonce/expiry; signed-grant mapping to
  `buddy:<human>`;
- ticket minting with `{spore_cid, principal, capabilities, issued_at,
  expires_at, generation, reason, audience}`, signed by a narrow
  `spore.ticket` delegation resolved through `AuthorityResolver`;
- capability clamping against the Spore's signed manifest and the principal's
  active grants; generation/revocation checks; short TTL and silent re-mint;
- audit rows for mint/deny/expiry, with the required keys.

**Explicitly not in W3:** no browser host/capability enforcement (W2 owns
that); no BLE/GPU/audio; no real IdP in CI (a fixture OIDC/JWKS provider is
allowed); no UI beyond a minimal login/callback; no cross-origin embedding; no
long-lived token storage; no Spore Store; no production key custody; no
`spore:ble`; no claim that session refresh equals ticket renewal.

**Proof command (target):**

```sh
cargo test -p myceliumd --test oidc_ticket -- --nocapture
```

The test must prove: no session → no ticket; wrong origin → rejected; a
capability outside the manifest/grants → clamped or denied; ticket audience and
TTL are exact; a revoked grant stops re-minting.

### W4 — second capability + revocation test

**Deliver:**

- a second capability, initially `soil:stream` over WebTransport with an
  explicit WebSocket fallback (the fallback must be declared/ticketed, not
  silent); `soil:ble` is deliberately **not** the second capability because its
  engine availability is the open scope decision;
- a long-lived stream that is bound to a ticket and generation;
- revocation/generation-bump handling: next capability check denies, in-flight
  WebTransport streams are reset/closed, WebSocket streams are closed with a
  named code, and audit rows record the closure;
- a test that a browser permission grant cannot exceed the ticket (e.g. user
  allows a surface/fullscreen gesture while the ticket lacks the capability, or
  a selected BLE device while `soil:ble` is unticketed, where testable).

**Explicitly not in W4:** no BLE/hardware qualification; no WebGPU; no
cross-engine certification matrix (Chromium is the first proof; Firefox/Safari
remain recorded gaps); no Spore Store delivery; no multi-tenant service; no
offline/partition-tolerant revocation guarantee beyond the freshness bound; no
claim that WebSocket fallback is semantically equivalent to WebTransport.

**Proof commands (target):**

```sh
cargo test -p soil-web-host --test w4_ticket_revocation
node --test web/soil/test/revocation_*.mjs
```

The revocation test is only allowed to pass if it observes the stream close and
a subsequent `web_ticket_revoked`/`web_ticket_generation` denial. A test that
merely waits for ticket expiry does not prove revocation.

---

## Decisions a human must confirm

These are the two decisions that change the design, not implementation details:

1. **Who mints capability tickets?** Recommendation: the **fleet authority**
   (Mycelium ticket endpoint, holding a narrow `spore.ticket` delegation and
   reading the same signed grants/AuthorityResolver). The alternative is an
   application server minting tickets, which makes every app a second authority
   and creates a second place that can widen capabilities. If an app server is
   chosen, it must still be a delegated signer with exactly the same ticket
   shape, audience binding, TTL, and audit; it cannot be an unsigned policy
   layer.
2. **Is Web Bluetooth in scope at all?** Recommendation: **not in the initial
   web target**. It is Chromium-only, GATT-only, foreground/chooser-gated, and
   absent on Firefox, Safari, and every iOS browser. If BLE is in scope, it is
   an explicitly Chromium-only capability with a visible "unsupported on this
   browser" path and a separate qualification plan; it is not parity with the
   native ring host. If BLE is out of scope, `soil:ble` is denied on web with
   `web_host_unsupported`, not emulated.

The target decision also needs to accept the correction in §5: **the web target
is a new artifact/engine profile, not a fourth wasmtime target.** The same WIT
does not imply the same component binary, and no `.cwasm`, fuel, epoch, or
native filesystem behavior carries over.
