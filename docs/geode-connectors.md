# Geode connectors: passkeys, 2FA, OAuth2/OIDC, Composio

Status: **implemented connectors** (`geode-passkey`, `geode-otp`,
`geode-oauth`) plus reference conventions for Composio and fpl-auth.

## Model

Geode owns the credential. A connector owns the protocol.

```text
geode           opaque storage, purpose allowlist, leases, expiry, audit
geode-passkey   WebAuthn assertion/registration from a software ES256 key
geode-otp       TOTP/HOTP codes from a shared secret
geode-oauth     PKCE, refresh, device authorization, discovery; token vault
```

Connectors are ordinary Cargo crates selected at build time. There is no
`dlopen` plugin ABI and no runtime backend autodetection. Optional means
"opt into the dependency", not "load unknown code into the credential process".

Two rules apply to every connector:

1. **Reveal only what the caller must send.** A password is revealed to the
   protocol client; a refresh token, passkey private key, or OTP shared secret is
   not. The connector performs the derivation or refresh inside its own boundary.
2. **The purpose name is the grant.** Each connector leases a distinct purpose.
   An adapter holding `mail.connect` cannot ask for `passkey.assert`.

In-process Rust cannot isolate a connector from code in the same address space.
A connector that leases a private key can read it. If that matters, the boundary
is `geoded` (owner-only Unix socket, peer credentials) or an OS keychain item that
does not export the key. In-process geode enforces policy, not isolation.

## Reference conventions

```text
geode://mail/<account>/imap              password / app password
geode://oauth/<provider>/{access,refresh,id}   TokenSlots::for_account
geode://auth/<account>/passkey-<id>      PKCS#8 P-256 private key
geode://auth/<account>/totp              OTP shared secret (raw bytes)
geode://composio/<project>/api-key       COMPOSIO_API_KEY
geode://composio/<user>/consumer-key     ck_... (Composio For You)
```

Purposes used by the connectors:

| Purpose | Held by | Reveals |
| --- | --- | --- |
| `passkey.assert` | passkey connector | private key, for one assertion |
| `otp.generate` | OTP connector | shared secret, for one derivation |
| `oauth2.access` | API caller | access token, short lease |
| `oauth2.refresh` | OAuth connector only | refresh token, one refresh call |
| `oauth2.id` | session validator | ID token |
| `mail.connect` / `mail.submit` | mail adapter | password / app password |

## `geode-passkey`

A **software WebAuthn authenticator**, not a relying party.

- ES256 (COSE `-7`), `fmt: "none"` attestation, UP+UV flags.
- Real `clientDataJSON` with the challenge exactly as the RP sent it.
- `authenticatorData` = RP-ID hash, flags, and an advancing signature counter.
- Registration emits attested credential data with a COSE public key.
- Private key is PKCS#8 in geode; public metadata (`rp_id`, credential id, user
  handle, origin, counter) is non-secret configuration.

Limits, stated plainly:

- Platform passkeys (iCloud Keychain, Google Password Manager) are bound to the
  platform app identity. A headless daemon cannot use them. They need a separate
  platform signer, not this format.
- Origin/RP-ID matching, challenge binding, and counter acceptance are the
  relying party's job. `passkey-auth` or `webauthn-rs` verifies assertions.
- A software key is exportable: geode can lease the PKCS#8 bytes. It is not a
  non-exportable Secure Enclave key and must not be described as one.
- TPM/Keychain sealing protects a copied disk, not a compromised running daemon.

## `geode-otp` (2FA)

TOTP (RFC 6238) and HOTP (RFC 4226), SHA-1/SHA-256/SHA-512, 6–8 digits.

- Secret stays behind `otp.generate`; only the code leaves the connector.
- `otpauth://` enrollment parsing (base32, issuer, account, algorithm, digits,
  period, counter) with unknown parameters ignored.
- Verification accepts a bounded skew (`±1` step) and compares in constant time.
- **TOTP is the default for hosts and agents**: it is stateless.
- **HOTP is stateful.** Geode has no compare-and-swap, so an HOTP counter needs a
  single owner, or a backend with atomic increment. The connector returns the next
  counter; persisting it is the caller's job.

HMAC here is the construction TOTP/HOTP are built on. A separate generic HMAC
request signer is deferred until a concrete consumer exists; when it lands, the
key stays in geode and the connector returns the MAC, never the key.

Password hashing and verification do **not** belong in geode. That is the
verifier's job (`fpl-auth`, `passkey-auth`), not the client credential store.

## `geode-oauth` (OAuth2/OIDC client)

Implemented flows:

- OpenID Connect Discovery (`/.well-known/openid-configuration`) with issuer
  match and `https` endpoint checks.
- Authorization code + PKCE S256 (RFC 7636), with a caller-supplied `state`.
- Refresh token grant.
- Device authorization grant (RFC 8628) with `authorization_pending`,
  `slow_down`, `access_denied`, and `expired_token` handling.
- `TokenVault` writes `access`, `refresh`, and `id` slots with the right
  `CredentialKind`, purpose, and credential expiry.

Non-secrets stay in `OAuth2Config`. A confidential client's secret is a
`client_secret_ref` in configuration, leased from geode and passed to
`with_client_secret` for the flow. Refresh tokens never leave the connector; the
vault keeps the previous refresh token when a response omits a rotated one.

`HttpTransport` is injected so flow logic is testable offline. Enable the
`reqwest` feature for a default transport; redirects are disabled so a token
request cannot be replayed to another origin.

Not implemented: ID-token signature verification, JWT introspection, DPoP,
mTLS-bound tokens, and PAR. Those are relying-party or provider-specific
concerns and should be added with the consumer that needs them.

## fpl-auth profile

`fpl-auth` is the OpenID Connect provider and passkey/TOTP relying party. Geode
is its **client**. They do not duplicate each other:

| Concern | Owner |
| --- | --- |
| Passkey enrollment, verification, counters | fpl-auth (`passkey-auth`) |
| TOTP enrollment, replay prevention, trusted devices | fpl-auth |
| OIDC authorization code / device grants | fpl-auth |
| Browser session, `palisade_token`, vouch scopes | fpl-auth |
| Client refresh/access/ID tokens | geode-oauth |
| Client passkey assertion (software authenticator) | geode-passkey |
| Client 2FA code generation | geode-otp |

Suggested profiles:

- **Headless host / agent**: device authorization grant against
  `https://sso.fpl.dev`; store the refresh token under `oauth2.refresh`; refresh
  on demand. No browser, no client secret.
- **Interactive CLI**: authorization code + PKCE with a loopback redirect; the
  same token vault.
- **App login** (LibreChat/Grafana): fpl-auth owns the session; geode is not in
  the browser path.

Do not put a `palisade_token` in geode and call it OIDC. It is a session cookie,
not an OAuth token, and it belongs to the browser.

## Composio profile

Composio is a tool provider, not an OAuth provider geode should impersonate.
Follow Composio's own rule: **do not build provider OAuth flows**. Composio
returns a Connect Link when a toolkit needs authorization.

- **Composio Platform**: store `COMPOSIO_API_KEY` as an `api_key` credential under
  `geode://composio/<project>/api-key`. Agent/toolkit sessions are runtime state,
  not secrets.
- **Composio For You**: store `ck_...` under
  `geode://composio/<user>/consumer-key` when the client requires the header.
- **Connected accounts** are provider-side identifiers returned by Composio. They
  are not credentials; do not store provider access/refresh tokens in geode just
  because Composio issued them.
- **Connect Links** are short-lived URLs. Generate, show, and drop them; do not
  persist them as credentials.

A future `geode-composio` crate should be a thin API client (injected transport,
API key leased from geode) for listing toolkits/connected accounts and creating
connect links. It should not implement provider OAuth.

## Unibus MCP

Geode stays off the bus. Unibus contracts stay credential-free.

- `unibus-mcp` keeps its scoped `unibus-scoped-v1:` capability model, exact tool
  arguments, short TTLs, and fail-closed unknown-tool policy.
- A bridge/provider that needs an upstream credential (OAuth access token,
  Composio key, MCP bearer) asks a geode connector on the **host**, then makes the
  upstream call. It never sends the credential to a peer, and never puts it in
  tool arguments or results.
- If a short-lived bus capability is needed, the issuer derives it from a
  geode-held secret under a distinct purpose (for example `mcp.invoke`) and keeps
  the underlying secret local.
- `unibus-mail` is the model: `email.account.v1` carries a `geode://` reference,
  and the adapter leases `mail.connect` for the session.

## Threat model additions

Passkeys, OTP secrets, refresh tokens, and client secrets inherit geode's model:

- Protected: durable configuration, backups, diffs, logs, and the bus.
- Bound: lease TTL, credential expiry, per-purpose allowlist, audit ring.
- Not protected: a compromised same-user process, root, or a live memory dump.
- Not promised: non-exportability for software keys, platform-passkey use by a
  daemon, or attestation.

A 6-digit TOTP code is low entropy. Rate-limit verification at the relying party
and never treat a generated code as a durable credential.

## Next slices

1. Keychain/TPM backend so software passkey and OTP secrets are sealed at rest.
2. `geoded` if connectors need a real use-without-reveal boundary.
3. `geode-composio` client once a concrete MCP/agent consumer exists.
4. Generic HMAC signer (`hmac.sign`) once a webhook/bridge consumer exists.
5. `mycelium-core` `CredentialRef` and `unibus-mail` integration.
6. Platform passkey signer for interactive macOS clients (not headless).
