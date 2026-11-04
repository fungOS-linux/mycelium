//! OAuth2/OIDC client flows for credentials owned by [`geode`].
//!
//! The token plane is split by lifetime and secrecy:
//!
//! - **Refresh tokens never leave the connector.** They are stored under
//!   `oauth2.refresh` and leased only for the duration of one refresh request.
//! - **Access tokens are bearer secrets** and can be leased under
//!   `oauth2.access` for the short window a caller needs to make a request.
//! - **ID tokens** are stored under `oauth2.id`; they are read by the client that
//!   needs to validate a session, not broadcast.
//! - **Client secrets** are geode references in configuration, resolved by the
//!   host, never embedded in [`OAuth2Config`].
//!
//! Flows implemented: authorization code + PKCE (RFC 7636), refresh (RFC 6749),
//! and device authorization (RFC 8628). Discovery follows OpenID Connect
//! Discovery. This crate does not verify ID-token signatures; that is the
//! relying party's job.
//!
//! `HttpTransport` is injected so the flow logic can be tested without a network.
//! Enable the `reqwest` feature for a default transport.

use std::collections::BTreeSet;
use std::fmt;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use geode::{
    Backend, GeodeError, GeodeRef, Lease, NewCredential, Purpose, SecretBytes, SharedClock, Store,
    SystemClock,
};
use rand_core::{OsRng, RngCore};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use url::Url;

pub const DEVICE_CODE_GRANT: &str = "urn:ietf:params:oauth:grant-type:device_code";

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum OAuthError {
    #[error("HTTP transport failed: {0}")]
    Transport(String),
    #[error("provider returned HTTP {status}: {error}{description}")]
    Server {
        status: u16,
        error: String,
        description: String,
    },
    #[error("provider response is not valid JSON: {0}")]
    Json(String),
    #[error("provider response is missing `{0}`")]
    Missing(&'static str),
    #[error("invalid URL: {0}")]
    Url(String),
    #[error("protocol violation: {0}")]
    Protocol(String),
    #[error(transparent)]
    Geode(#[from] GeodeError),
}

/// Minimal HTTP response. The body is secret-bearing (it can contain tokens), so
/// it redacts itself in `Debug`.
pub struct HttpResponse {
    pub status: u16,
    pub body: SecretBytes,
}

impl fmt::Debug for HttpResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpResponse")
            .field("status", &self.status)
            .field("body", &self.body)
            .finish()
    }
}

/// Injected HTTP boundary. Implementations must not log request or response
/// bodies, because they carry authorization codes and tokens.
#[async_trait]
pub trait HttpTransport: Send + Sync {
    async fn post_form(
        &self,
        url: &str,
        form: &[(String, String)],
    ) -> Result<HttpResponse, OAuthError>;

    async fn get(&self, url: &str) -> Result<HttpResponse, OAuthError>;
}

/// OpenID Connect provider metadata (the subset this client uses).
#[derive(Clone, Debug, Deserialize)]
pub struct ProviderMetadata {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    #[serde(default)]
    pub device_authorization_endpoint: Option<String>,
    #[serde(default)]
    pub jwks_uri: Option<String>,
    #[serde(default)]
    pub scopes_supported: Vec<String>,
}

impl ProviderMetadata {
    /// Discovery URL for an issuer, per OpenID Connect Discovery.
    pub fn discovery_url(issuer: &str) -> String {
        format!(
            "{}/.well-known/openid-configuration",
            issuer.trim_end_matches('/')
        )
    }

    pub fn validate(&self, expected_issuer: &str) -> Result<(), OAuthError> {
        if self.issuer.trim_end_matches('/') != expected_issuer.trim_end_matches('/') {
            return Err(OAuthError::Protocol(format!(
                "discovered issuer `{}` does not match configured issuer `{expected_issuer}`",
                self.issuer
            )));
        }
        for endpoint in [&self.authorization_endpoint, &self.token_endpoint] {
            let url = Url::parse(endpoint).map_err(|error| OAuthError::Url(error.to_string()))?;
            if url.scheme() != "https" && url.host_str() != Some("localhost") {
                return Err(OAuthError::Protocol(format!(
                    "endpoint `{endpoint}` must use https"
                )));
            }
        }
        Ok(())
    }
}

/// Non-secret OAuth2 client configuration.
#[derive(Clone, Debug)]
pub struct OAuth2Config {
    pub issuer: String,
    pub client_id: String,
    pub scopes: Vec<String>,
    pub redirect_uri: Option<String>,
    /// Reference to a client secret held by geode. Never the secret itself.
    pub client_secret_ref: Option<GeodeRef>,
}

impl OAuth2Config {
    pub fn new(issuer: impl Into<String>, client_id: impl Into<String>) -> Self {
        Self {
            issuer: issuer.into(),
            client_id: client_id.into(),
            scopes: Vec::new(),
            redirect_uri: None,
            client_secret_ref: None,
        }
    }

    pub fn with_scope(mut self, scope: impl Into<String>) -> Self {
        self.scopes.push(scope.into());
        self
    }

    pub fn with_redirect_uri(mut self, redirect_uri: impl Into<String>) -> Self {
        self.redirect_uri = Some(redirect_uri.into());
        self
    }
}

/// PKCE code verifier (RFC 7636). Debug is redacted.
pub struct Pkce {
    verifier: SecretBytes,
}

impl fmt::Debug for Pkce {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Pkce").field(&self.verifier).finish()
    }
}

impl Pkce {
    /// 32 random bytes, base64url-encoded (43 characters).
    pub fn generate() -> Self {
        let mut bytes = [0u8; 32];
        OsRng.fill_bytes(&mut bytes);
        Self {
            verifier: SecretBytes::new(URL_SAFE_NO_PAD.encode(bytes)),
        }
    }

    /// Adopt an existing verifier (for tests or a resumed flow).
    pub fn from_verifier(verifier: impl AsRef<[u8]>) -> Result<Self, OAuthError> {
        let value = verifier.as_ref();
        if !(43..=128).contains(&value.len())
            || !value
                .iter()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~'))
        {
            return Err(OAuthError::Protocol(
                "PKCE verifier must be 43..=128 unreserved characters".into(),
            ));
        }
        Ok(Self {
            verifier: SecretBytes::new(value.to_vec()),
        })
    }

    pub fn challenge(&self) -> String {
        URL_SAFE_NO_PAD.encode(Sha256::digest(self.verifier.expose()))
    }

    pub fn verifier(&self) -> &str {
        // The verifier is base64url by construction.
        std::str::from_utf8(self.verifier.expose()).expect("base64url is UTF-8")
    }
}

/// A token response. Tokens have a redacting `Debug` and no `Serialize`.
pub struct TokenSet {
    pub access_token: SecretBytes,
    pub refresh_token: Option<SecretBytes>,
    pub id_token: Option<SecretBytes>,
    pub token_type: String,
    pub scopes: BTreeSet<String>,
    pub issued_at: u64,
    pub expires_at: Option<u64>,
}

impl fmt::Debug for TokenSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TokenSet")
            .field("access_token", &self.access_token)
            .field("refresh_token", &self.refresh_token)
            .field("id_token", &self.id_token)
            .field("token_type", &self.token_type)
            .field("scopes", &self.scopes)
            .field("issued_at", &self.issued_at)
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

impl TokenSet {
    pub fn is_expired(&self, now: u64, skew: Duration) -> bool {
        self.expires_at
            .is_some_and(|expires_at| now.saturating_add(skew.as_secs()) >= expires_at)
    }
}

#[derive(Deserialize)]
struct TokenWire {
    access_token: String,
    #[serde(default)]
    refresh_token: Option<String>,
    #[serde(default)]
    id_token: Option<String>,
    #[serde(default)]
    token_type: Option<String>,
    #[serde(default)]
    scope: Option<String>,
    #[serde(default)]
    expires_in: Option<u64>,
}

#[derive(Deserialize)]
struct ErrorWire {
    #[serde(default)]
    error: Option<String>,
    #[serde(default)]
    error_description: Option<String>,
}

impl TokenSet {
    fn from_response(wire: TokenWire, now: u64, fallback_scope: &[String]) -> Self {
        let scopes = wire
            .scope
            .as_deref()
            .map(|scope| scope.split_ascii_whitespace().map(str::to_owned).collect())
            .unwrap_or_else(|| fallback_scope.iter().cloned().collect());
        Self {
            access_token: SecretBytes::from(wire.access_token),
            refresh_token: wire.refresh_token.map(SecretBytes::from),
            id_token: wire.id_token.map(SecretBytes::from),
            token_type: wire.token_type.unwrap_or_else(|| "Bearer".into()),
            scopes,
            issued_at: now,
            expires_at: wire.expires_in.map(|seconds| now.saturating_add(seconds)),
        }
    }
}

/// Device authorization start response.
#[derive(Clone, Debug)]
pub struct DeviceAuthorization {
    /// Bearer-ish device code. Debug is redacted through `SecretBytes`.
    pub device_code: SecretBytes,
    pub user_code: String,
    pub verification_uri: String,
    pub verification_uri_complete: Option<String>,
    pub expires_at: u64,
    pub interval: u64,
}

#[derive(Deserialize)]
struct DeviceWire {
    device_code: String,
    user_code: String,
    verification_uri: String,
    #[serde(default)]
    verification_uri_complete: Option<String>,
    expires_in: u64,
    #[serde(default = "default_interval")]
    interval: u64,
}

fn default_interval() -> u64 {
    5
}

/// Result of one device-token poll.
pub enum DevicePoll {
    Pending,
    SlowDown,
    Authorized(TokenSet),
    Denied,
    Expired,
}

impl fmt::Debug for DevicePoll {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Pending => f.write_str("DevicePoll::Pending"),
            Self::SlowDown => f.write_str("DevicePoll::SlowDown"),
            Self::Authorized(tokens) => f
                .debug_tuple("DevicePoll::Authorized")
                .field(tokens)
                .finish(),
            Self::Denied => f.write_str("DevicePoll::Denied"),
            Self::Expired => f.write_str("DevicePoll::Expired"),
        }
    }
}

/// OAuth2/OIDC client bound to one provider and one client id.
pub struct OAuth2Client<T: HttpTransport> {
    config: OAuth2Config,
    metadata: ProviderMetadata,
    transport: T,
    clock: SharedClock,
    client_secret: Option<SecretBytes>,
}

impl<T: HttpTransport> OAuth2Client<T> {
    pub fn new(
        config: OAuth2Config,
        metadata: ProviderMetadata,
        transport: T,
    ) -> Result<Self, OAuthError> {
        metadata.validate(&config.issuer)?;
        Ok(Self {
            config,
            metadata,
            transport,
            clock: Arc::new(SystemClock),
            client_secret: None,
        })
    }

    pub fn with_clock(mut self, clock: SharedClock) -> Self {
        self.clock = clock;
        self
    }

    /// Attach a confidential-client secret previously leased from geode. The
    /// caller drops its lease after this call; the client holds the bytes only
    /// for the lifetime of the flow.
    pub fn with_client_secret(mut self, secret: SecretBytes) -> Self {
        self.client_secret = Some(secret);
        self
    }

    pub fn metadata(&self) -> &ProviderMetadata {
        &self.metadata
    }

    /// Fetch and validate provider metadata.
    pub async fn discover(config: OAuth2Config, transport: T) -> Result<Self, OAuthError> {
        let url = ProviderMetadata::discovery_url(&config.issuer);
        let response = transport.get(&url).await?;
        let metadata: ProviderMetadata = parse_json(&response)?;
        Self::new(config, metadata, transport)
    }

    /// Build the authorization-code URL. `state` must be unguessable and bound
    /// to the caller's session.
    pub fn authorization_url(&self, state: &str, pkce: &Pkce) -> Result<String, OAuthError> {
        if state.is_empty() {
            return Err(OAuthError::Protocol("state must not be empty".into()));
        }
        let mut url = Url::parse(&self.metadata.authorization_endpoint)
            .map_err(|error| OAuthError::Url(error.to_string()))?;
        {
            let mut query = url.query_pairs_mut();
            query.append_pair("response_type", "code");
            query.append_pair("client_id", &self.config.client_id);
            query.append_pair("state", state);
            query.append_pair("code_challenge", &pkce.challenge());
            query.append_pair("code_challenge_method", "S256");
            if let Some(redirect_uri) = &self.config.redirect_uri {
                query.append_pair("redirect_uri", redirect_uri);
            }
            if !self.config.scopes.is_empty() {
                query.append_pair("scope", &self.config.scopes.join(" "));
            }
        }
        Ok(url.into())
    }

    pub async fn exchange_code(&self, code: &str, pkce: &Pkce) -> Result<TokenSet, OAuthError> {
        let mut form = vec![
            ("grant_type".into(), "authorization_code".into()),
            ("code".into(), code.into()),
            ("client_id".into(), self.config.client_id.clone()),
            ("code_verifier".into(), pkce.verifier().into()),
        ];
        if let Some(redirect_uri) = &self.config.redirect_uri {
            form.push(("redirect_uri".into(), redirect_uri.clone()));
        }
        self.token_request(form).await
    }

    pub async fn refresh(&self, refresh_token: &SecretBytes) -> Result<TokenSet, OAuthError> {
        let refresh_token = std::str::from_utf8(refresh_token.expose())
            .map_err(|_| OAuthError::Protocol("refresh token is not UTF-8".into()))?;
        let form = vec![
            ("grant_type".into(), "refresh_token".into()),
            ("refresh_token".into(), refresh_token.into()),
            ("client_id".into(), self.config.client_id.clone()),
        ];
        self.token_request(form).await
    }

    pub async fn start_device_authorization(&self) -> Result<DeviceAuthorization, OAuthError> {
        let endpoint = self
            .metadata
            .device_authorization_endpoint
            .as_ref()
            .ok_or_else(|| {
                OAuthError::Protocol("provider has no device_authorization_endpoint".into())
            })?;
        let form = vec![
            ("client_id".into(), self.config.client_id.clone()),
            ("scope".into(), self.config.scopes.join(" ")),
        ];
        let response = self.transport.post_form(endpoint, &form).await?;
        let now = self.clock.now();
        let wire: DeviceWire = parse_json(&response)?;
        Ok(DeviceAuthorization {
            device_code: SecretBytes::from(wire.device_code),
            user_code: wire.user_code,
            verification_uri: wire.verification_uri,
            verification_uri_complete: wire.verification_uri_complete,
            expires_at: now.saturating_add(wire.expires_in),
            interval: wire.interval.max(1),
        })
    }

    pub async fn poll_device_token(
        &self,
        device: &DeviceAuthorization,
    ) -> Result<DevicePoll, OAuthError> {
        if self.clock.now() >= device.expires_at {
            return Ok(DevicePoll::Expired);
        }
        let device_code = std::str::from_utf8(device.device_code.expose())
            .map_err(|_| OAuthError::Protocol("device code is not UTF-8".into()))?;
        let form = vec![
            ("grant_type".into(), DEVICE_CODE_GRANT.into()),
            ("device_code".into(), device_code.into()),
            ("client_id".into(), self.config.client_id.clone()),
        ];
        let response = self
            .transport
            .post_form(&self.metadata.token_endpoint, &form)
            .await?;
        if response.status == 200 {
            let wire: TokenWire = parse_json(&response)?;
            return Ok(DevicePoll::Authorized(TokenSet::from_response(
                wire,
                self.clock.now(),
                &self.config.scopes,
            )));
        }
        let error: ErrorWire = parse_json(&response)?;
        match error.error.as_deref() {
            Some("authorization_pending") => Ok(DevicePoll::Pending),
            Some("slow_down") => Ok(DevicePoll::SlowDown),
            Some("access_denied") => Ok(DevicePoll::Denied),
            Some("expired_token") => Ok(DevicePoll::Expired),
            other => Err(server_error(&response, other, &error)),
        }
    }

    async fn token_request(&self, mut form: Vec<(String, String)>) -> Result<TokenSet, OAuthError> {
        if let Some(secret) = &self.client_secret {
            let secret = std::str::from_utf8(secret.expose())
                .map_err(|_| OAuthError::Protocol("client secret is not UTF-8".into()))?;
            form.push(("client_secret".into(), secret.into()));
        }
        let response = self
            .transport
            .post_form(&self.metadata.token_endpoint, &form)
            .await?;
        if response.status != 200 {
            let error: ErrorWire = parse_json(&response).unwrap_or(ErrorWire {
                error: None,
                error_description: None,
            });
            return Err(server_error(&response, error.error.as_deref(), &error));
        }
        let wire: TokenWire = parse_json(&response)?;
        Ok(TokenSet::from_response(
            wire,
            self.clock.now(),
            &self.config.scopes,
        ))
    }
}

fn parse_json<'de, D: Deserialize<'de>>(response: &'de HttpResponse) -> Result<D, OAuthError> {
    serde_json::from_slice(response.body.expose())
        .map_err(|error| OAuthError::Json(error.to_string()))
}

fn server_error(status: &HttpResponse, code: Option<&str>, wire: &ErrorWire) -> OAuthError {
    OAuthError::Server {
        status: status.status,
        error: code.unwrap_or("unknown").to_owned(),
        description: wire
            .error_description
            .as_ref()
            .map(|description| format!(" ({description})"))
            .unwrap_or_default(),
    }
}

/// The three geode references that hold one account's tokens.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TokenSlots {
    pub access: GeodeRef,
    pub refresh: GeodeRef,
    pub id: GeodeRef,
}

impl TokenSlots {
    /// `geode://<realm>/<account>/{access,refresh,id}`.
    pub fn for_account(realm: &str, account: &str) -> Result<Self, GeodeError> {
        Ok(Self {
            access: GeodeRef::new(realm, account, "access")?,
            refresh: GeodeRef::new(realm, account, "refresh")?,
            id: GeodeRef::new(realm, account, "id")?,
        })
    }
}

/// Persist and lease token sets through geode.
pub struct TokenVault<'a, B: Backend> {
    store: &'a Store<B>,
    slots: TokenSlots,
}

impl<'a, B: Backend> TokenVault<'a, B> {
    pub fn new(store: &'a Store<B>, slots: TokenSlots) -> Self {
        Self { store, slots }
    }

    /// Write the tokens, preserving `created_at` for existing entries.
    ///
    /// A response without a new refresh token keeps the previous one, which is
    /// how most providers rotate refresh tokens.
    pub fn persist(&self, tokens: &TokenSet) -> Result<(), OAuthError> {
        let mut access = NewCredential::oauth2_access(
            SecretBytes::new(tokens.access_token.expose().to_vec()),
            tokens
                .expires_at
                .unwrap_or_else(|| tokens.issued_at.saturating_add(300)),
        )
        .with_purpose(Purpose::oauth2_access());
        access.label = Some(format!("{} access", tokens.token_type));
        self.store.insert(&self.slots.access, access)?;

        if let Some(refresh_token) = &tokens.refresh_token {
            let mut refresh =
                NewCredential::oauth2_refresh(SecretBytes::new(refresh_token.expose().to_vec()))
                    .with_purpose(Purpose::oauth2_refresh());
            refresh.label = Some("refresh".into());
            self.store.insert(&self.slots.refresh, refresh)?;
        }

        if let Some(id_token) = &tokens.id_token {
            let mut id = NewCredential::oauth2_id(
                SecretBytes::new(id_token.expose().to_vec()),
                tokens.expires_at,
            )
            .with_purpose(Purpose::oauth2_id());
            id.label = Some("id".into());
            self.store.insert(&self.slots.id, id)?;
        }
        Ok(())
    }

    pub fn access_lease(&self, ttl: Duration) -> Result<Lease, OAuthError> {
        Ok(self
            .store
            .lease(&self.slots.access, &Purpose::oauth2_access(), ttl)?)
    }

    pub fn refresh_lease(&self, ttl: Duration) -> Result<Lease, OAuthError> {
        Ok(self
            .store
            .lease(&self.slots.refresh, &Purpose::oauth2_refresh(), ttl)?)
    }

    pub fn id_lease(&self, ttl: Duration) -> Result<Lease, OAuthError> {
        Ok(self
            .store
            .lease(&self.slots.id, &Purpose::oauth2_id(), ttl)?)
    }
}

impl<T: HttpTransport> fmt::Debug for OAuth2Client<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OAuth2Client")
            .field("issuer", &self.config.issuer)
            .field("client_id", &self.config.client_id)
            .field("token_endpoint", &self.metadata.token_endpoint)
            .field("client_secret", &self.client_secret)
            .finish()
    }
}

#[cfg(feature = "reqwest")]
mod reqwest_transport {
    use super::*;

    /// Default transport. Redirects are disabled so a token request cannot be
    /// replayed to a different origin; the provider endpoints are fixed.
    pub struct ReqwestTransport {
        client: reqwest::Client,
    }

    impl ReqwestTransport {
        pub fn new() -> Result<Self, OAuthError> {
            let client = reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .map_err(|error| OAuthError::Transport(error.to_string()))?;
            Ok(Self { client })
        }
    }

    impl Default for ReqwestTransport {
        fn default() -> Self {
            Self::new().expect("reqwest client construction")
        }
    }

    async fn into_http_response(response: reqwest::Response) -> Result<HttpResponse, OAuthError> {
        let status = response.status().as_u16();
        let body = response
            .bytes()
            .await
            .map_err(|error| OAuthError::Transport(error.to_string()))?;
        Ok(HttpResponse {
            status,
            body: SecretBytes::new(body.to_vec()),
        })
    }

    #[async_trait]
    impl HttpTransport for ReqwestTransport {
        async fn post_form(
            &self,
            url: &str,
            form: &[(String, String)],
        ) -> Result<HttpResponse, OAuthError> {
            let response = self
                .client
                .post(url)
                .form(form)
                .send()
                .await
                .map_err(|error| OAuthError::Transport(error.to_string()))?;
            into_http_response(response).await
        }

        async fn get(&self, url: &str) -> Result<HttpResponse, OAuthError> {
            let response = self
                .client
                .get(url)
                .send()
                .await
                .map_err(|error| OAuthError::Transport(error.to_string()))?;
            into_http_response(response).await
        }
    }
}

#[cfg(feature = "reqwest")]
pub use reqwest_transport::ReqwestTransport;

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0)
}

// Re-exported so a caller can build a `SharedClock` without importing geode.
pub use geode::Clock as OAuthClock;

/// Convenience: current time, matching the crate's default clock.
pub fn now() -> u64 {
    unix_now()
}
