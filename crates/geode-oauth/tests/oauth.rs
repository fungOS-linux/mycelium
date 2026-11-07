use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use geode::{CredentialKind, GeodeRef, ManualClock, MemoryBackend, SecretBytes, Store};
use geode_oauth::{
    DevicePoll, HttpResponse, HttpTransport, OAuth2Client, OAuth2Config, Pkce, ProviderMetadata,
    TokenSlots, TokenVault,
};
use url::Url;

const ISSUER: &str = "https://sso.fpl.dev";

#[derive(Debug)]
struct Call {
    method: &'static str,
    url: String,
    form: Vec<(String, String)>,
}

struct FakeTransport {
    calls: Mutex<Vec<Call>>,
    responses: Mutex<VecDeque<HttpResponse>>,
}

impl FakeTransport {
    fn new(responses: impl IntoIterator<Item = (u16, &'static str)>) -> Self {
        Self {
            calls: Mutex::new(Vec::new()),
            responses: Mutex::new(
                responses
                    .into_iter()
                    .map(|(status, body)| HttpResponse {
                        status,
                        body: SecretBytes::from(body),
                    })
                    .collect(),
            ),
        }
    }

    fn next(&self) -> HttpResponse {
        self.responses
            .lock()
            .unwrap()
            .pop_front()
            .expect("no queued response")
    }

    fn calls(&self) -> std::sync::MutexGuard<'_, Vec<Call>> {
        self.calls.lock().unwrap()
    }
}

#[async_trait]
impl HttpTransport for FakeTransport {
    async fn post_form(
        &self,
        url: &str,
        form: &[(String, String)],
    ) -> Result<HttpResponse, geode_oauth::OAuthError> {
        self.calls.lock().unwrap().push(Call {
            method: "POST",
            url: url.into(),
            form: form.to_vec(),
        });
        Ok(self.next())
    }

    async fn get(&self, url: &str) -> Result<HttpResponse, geode_oauth::OAuthError> {
        self.calls.lock().unwrap().push(Call {
            method: "GET",
            url: url.into(),
            form: Vec::new(),
        });
        Ok(self.next())
    }
}

fn metadata() -> ProviderMetadata {
    ProviderMetadata {
        issuer: ISSUER.into(),
        authorization_endpoint: "https://sso.fpl.dev/oidc/authorize".into(),
        token_endpoint: "https://sso.fpl.dev/oidc/token".into(),
        device_authorization_endpoint: Some("https://sso.fpl.dev/oidc/device".into()),
        jwks_uri: Some("https://sso.fpl.dev/oidc/jwks".into()),
        scopes_supported: vec!["openid".into()],
    }
}

fn config() -> OAuth2Config {
    OAuth2Config::new(ISSUER, "mycelium")
        .with_scope("openid")
        .with_scope("profile")
        .with_redirect_uri("http://127.0.0.1:53682/callback")
}

fn clock(start: u64) -> (Arc<ManualClock>, Arc<dyn geode::Clock>) {
    let manual = Arc::new(ManualClock::new(start));
    let shared: Arc<dyn geode::Clock> = manual.clone();
    (manual, shared)
}

#[test]
fn pkce_matches_the_rfc_7636_vector() {
    let pkce = Pkce::from_verifier("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk").unwrap();
    assert_eq!(
        pkce.challenge(),
        "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
    );
    assert!(!format!("{pkce:?}").contains(pkce.verifier()));
}

#[tokio::test]
async fn discovery_validates_the_issuer_and_endpoint_scheme() {
    let transport = FakeTransport::new([(
        200,
        r#"{
            "issuer": "https://sso.fpl.dev",
            "authorization_endpoint": "https://sso.fpl.dev/oidc/authorize",
            "token_endpoint": "https://sso.fpl.dev/oidc/token",
            "device_authorization_endpoint": "https://sso.fpl.dev/oidc/device",
            "scopes_supported": ["openid", "profile"],
            "extra_field_is_ignored": true
        }"#,
    )]);
    let client = OAuth2Client::discover(config(), transport).await.unwrap();
    assert_eq!(client.metadata().issuer, ISSUER);

    let mismatch = FakeTransport::new([(
        200,
        r#"{
            "issuer": "https://evil.example",
            "authorization_endpoint": "https://evil.example/authorize",
            "token_endpoint": "https://evil.example/token"
        }"#,
    )]);
    assert!(OAuth2Client::discover(config(), mismatch).await.is_err());
}

#[tokio::test]
async fn authorization_url_carries_pkce_scope_and_state() {
    let transport = FakeTransport::new(Vec::<(u16, &str)>::new());
    let client = OAuth2Client::new(config(), metadata(), transport).unwrap();
    let pkce = Pkce::generate();
    let url = Url::parse(&client.authorization_url("state-123", &pkce).unwrap()).unwrap();
    let query: std::collections::HashMap<_, _> = url.query_pairs().into_owned().collect();
    assert_eq!(url.path(), "/oidc/authorize");
    assert_eq!(query["response_type"], "code");
    assert_eq!(query["client_id"], "mycelium");
    assert_eq!(query["state"], "state-123");
    assert_eq!(query["code_challenge"], pkce.challenge());
    assert_eq!(query["code_challenge_method"], "S256");
    assert_eq!(query["scope"], "openid profile");
    assert_eq!(query["redirect_uri"], "http://127.0.0.1:53682/callback");
}

#[tokio::test]
async fn code_exchange_posts_the_verifier_and_parses_expiry() {
    let transport = Arc::new(FakeTransport::new([(
        200,
        r#"{
            "access_token": "access-1",
            "refresh_token": "refresh-1",
            "id_token": "id-1",
            "token_type": "Bearer",
            "scope": "openid profile email",
            "expires_in": 3600
        }"#,
    )]));
    let (_manual, shared) = clock(1_000);
    let client = OAuth2Client::new(config(), metadata(), ArcTransport(transport.clone()))
        .unwrap()
        .with_clock(shared);
    let pkce = Pkce::from_verifier("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk").unwrap();
    let tokens = client.exchange_code("code-1", &pkce).await.unwrap();

    assert_eq!(tokens.access_token.expose(), b"access-1");
    assert_eq!(
        tokens.refresh_token.as_ref().unwrap().expose(),
        b"refresh-1"
    );
    assert_eq!(tokens.expires_at, Some(4_600));
    assert_eq!(tokens.issued_at, 1_000);
    assert!(tokens.scopes.contains("email"));
    assert!(!format!("{tokens:?}").contains("access-1"));
    assert!(!format!("{tokens:?}").contains("refresh-1"));

    let calls = transport.calls();
    assert_eq!(calls[0].method, "POST");
    assert_eq!(calls[0].url, "https://sso.fpl.dev/oidc/token");
    let form = &calls[0].form;
    assert_eq!(form_value(form, "grant_type"), "authorization_code");
    assert_eq!(form_value(form, "code"), "code-1");
    assert_eq!(form_value(form, "code_verifier"), pkce.verifier());
    assert_eq!(
        form_value(form, "redirect_uri"),
        "http://127.0.0.1:53682/callback"
    );
}

fn form_value<'a>(form: &'a [(String, String)], key: &str) -> &'a str {
    form.iter()
        .find(|(name, _)| name == key)
        .map(|(_, value)| value.as_str())
        .unwrap_or_default()
}

#[tokio::test]
async fn refresh_uses_the_refresh_token_and_surfaces_provider_errors() {
    let transport = FakeTransport::new([
        (200, r#"{"access_token":"access-2","expires_in":60}"#),
        (
            400,
            r#"{"error":"invalid_grant","error_description":"expired"}"#,
        ),
    ]);
    // Keep a handle to inspect calls: reuse the same queue via Arc.
    let transport = Arc::new(transport);
    let client = OAuth2Client::new(config(), metadata(), ArcTransport(transport.clone())).unwrap();
    let refresh = SecretBytes::from("refresh-1");
    let tokens = client.refresh(&refresh).await.unwrap();
    assert_eq!(tokens.access_token.expose(), b"access-2");
    assert!(tokens.refresh_token.is_none());

    let error = client.refresh(&refresh).await.unwrap_err();
    assert!(matches!(
        error,
        geode_oauth::OAuthError::Server { status: 400, .. }
    ));

    let calls = transport.calls();
    assert_eq!(form_value(&calls[0].form, "grant_type"), "refresh_token");
    assert_eq!(form_value(&calls[0].form, "refresh_token"), "refresh-1");
}

#[tokio::test]
async fn device_flow_reports_pending_then_authorized() {
    let transport = FakeTransport::new([
        (
            200,
            r#"{
                "device_code": "device-1",
                "user_code": "ABCD-EFGH",
                "verification_uri": "https://sso.fpl.dev/device",
                "expires_in": 600,
                "interval": 5
            }"#,
        ),
        (400, r#"{"error":"authorization_pending"}"#),
        (400, r#"{"error":"slow_down"}"#),
        (
            200,
            r#"{"access_token":"access-3","refresh_token":"refresh-3","expires_in":300}"#,
        ),
    ]);
    let transport = Arc::new(transport);
    let (_manual, shared) = clock(2_000);
    let client = OAuth2Client::new(config(), metadata(), ArcTransport(transport.clone()))
        .unwrap()
        .with_clock(shared);

    let device = client.start_device_authorization().await.unwrap();
    assert_eq!(device.user_code, "ABCD-EFGH");
    assert_eq!(device.expires_at, 2_600);
    assert!(!format!("{device:?}").contains("device-1"));

    assert!(matches!(
        client.poll_device_token(&device).await.unwrap(),
        DevicePoll::Pending
    ));
    assert!(matches!(
        client.poll_device_token(&device).await.unwrap(),
        DevicePoll::SlowDown
    ));
    let DevicePoll::Authorized(tokens) = client.poll_device_token(&device).await.unwrap() else {
        panic!("expected authorization");
    };
    assert_eq!(tokens.access_token.expose(), b"access-3");

    let calls = transport.calls();
    assert_eq!(
        form_value(&calls[1].form, "grant_type"),
        geode_oauth::DEVICE_CODE_GRANT
    );
    assert_eq!(form_value(&calls[1].form, "device_code"), "device-1");
}

#[tokio::test]
async fn token_vault_persists_tokens_and_preserves_a_rotated_refresh() {
    let (manual, shared) = clock(1_000);
    let store = Store::with_clock(MemoryBackend::new(), shared.clone());
    let slots = TokenSlots::for_account("oauth", "fpl").unwrap();
    assert_eq!(slots.access.as_reference(), "geode://oauth/fpl/access");
    let vault = TokenVault::new(&store, slots.clone());

    let transport = FakeTransport::new([
        (
            200,
            r#"{"access_token":"a1","refresh_token":"r1","expires_in":60}"#,
        ),
        (200, r#"{"access_token":"a2","expires_in":60}"#),
    ]);
    let client = OAuth2Client::new(config(), metadata(), transport)
        .unwrap()
        .with_clock(shared);
    let first = client.exchange_code("c1", &Pkce::generate()).await.unwrap();
    vault.persist(&first).unwrap();

    let access = vault.access_lease(Duration::from_secs(5)).unwrap();
    assert_eq!(access.expose().unwrap(), b"a1");
    drop(access);

    let second = client.exchange_code("c2", &Pkce::generate()).await.unwrap();
    vault.persist(&second).unwrap();
    let access = vault.access_lease(Duration::from_secs(5)).unwrap();
    assert_eq!(access.expose().unwrap(), b"a2");
    let refresh = vault.refresh_lease(Duration::from_secs(5)).unwrap();
    assert_eq!(
        refresh.expose().unwrap(),
        b"r1",
        "refresh token is retained"
    );

    let meta = store.describe(&slots.access).unwrap().unwrap();
    assert_eq!(meta.kind, CredentialKind::OAuth2AccessToken);
    assert_eq!(meta.expires_at, Some(1_060));
    assert!(meta.purposes.contains(&geode::Purpose::oauth2_access()));

    manual.advance(Duration::from_secs(1));
    let missing = GeodeRef::parse("geode://oauth/other/id").unwrap();
    assert!(store.describe(&missing).unwrap().is_none());
}

/// Newtype so an `Arc<FakeTransport>` can satisfy `HttpTransport` without
/// cloning the queue.
struct ArcTransport(Arc<FakeTransport>);

#[async_trait]
impl HttpTransport for ArcTransport {
    async fn post_form(
        &self,
        url: &str,
        form: &[(String, String)],
    ) -> Result<HttpResponse, geode_oauth::OAuthError> {
        self.0.post_form(url, form).await
    }

    async fn get(&self, url: &str) -> Result<HttpResponse, geode_oauth::OAuthError> {
        self.0.get(url).await
    }
}
