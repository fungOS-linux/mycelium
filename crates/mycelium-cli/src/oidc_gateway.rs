use std::collections::HashMap;
use std::fs;
use std::future::IntoFuture;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::{Path as AxumPath, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::routing::{get, post};
use axum::{Json, Router};
use myceliumd::client::Client;
use myceliumd::protocol::Request;
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};

#[derive(Clone)]
pub(crate) struct GatewayState {
    issuer: Arc<str>,
    audience: Arc<str>,
    ca: Arc<PathBuf>,
    enrollment_ca: Option<Arc<PathBuf>>,
    client_id: Arc<str>,
    client_secret: Arc<str>,
    callback_url: Arc<str>,
    invite_store: Arc<PathBuf>,
    invite_lock: Arc<Mutex<()>>,
    pending: Arc<Mutex<HashMap<String, Pending>>>,
}

#[derive(Clone, Deserialize, Serialize)]
struct IssueRequest {
    token: String,
    public_key: String,
    #[serde(default)]
    grant: Option<String>,
    #[serde(default = "default_ttl")]
    ttl: String,
}

#[derive(Clone, Serialize, Deserialize)]
struct IssueResponse {
    certificate: String,
    principal: String,
    expires_at: u64,
}

struct Pending {
    poll_secret: String,
    request: IssueRequest,
    result: Option<Result<IssueResponse, String>>,
}

#[derive(Serialize, Deserialize)]
struct StartResponse {
    authorization_url: String,
    request_id: String,
    poll_secret: String,
}

#[derive(Deserialize)]
struct CallbackQuery {
    code: String,
    state: String,
}

#[derive(Deserialize, Serialize)]
struct StartRequest {
    public_key: String,
    #[serde(default)]
    grant: Option<String>,
    #[serde(default = "default_ttl")]
    ttl: String,
}

#[derive(Serialize, Deserialize)]
struct ErrorResponse {
    error: String,
}

#[derive(Deserialize)]
struct ProviderFile {
    providers: HashMap<String, CredentialProvider>,
}

#[derive(Deserialize)]
struct CredentialProvider {
    issuer: String,
    audience: String,
    credential_process: Vec<String>,
}

pub async fn serve(args: &[String]) -> Result<Vec<String>, String> {
    require_write(args)?;
    let listen = required(args, "--listen")?
        .parse::<SocketAddr>()
        .map_err(|e| format!("invalid gateway listen address: {e}"))?;
    if !listen.ip().is_loopback() {
        return Err(
            "OIDC gateway only binds loopback; publish it through an HTTPS reverse proxy".into(),
        );
    }
    let issuer = required(args, "--issuer")?.trim_end_matches('/').to_owned();
    let audience = required(args, "--audience")?.to_owned();
    let ca = PathBuf::from(required(args, "--ca")?);
    let client_id = required(args, "--client-id")?.to_owned();
    if client_id != audience {
        return Err("OIDC audience must equal the gateway's registered client ID".into());
    }
    let client_secret_env = required(args, "--client-secret-env")?;
    let client_secret = std::env::var(client_secret_env).map_err(|_| {
        format!("OIDC client secret environment variable `{client_secret_env}` is not set")
    })?;
    let callback_url = required(args, "--callback-url")?.to_owned();
    let invite_store = crate::invite::store_path(args);
    if !ca.is_file() {
        return Err(format!(
            "SSH CA private key {} does not exist",
            ca.display()
        ));
    }
    let listener = tokio::net::TcpListener::bind(listen)
        .await
        .map_err(|e| format!("bind OIDC gateway {listen}: {e}"))?;
    let state = GatewayState {
        issuer: issuer.into(),
        audience: audience.into(),
        ca: Arc::new(ca),
        enrollment_ca: None,
        client_id: client_id.into(),
        client_secret: client_secret.into(),
        callback_url: callback_url.into(),
        invite_store: Arc::new(invite_store),
        invite_lock: Arc::new(Mutex::new(())),
        pending: Arc::new(Mutex::new(HashMap::new())),
    };
    let app = Router::new()
        .route("/health", get(|| async { StatusCode::NO_CONTENT }))
        .route("/v1/ssh/issue", post(issue))
        .route("/v1/oidc/start", post(start))
        .route("/v1/oidc/callback", get(callback))
        .route("/v1/oidc/status/{id}", get(status))
        .route("/v1/invite/redeem", post(redeem_invite))
        .with_state(state);
    eprintln!("mycelium OIDC gateway listening on http://{listen}; HTTPS termination is required");
    axum::serve(listener, app)
        .await
        .map_err(|e| format!("serve OIDC gateway: {e}"))?;
    Ok(Vec::new())
}

pub(crate) async fn serve_pairing(
    listen: SocketAddr,
    ca: PathBuf,
    enrollment_ca: PathBuf,
    invite_store: PathBuf,
    invitation_id: String,
    expires_at: u64,
) -> Result<(), String> {
    let listener = tokio::net::TcpListener::bind(listen)
        .await
        .map_err(|error| format!("bind pairing listener {listen}: {error}"))?;
    let state = pairing_state(ca, enrollment_ca, invite_store.clone());
    let app = Router::new()
        .route("/health", get(|| async { StatusCode::NO_CONTENT }))
        .route("/v1/invite/redeem", post(redeem_invite))
        .with_state(state);
    let server = axum::serve(listener, app).into_future();
    tokio::pin!(server);
    loop {
        tokio::select! {
            result = &mut server => {
                return result.map_err(|error| format!("serve pairing listener: {error}"));
            }
            _ = tokio::time::sleep(std::time::Duration::from_millis(250)) => {
                if pairing_finished(&invite_store, &invitation_id, expires_at)? { return Ok(()); }
            }
        }
    }
}

pub(crate) fn pairing_state(
    ca: PathBuf,
    enrollment_ca: PathBuf,
    invite_store: PathBuf,
) -> GatewayState {
    GatewayState {
        issuer: "pairing".into(),
        audience: "pairing".into(),
        ca: Arc::new(ca),
        enrollment_ca: Some(Arc::new(enrollment_ca)),
        client_id: "pairing".into(),
        client_secret: "pairing".into(),
        callback_url: "pairing".into(),
        invite_store: Arc::new(invite_store.clone()),
        invite_lock: Arc::new(Mutex::new(())),
        pending: Arc::new(Mutex::new(HashMap::new())),
    }
}

pub(crate) fn pairing_finished(store: &Path, id: &str, expires_at: u64) -> Result<bool, String> {
    let store = crate::invite::load(store)?;
    let consumed = store
        .invitations
        .iter()
        .find(|invitation| invitation.id == id)
        .is_none_or(|invitation| invitation.remaining_uses == 0);
    if consumed {
        return Ok(true);
    }
    if crate::invite::now()? >= expires_at {
        return Err("pairing claim expired before redemption".into());
    }
    Ok(false)
}

#[cfg(feature = "iroh-sync")]
pub(crate) async fn redeem_pair_request(
    state: GatewayState,
    request: crate::invite::RedeemRequest,
) -> Result<crate::invite::RedeemResponse, String> {
    redeem_invite(State(state), Json(request))
        .await
        .map(|Json(value)| value)
        .map_err(|(status, Json(error))| {
            format!("claim gateway returned {status}: {}", error.error)
        })
}

async fn redeem_invite(
    State(state): State<GatewayState>,
    Json(request): Json<crate::invite::RedeemRequest>,
) -> Result<Json<crate::invite::RedeemResponse>, (StatusCode, Json<ErrorResponse>)> {
    if request.claim.len() > 128
        || request.public_key.len() > 16 * 1024
        || request
            .peer_csr
            .as_ref()
            .is_some_and(|csr| csr.len() > 32 * 1024)
    {
        return Err(api_error(
            StatusCode::PAYLOAD_TOO_LARGE,
            "request too large",
        ));
    }
    let _guard = state
        .invite_lock
        .lock()
        .map_err(|_| api_error(StatusCode::INTERNAL_SERVER_ERROR, "invite lock poisoned"))?;
    let now = crate::invite::now()
        .map_err(|error| api_error(StatusCode::INTERNAL_SERVER_ERROR, error))?;
    let mut store = crate::invite::load(&state.invite_store)
        .map_err(|error| api_error(StatusCode::INTERNAL_SERVER_ERROR, error))?;
    let claim_hash = crate::invite::claim_hash(&request.claim);
    let index = store
        .invitations
        .iter()
        .position(|invite| invite.code_hash == claim_hash)
        .ok_or_else(|| api_error(StatusCode::UNAUTHORIZED, "invalid claim"))?;
    let invitation = store.invitations[index].clone();
    if invitation.expires_at <= now || invitation.remaining_uses == 0 {
        return Err(api_error(StatusCode::GONE, "claim expired or consumed"));
    }
    let root = temporary_root();
    fs::create_dir_all(&root)
        .map_err(|error| api_error(StatusCode::INTERNAL_SERVER_ERROR, error.to_string()))?;
    let ttl = invitation.credential_ttl;
    let result = (|| -> Result<(String, Option<crate::invite::PeerEnrollment>), String> {
        if invitation.kind == crate::invite::InvitationKind::Peer {
            let csr = request
                .peer_csr
                .as_deref()
                .ok_or("peer invitation requires a certificate signing request")?;
            let ca = state
                .enrollment_ca
                .as_deref()
                .ok_or("peer enrollment is unavailable on this gateway")?;
            let site = invitation
                .site
                .clone()
                .ok_or("peer invitation has no site")?;
            let node_certificate =
                crate::enroll::sign_csr(ca, csr, &invitation.name, &site, &root)?;
            let ca_certificate = fs::read_to_string(ca.join("ca.pem"))
                .map_err(|error| format!("read mesh CA: {error}"))?;
            let certificate = if invitation.unix_users.is_empty() {
                String::new()
            } else {
                if request.public_key.is_empty() {
                    return Err("peer invitation with SSH roles requires a public key".into());
                }
                let public_key = root.join("user.pub");
                let certificate = root.join("user-cert.pub");
                fs::write(&public_key, request.public_key.as_bytes())
                    .map_err(|error| format!("stage SSH public key: {error}"))?;
                crate::ssh_access::issue_for_invite(
                    &public_key,
                    &state.ca,
                    &certificate,
                    &invitation.id,
                    &invitation.name,
                    invitation
                        .serial
                        .wrapping_add(invitation.remaining_uses as u64),
                    &invitation.unix_users,
                    &invitation.roles,
                    ttl,
                )?;
                fs::read_to_string(certificate)
                    .map_err(|error| format!("read issued SSH certificate: {error}"))?
            };
            return Ok((
                certificate,
                Some(crate::invite::PeerEnrollment {
                    ca_certificate,
                    node_certificate,
                    site,
                    peers: invitation.peers.clone(),
                    roles: invitation.roles.clone(),
                }),
            ));
        }
        let public_key = root.join("user.pub");
        let certificate = root.join("user-cert.pub");
        fs::write(&public_key, request.public_key.as_bytes())
            .map_err(|error| format!("stage SSH public key: {error}"))?;
        crate::ssh_access::issue_for_invite(
            &public_key,
            &state.ca,
            &certificate,
            &invitation.id,
            &invitation.name,
            invitation
                .serial
                .wrapping_add(invitation.remaining_uses as u64),
            &invitation.unix_users,
            &invitation.roles,
            ttl,
        )?;
        let certificate = fs::read_to_string(&certificate)
            .map_err(|error| format!("read issued SSH certificate: {error}"))?;
        Ok((certificate, None))
    })();
    let _ = fs::remove_dir_all(&root);
    let (certificate, peer) = result.map_err(|error| api_error(StatusCode::FORBIDDEN, error))?;
    store.invitations[index].remaining_uses -= 1;
    crate::invite::save(&state.invite_store, &store)
        .map_err(|error| api_error(StatusCode::INTERNAL_SERVER_ERROR, error))?;
    Ok(Json(crate::invite::RedeemResponse {
        certificate,
        invitation: invitation.id,
        principal: invitation.name,
        expires_at: now.saturating_add(ttl),
        peer,
    }))
}

async fn issue(
    State(state): State<GatewayState>,
    headers: HeaderMap,
    Json(mut request): Json<IssueRequest>,
) -> Result<Json<IssueResponse>, (StatusCode, Json<ErrorResponse>)> {
    if headers
        .get("content-type")
        .and_then(|value| value.to_str().ok())
        .is_none_or(|value| !value.starts_with("application/json"))
    {
        return Err(api_error(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "JSON required",
        ));
    }
    if request.token.len() > 64 * 1024 || request.public_key.len() > 16 * 1024 {
        return Err(api_error(
            StatusCode::PAYLOAD_TOO_LARGE,
            "request too large",
        ));
    }
    let identity = crate::oidc::verify_token(&state.issuer, &state.audience, &request.token, None)
        .await
        .map_err(|error| api_error(StatusCode::UNAUTHORIZED, error))?;
    request.token.clear();

    let mut client = Client::connect()
        .await
        .map_err(|error| api_error(StatusCode::SERVICE_UNAVAILABLE, error.to_string()))?;
    let access = client
        .call(&Request::AccessList)
        .await
        .map_err(|error| api_error(StatusCode::SERVICE_UNAVAILABLE, error.to_string()))?;
    let root = temporary_root();
    fs::create_dir_all(&root)
        .map_err(|error| api_error(StatusCode::INTERNAL_SERVER_ERROR, error.to_string()))?;
    let key_path = root.join("user.pub");
    let certificate_path = root.join("user-cert.pub");
    let result = (|| {
        fs::write(&key_path, request.public_key.as_bytes())
            .map_err(|error| format!("stage SSH public key: {error}"))?;
        let mut args = vec![
            "ssh-issue".into(),
            "--public-key".into(),
            path_string(&key_path)?,
            "--ca".into(),
            path_string(&state.ca)?,
            "--path".into(),
            path_string(&certificate_path)?,
            "--ttl".into(),
            request.ttl,
            "--write".into(),
        ];
        if let Some(grant) = request.grant {
            args.extend(["--grant".into(), grant]);
        }
        crate::ssh_access::issue_for_oidc(
            &args,
            &access,
            &identity.principal,
            &state.audience,
            identity.expires_at,
        )?;
        fs::read_to_string(&certificate_path)
            .map_err(|error| format!("read issued SSH certificate: {error}"))
    })();
    let _ = fs::remove_dir_all(&root);
    let certificate = result.map_err(|error| api_error(StatusCode::FORBIDDEN, error))?;
    Ok(Json(IssueResponse {
        certificate,
        principal: identity.principal,
        expires_at: identity.expires_at,
    }))
}

async fn start(
    State(state): State<GatewayState>,
    Json(body): Json<StartRequest>,
) -> Result<Json<StartResponse>, (StatusCode, Json<ErrorResponse>)> {
    if body.public_key.len() > 16 * 1024 {
        return Err(api_error(
            StatusCode::PAYLOAD_TOO_LARGE,
            "public key too large",
        ));
    }
    let request_id = random_secret();
    let poll_secret = random_secret();
    state
        .pending
        .lock()
        .map_err(|_| api_error(StatusCode::INTERNAL_SERVER_ERROR, "pending lock poisoned"))?
        .insert(
            request_id.clone(),
            Pending {
                poll_secret: poll_secret.clone(),
                request: IssueRequest {
                    token: String::new(),
                    public_key: body.public_key,
                    grant: body.grant,
                    ttl: body.ttl,
                },
                result: None,
            },
        );
    let mut url = reqwest::Url::parse(&format!("{}/authorize", state.issuer))
        .map_err(|e| api_error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    url.query_pairs_mut()
        .append_pair("response_type", "code")
        .append_pair("client_id", &state.client_id)
        .append_pair("redirect_uri", &state.callback_url)
        .append_pair("scope", "openid email profile")
        .append_pair("state", &request_id);
    Ok(Json(StartResponse {
        authorization_url: url.into(),
        request_id,
        poll_secret,
    }))
}

async fn callback(
    State(state): State<GatewayState>,
    Query(query): Query<CallbackQuery>,
) -> Result<&'static str, (StatusCode, Json<ErrorResponse>)> {
    if !state
        .pending
        .lock()
        .map_err(|_| api_error(StatusCode::INTERNAL_SERVER_ERROR, "pending lock poisoned"))?
        .contains_key(&query.state)
    {
        return Err(api_error(
            StatusCode::BAD_REQUEST,
            "unknown or expired OIDC state",
        ));
    }
    let token_response = reqwest::Client::new()
        .post(format!("{}/token", state.issuer))
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", query.code.as_str()),
            ("client_id", &state.client_id),
            ("client_secret", &state.client_secret),
            ("redirect_uri", &state.callback_url),
        ])
        .send()
        .await
        .map_err(|e| api_error(StatusCode::BAD_GATEWAY, e.to_string()))?;
    let token_json: serde_json::Value = token_response
        .json()
        .await
        .map_err(|e| api_error(StatusCode::BAD_GATEWAY, e.to_string()))?;
    let token = token_json["id_token"]
        .as_str()
        .ok_or_else(|| {
            api_error(
                StatusCode::UNAUTHORIZED,
                "OIDC token response has no id_token",
            )
        })?
        .to_owned();
    let mut request = {
        let mut pending = state
            .pending
            .lock()
            .map_err(|_| api_error(StatusCode::INTERNAL_SERVER_ERROR, "pending lock poisoned"))?;
        pending
            .get_mut(&query.state)
            .ok_or_else(|| api_error(StatusCode::BAD_REQUEST, "unknown OIDC state"))?
            .request
            .clone()
    };
    request.token = token;
    let mut headers = HeaderMap::new();
    headers.insert("content-type", "application/json".parse().unwrap());
    let result = issue(State(state.clone()), headers, Json(request))
        .await
        .map(|Json(value)| value)
        .map_err(|(_, Json(error))| error.error);
    state
        .pending
        .lock()
        .map_err(|_| api_error(StatusCode::INTERNAL_SERVER_ERROR, "pending lock poisoned"))?
        .get_mut(&query.state)
        .unwrap()
        .result = Some(result);
    Ok("Mycelium authentication complete. You may close this window.")
}

async fn status(
    State(state): State<GatewayState>,
    AxumPath(id): AxumPath<String>,
    headers: HeaderMap,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<ErrorResponse>)> {
    let bearer = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or_else(|| api_error(StatusCode::UNAUTHORIZED, "poll secret required"))?;
    let mut pending = state
        .pending
        .lock()
        .map_err(|_| api_error(StatusCode::INTERNAL_SERVER_ERROR, "pending lock poisoned"))?;
    let item = pending
        .get(&id)
        .ok_or_else(|| api_error(StatusCode::NOT_FOUND, "join request not found"))?;
    if item.poll_secret != bearer {
        return Err(api_error(StatusCode::UNAUTHORIZED, "invalid poll secret"));
    }
    match item.result.clone() {
        None => Ok((
            StatusCode::ACCEPTED,
            Json(serde_json::json!({"status":"pending"})),
        )),
        Some(Ok(value)) => {
            pending.remove(&id);
            Ok((StatusCode::OK, Json(serde_json::to_value(value).unwrap())))
        }
        Some(Err(error)) => {
            pending.remove(&id);
            Err(api_error(StatusCode::FORBIDDEN, error))
        }
    }
}

pub async fn join(args: &[String]) -> Result<Vec<String>, String> {
    require_write(args)?;
    let gateway = required(args, "--gateway")?.trim_end_matches('/');
    validate_gateway_url(gateway)?;
    let public_key_path = required(args, "--public-key")?;
    let public_key = fs::read_to_string(public_key_path)
        .map_err(|e| format!("read SSH public key {public_key_path}: {e}"))?;
    let certificate_path = Path::new(required(args, "--certificate")?);
    if certificate_path.exists() {
        return Err(format!(
            "refusing to replace existing SSH certificate {}",
            certificate_path.display()
        ));
    }
    let client = reqwest::Client::new();
    let configured_token = value(args, "--provider")
        .map(|provider| credential_process(args, provider))
        .transpose()?;
    let response = if let Some((token, provider)) = configured_token {
        crate::oidc::verify_token(&provider.issuer, &provider.audience, &token, None).await?;
        client
            .post(format!("{gateway}/v1/ssh/issue"))
            .json(&IssueRequest {
                token,
                public_key,
                grant: value(args, "--grant").map(str::to_owned),
                ttl: value(args, "--ttl").unwrap_or("8h").to_owned(),
            })
            .send()
            .await
            .map_err(|e| format!("request SSH certificate from gateway: {e}"))?
    } else if let Some(token_env) = value(args, "--token-env") {
        let token = std::env::var(token_env)
            .map_err(|_| format!("OIDC token environment variable `{token_env}` is not set"))?;
        client
            .post(format!("{gateway}/v1/ssh/issue"))
            .json(&IssueRequest {
                token,
                public_key,
                grant: value(args, "--grant").map(str::to_owned),
                ttl: value(args, "--ttl").unwrap_or("8h").to_owned(),
            })
            .send()
            .await
            .map_err(|e| format!("request SSH certificate from gateway: {e}"))?
    } else {
        let started = client
            .post(format!("{gateway}/v1/oidc/start"))
            .json(&StartRequest {
                public_key,
                grant: value(args, "--grant").map(str::to_owned),
                ttl: value(args, "--ttl").unwrap_or("8h").to_owned(),
            })
            .send()
            .await
            .map_err(|e| format!("start OIDC join: {e}"))?;
        if !started.status().is_success() {
            return Err(format!(
                "OIDC gateway refused join start: {}",
                started.status()
            ));
        }
        let started: StartResponse = started
            .json()
            .await
            .map_err(|e| format!("decode join start: {e}"))?;
        eprintln!(
            "Open this URL to authenticate:\n{}",
            started.authorization_url
        );
        open_browser(&started.authorization_url);
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            let polled = client
                .get(format!("{gateway}/v1/oidc/status/{}", started.request_id))
                .bearer_auth(&started.poll_secret)
                .send()
                .await
                .map_err(|e| format!("poll OIDC join: {e}"))?;
            if polled.status() == StatusCode::ACCEPTED {
                continue;
            }
            break polled;
        }
    };
    if !response.status().is_success() {
        let status = response.status();
        let error = response
            .json::<ErrorResponse>()
            .await
            .map(|body| body.error)
            .unwrap_or_else(|_| "gateway returned an unreadable error".into());
        return Err(format!("OIDC gateway returned {status}: {error}"));
    }
    let issued = response
        .json::<IssueResponse>()
        .await
        .map_err(|e| format!("decode OIDC gateway response: {e}"))?;
    if let Some(parent) = certificate_path.parent() {
        fs::create_dir_all(parent).map_err(|e| format!("create {}: {e}", parent.display()))?;
    }
    let staging = certificate_path.with_extension("mycelium-staging");
    fs::write(&staging, issued.certificate)
        .map_err(|e| format!("write staged SSH certificate {}: {e}", staging.display()))?;
    fs::rename(&staging, certificate_path).map_err(|e| {
        format!(
            "install SSH certificate {}: {e}",
            certificate_path.display()
        )
    })?;
    Ok(vec![format!(
        "joined as {}; wrote {} (OIDC token expires at {})",
        issued.principal,
        certificate_path.display(),
        issued.expires_at
    )])
}

pub async fn redeem(args: &[String]) -> Result<Vec<String>, String> {
    require_write(args)?;
    let packaged = crate::packaged::current()?;
    if value(args, "--peer-csr").is_some() && packaged {
        let home = value(args, "--home")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(crate::packaged::HOME));
        crate::packaged::validate(
            &home,
            args.iter().any(|argument| argument == "--system-service"),
        )?;
        if home.join("pki/node-key.pem").exists() || home.join("node.env").exists() {
            return Err("refusing a new packaged peer claim over an existing identity; use setup --packaged --repair".into());
        }
    }
    let gateway = required(args, "--gateway")?.trim_end_matches('/');
    if !gateway.starts_with("iroh-pair:") {
        validate_gateway_url(gateway)?;
    }
    let claim = required(args, "--claim")?;
    let public_key = value(args, "--public-key")
        .map(fs::read_to_string)
        .transpose()
        .map_err(|error| format!("read SSH public key: {error}"))?
        .unwrap_or_default();
    let peer_csr = value(args, "--peer-csr")
        .map(fs::read_to_string)
        .transpose()
        .map_err(|error| format!("read peer CSR: {error}"))?;
    if public_key.is_empty() && peer_csr.is_none() {
        return Err("redeem needs --public-key, --peer-csr, or both".into());
    }
    let certificate_path = value(args, "--certificate").map(Path::new);
    if certificate_path.is_some_and(Path::exists) {
        return Err(format!(
            "refusing to replace existing SSH certificate {}",
            certificate_path.expect("checked above").display()
        ));
    }
    let request = crate::invite::RedeemRequest {
        claim: claim.to_owned(),
        public_key,
        peer_csr,
    };
    if gateway.starts_with("iroh-pair:") {
        let home = value(args, "--home")
            .map(PathBuf::from)
            .unwrap_or_else(myceliumd::home_dir);
        if home.join("iroh-sync.json").exists() || home.join("pki/node-key.pem").exists() {
            return Err(
                "refusing to redeem a new-peer claim over an existing peer identity/configuration"
                    .into(),
            );
        }
    }
    #[cfg(feature = "iroh-sync")]
    let mut sync_seed = None;
    let redeemed = if gateway.starts_with("iroh-pair:") {
        #[cfg(feature = "iroh-sync")]
        {
            let (response, seed, relays) = crate::pair_iroh::redeem(gateway, request).await?;
            sync_seed = Some((seed, relays));
            response
        }
        #[cfg(not(feature = "iroh-sync"))]
        {
            return Err("Iroh enrollment requires --features iroh-sync".into());
        }
    } else {
        let response = reqwest::Client::new()
            .post(format!("{gateway}/v1/invite/redeem"))
            .json(&request)
            .send()
            .await
            .map_err(|error| format!("redeem Mycelium claim: {error}"))?;
        if !response.status().is_success() {
            let status = response.status();
            let error = response
                .json::<ErrorResponse>()
                .await
                .map(|body| body.error)
                .unwrap_or_else(|_| "gateway returned an unreadable error".into());
            return Err(format!("claim gateway returned {status}: {error}"));
        }
        response
            .json::<crate::invite::RedeemResponse>()
            .await
            .map_err(|error| format!("decode claim response: {error}"))?
    };
    if let Some(peer) = redeemed.peer {
        let home = value(args, "--home").map(PathBuf::from).unwrap_or_else(|| {
            if packaged {
                PathBuf::from(crate::packaged::HOME)
            } else {
                myceliumd::home_dir()
            }
        });
        let key = Path::new(required(args, "--peer-key")?);
        #[cfg(feature = "iroh-sync")]
        let iroh_server_name = if let Some((seed, relays)) = sync_seed {
            crate::pair_iroh::install_seed(&home, seed, relays)?;
            Some(redeemed.principal.as_str())
        } else {
            None
        };
        #[cfg(not(feature = "iroh-sync"))]
        let iroh_server_name = None;
        let mut lines = crate::enroll::install_peer_material(
            &home,
            key,
            &peer.node_certificate,
            &peer.ca_certificate,
            &peer.site,
            &peer.peers,
            args.iter().any(|argument| argument == "--system-service"),
            iroh_server_name,
        )?;
        if !redeemed.certificate.is_empty() {
            let certificate_path =
                certificate_path.ok_or("peer access claim needs --certificate")?;
            if let Some(parent) = certificate_path.parent() {
                fs::create_dir_all(parent)
                    .map_err(|error| format!("create {}: {error}", parent.display()))?;
            }
            fs::write(certificate_path, redeemed.certificate)
                .map_err(|error| format!("install SSH certificate: {error}"))?;
            lines.push(format!(
                "installed role-bound SSH certificate at {}",
                certificate_path.display()
            ));
        }
        lines.push(format!(
            "claimed peer invitation {} as {} with roles [{}]",
            redeemed.invitation,
            redeemed.principal,
            peer.roles.join(",")
        ));
        return Ok(lines);
    }
    let certificate_path = certificate_path.ok_or("access claim needs --certificate")?;
    if let Some(parent) = certificate_path.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| format!("create {}: {error}", parent.display()))?;
    }
    let staging = certificate_path.with_extension("mycelium-staging");
    fs::write(&staging, redeemed.certificate)
        .map_err(|error| format!("write staged certificate {}: {error}", staging.display()))?;
    fs::rename(&staging, certificate_path).map_err(|error| {
        format!(
            "install SSH certificate {}: {error}",
            certificate_path.display()
        )
    })?;
    Ok(vec![format!(
        "claimed invitation {} as {}; wrote {} (credential expires at {})",
        redeemed.invitation,
        redeemed.principal,
        certificate_path.display(),
        redeemed.expires_at
    )])
}

fn credential_process(args: &[String], name: &str) -> Result<(String, CredentialProvider), String> {
    let path = value(args, "--providers")
        .map(PathBuf::from)
        .unwrap_or_else(|| myceliumd::home_dir().join("auth-providers.json"));
    let raw = fs::read_to_string(&path)
        .map_err(|e| format!("read auth providers {}: {e}", path.display()))?;
    let mut file: ProviderFile = serde_json::from_str(&raw)
        .map_err(|e| format!("parse auth providers {}: {e}", path.display()))?;
    let provider = file
        .providers
        .remove(name)
        .ok_or_else(|| format!("auth provider `{name}` is not configured"))?;
    let (program, process_args) = provider
        .credential_process
        .split_first()
        .ok_or_else(|| format!("auth provider `{name}` has an empty credential_process"))?;
    let output = std::process::Command::new(program)
        .args(process_args)
        .output()
        .map_err(|e| format!("run credential process for `{name}`: {e}"))?;
    if !output.status.success() {
        return Err(format!(
            "credential process for `{name}` exited {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let body: serde_json::Value = serde_json::from_slice(&output.stdout)
        .map_err(|e| format!("credential process for `{name}` returned invalid JSON: {e}"))?;
    let token = body["access_token"]
        .as_str()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| format!("credential process for `{name}` returned no access_token"))?;
    Ok((token.to_owned(), provider))
}

fn validate_gateway_url(value: &str) -> Result<(), String> {
    let url = reqwest::Url::parse(value).map_err(|e| format!("invalid gateway URL: {e}"))?;
    let private = url.host_str().is_some_and(|host| {
        host == "localhost"
            || host
                .parse::<std::net::IpAddr>()
                .is_ok_and(crate::pair::private_transport_ip)
    });
    if url.scheme() != "https" && !(url.scheme() == "http" && private) {
        return Err("gateway URL must use HTTPS (HTTP is allowed only on private networks)".into());
    }
    if url.username() != "" || url.password().is_some() {
        return Err("gateway URL must not contain credentials".into());
    }
    Ok(())
}

fn api_error(status: StatusCode, error: impl Into<String>) -> (StatusCode, Json<ErrorResponse>) {
    (
        status,
        Json(ErrorResponse {
            error: error.into(),
        }),
    )
}

fn temporary_root() -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos());
    std::env::temp_dir().join(format!("mycelium-oidc-{}-{nanos}", std::process::id()))
}

fn random_secret() -> String {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn open_browser(url: &str) {
    let command = if cfg!(target_os = "macos") {
        "open"
    } else {
        "xdg-open"
    };
    let _ = std::process::Command::new(command).arg(url).spawn();
}

fn path_string(path: &Path) -> Result<String, String> {
    path.to_str()
        .map(str::to_owned)
        .ok_or_else(|| format!("path is not UTF-8: {}", path.display()))
}

fn default_ttl() -> String {
    "8h".into()
}

fn value<'a>(args: &'a [String], flag: &str) -> Option<&'a str> {
    args.iter()
        .position(|arg| arg == flag)
        .and_then(|index| args.get(index + 1))
        .map(String::as_str)
}

fn required<'a>(args: &'a [String], flag: &str) -> Result<&'a str, String> {
    value(args, flag).ok_or_else(|| format!("OIDC access command needs {flag}"))
}

fn require_write(args: &[String]) -> Result<(), String> {
    args.iter()
        .any(|arg| arg == "--write")
        .then_some(())
        .ok_or_else(|| "OIDC gateway changes require --write".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gateway_transport_requires_tls_except_on_loopback() {
        assert!(validate_gateway_url("https://access.example.test").is_ok());
        assert!(validate_gateway_url("http://127.0.0.1:8787").is_ok());
        assert!(validate_gateway_url("http://192.168.1.2:8787").is_ok());
        assert!(validate_gateway_url("http://100.120.101.5:8787").is_ok());
        assert!(validate_gateway_url("http://access.example.test").is_err());
        assert!(validate_gateway_url("https://user:secret@access.example.test").is_err());
    }

    #[test]
    fn credential_process_uses_argv_without_a_shell() {
        let root = temporary_root();
        fs::create_dir_all(&root).unwrap();
        let path = root.join("providers.json");
        fs::write(&path, r#"{"providers":{"test":{"issuer":"https://issuer.example","audience":"mycelium","credential_process":["/bin/echo","{\"access_token\":\"jwt\"}"]}}}"#).unwrap();
        let args = vec!["--providers".into(), path.to_string_lossy().into_owned()];
        let (token, provider) = credential_process(&args, "test").unwrap();
        assert_eq!(token, "jwt");
        assert_eq!(provider.audience, "mycelium");
        fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn invitation_is_consumed_only_once() {
        let root = temporary_root();
        fs::create_dir_all(&root).unwrap();
        let ca = root.join("ca");
        let user = root.join("user");
        for key in [&ca, &user] {
            let status = std::process::Command::new("ssh-keygen")
                .args(["-q", "-t", "ed25519", "-N", "", "-f"])
                .arg(key)
                .status()
                .unwrap();
            assert!(status.success());
        }
        let claim = "MYC-AAAA-BBBB-CCCC-DDDD-EEEE-FFFF-0000-1111";
        let store_path = root.join("invites.json");
        crate::invite::save(
            &store_path,
            &crate::invite::InviteStore {
                invitations: vec![crate::invite::Invitation {
                    kind: crate::invite::InvitationKind::Access,
                    id: "invite-1".into(),
                    code_hash: crate::invite::claim_hash(claim),
                    name: "buddy".into(),
                    unix_users: vec!["operator".into()],
                    roles: Vec::new(),
                    site: None,
                    peers: Vec::new(),
                    expires_at: crate::invite::now().unwrap() + 900,
                    credential_ttl: 3600,
                    remaining_uses: 1,
                    serial: 42,
                }],
            },
        )
        .unwrap();
        let state = GatewayState {
            issuer: "https://issuer.example".into(),
            audience: "mycelium".into(),
            ca: Arc::new(ca),
            enrollment_ca: None,
            client_id: "mycelium".into(),
            client_secret: "unused".into(),
            callback_url: "https://issuer.example/callback".into(),
            invite_store: Arc::new(store_path.clone()),
            invite_lock: Arc::new(Mutex::new(())),
            pending: Arc::new(Mutex::new(HashMap::new())),
        };
        let request = crate::invite::RedeemRequest {
            claim: claim.into(),
            public_key: fs::read_to_string(user.with_extension("pub")).unwrap(),
            peer_csr: None,
        };
        let first = redeem_invite(State(state.clone()), Json(request.clone())).await;
        assert!(first.is_ok());
        let second = redeem_invite(State(state), Json(request)).await;
        assert_eq!(second.unwrap_err().0, StatusCode::GONE);
        assert_eq!(
            crate::invite::load(&store_path).unwrap().invitations[0].remaining_uses,
            0
        );
        fs::remove_dir_all(root).unwrap();
    }
}
