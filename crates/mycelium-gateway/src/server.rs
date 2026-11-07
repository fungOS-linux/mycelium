use crate::config::{GatewayConfig, Route};
use crate::discovery::ServiceIndex;
use crate::route::RouteTable;
use axum::body::Body;
use axum::extract::State;
use axum::http::{Request, Response, StatusCode, Uri};
use axum::routing::get;
use axum::Router;
use futures_util::StreamExt;
use serde_json::json;
use std::collections::BTreeSet;
use std::io::{Error, ErrorKind};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;

const MAX_BODY_BYTES: usize = 32 * 1024 * 1024;

#[derive(Clone)]
struct GatewayState {
    client: reqwest::Client,
    table: Arc<std::sync::RwLock<RouteTable>>,
    services: Arc<std::sync::RwLock<ServiceIndex>>,
    auth_token: Option<Arc<str>>,
}

#[derive(Clone, Debug)]
struct Target {
    base: reqwest::Url,
    remote: bool,
}

pub async fn run(
    listen: SocketAddr,
    config_path: Option<PathBuf>,
    token_file: Option<PathBuf>,
    reload_secs: u64,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Read every operator input before opening the listener. A gateway that
    // started without its token or route table would be quietly wrong.
    let auth_token = match token_file.as_deref() {
        Some(path) => Some(read_token(path)?),
        None => None,
    };
    let (config, initial_mtime) = match config_path.as_deref() {
        Some(path) => (GatewayConfig::load(path)?, mtime(path)),
        None => (default_config(), None),
    };
    let table = Arc::new(std::sync::RwLock::new(RouteTable::new(
        config.routes.clone(),
        config.default_route.clone(),
    )));
    let services = Arc::new(std::sync::RwLock::new(ServiceIndex::default()));
    let discovery = config
        .routes
        .iter()
        .any(|route| route.service_kind.is_some())
        .then(|| {
            (
                config
                    .mycelium_bin
                    .clone()
                    .expect("validated: service_kind requires mycelium_bin"),
                config.service_refresh_secs,
            )
        });

    if let Some((bin, refresh_secs)) = discovery.clone() {
        match ServiceIndex::load(&bin).await {
            Ok(index) => {
                eprintln!(
                    "mycelium-gateway: discovered {} service endpoints from {}",
                    index.len(),
                    bin.display()
                );
                *services.write().unwrap() = index;
            }
            Err(error) => {
                eprintln!(
                    "mycelium-gateway: initial service discovery failed; static routes still work: {error}"
                );
            }
        }
        spawn_service_refresh(bin, refresh_secs, services.clone());
    }

    let state = GatewayState {
        client: reqwest::Client::builder()
            .timeout(Duration::from_secs(300))
            .pool_max_idle_per_host(64)
            .build()?,
        table: table.clone(),
        services,
        auth_token: auth_token.map(Arc::from),
    };

    if let (Some(path), true) = (config_path, reload_secs > 0) {
        spawn_reload(path, table, initial_mtime, reload_secs);
    }

    let listener = TcpListener::bind(listen).await?;
    eprintln!("mycelium-gateway: listening on {listen}; routing by Host");
    axum::serve(listener, routes(state))
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    Ok(())
}

fn read_token(path: &Path) -> std::io::Result<String> {
    let token = std::fs::read_to_string(path)?.trim().to_owned();
    if token.is_empty() {
        return Err(Error::new(
            ErrorKind::InvalidData,
            format!("{} is empty", path.display()),
        ));
    }
    Ok(token)
}

fn spawn_service_refresh(
    bin: PathBuf,
    refresh_secs: u64,
    services: Arc<std::sync::RwLock<ServiceIndex>>,
) {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(refresh_secs)).await;
            match ServiceIndex::load(&bin).await {
                Ok(index) => {
                    *services.write().unwrap() = index;
                }
                Err(error) => {
                    eprintln!(
                        "mycelium-gateway: service refresh failed; keeping previous catalog: {error}"
                    );
                }
            }
        }
    });
}

fn spawn_reload(
    path: PathBuf,
    table: Arc<std::sync::RwLock<RouteTable>>,
    mut last_mtime: Option<std::time::SystemTime>,
    reload_secs: u64,
) {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(reload_secs)).await;
            let current = mtime(&path);
            if current == last_mtime {
                continue;
            }
            // Update the cursor even on failure: a malformed edit should log
            // once, not once per second, and the next save will be retried.
            last_mtime = current;
            match GatewayConfig::load(&path) {
                Ok(config) => {
                    *table.write().unwrap() = RouteTable::new(config.routes, config.default_route);
                    eprintln!("mycelium-gateway: reloaded {}", path.display());
                }
                Err(error) => {
                    eprintln!("mycelium-gateway: keeping previous routes; reload failed: {error}");
                }
            }
        }
    });
}

fn routes(state: GatewayState) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .fallback(proxy)
        .with_state(state)
}

async fn healthz(State(state): State<GatewayState>) -> impl axum::response::IntoResponse {
    let table = state.table.read().unwrap();
    let services = state.services.read().unwrap();
    axum::Json(json!({
        "ok": true,
        "routes": table.routes().len(),
        "service_endpoints": services.len(),
        "local_node": services.local_node(),
        "auth_required": state.auth_token.is_some()
    }))
}

async fn proxy(State(state): State<GatewayState>, request: Request<Body>) -> Response<Body> {
    if !authorized(&request, state.auth_token.as_deref()) {
        return text(StatusCode::UNAUTHORIZED, "unauthorized");
    }

    let host = request
        .headers()
        .get("host")
        .and_then(|value| value.to_str().ok())
        .map(crate::route::normalize_host)
        .unwrap_or_default();
    let Some(route) = state.table.read().unwrap().select(&host) else {
        return text(StatusCode::NOT_FOUND, "no route");
    };
    let targets = targets_for(&route, &state.services.read().unwrap());
    if targets.is_empty() {
        return text(StatusCode::SERVICE_UNAVAILABLE, "no backend for route");
    }

    let method = request.method().clone();
    let uri = request.uri().clone();
    let headers = request.headers().clone();
    let body = match axum::body::to_bytes(request.into_body(), MAX_BODY_BYTES).await {
        Ok(body) => body,
        Err(_) => return text(StatusCode::PAYLOAD_TOO_LARGE, "request body too large"),
    };

    let mut last_error = None;
    for target in targets {
        let Some(url) = upstream_url(&target.base, &uri) else {
            last_error = Some("invalid upstream URL".to_owned());
            continue;
        };
        let mut forwarded = state.client.request(method.clone(), url);
        for (name, value) in &headers {
            if skip_header(name.as_str()) || (target.remote && name == "authorization") {
                continue;
            }
            forwarded = forwarded.header(name, value);
        }
        if let Some(host) = headers.get("host").and_then(|value| value.to_str().ok()) {
            forwarded = forwarded
                .header("x-forwarded-host", host)
                .header("x-forwarded-proto", "http");
        }
        if target.remote {
            match remote_authorization(&route) {
                Ok(Some(token)) => {
                    forwarded = forwarded.header("authorization", token);
                }
                Ok(None) => {}
                Err(error) => {
                    last_error = Some(error);
                    continue;
                }
            }
        }

        match forwarded.body(body.clone()).send().await {
            Ok(upstream) => return relay(upstream).await,
            // Only retry when no connection was established. Retrying an
            // ambiguous timeout or a non-idempotent POST could duplicate work.
            Err(error) if error.is_connect() => {
                eprintln!(
                    "mycelium-gateway: {} candidate {} connect failed: {error}",
                    route.name, target.base
                );
                last_error = Some(error.to_string());
            }
            Err(error) => {
                eprintln!(
                    "mycelium-gateway: {} candidate {} failed: {error}",
                    route.name, target.base
                );
                return text(StatusCode::BAD_GATEWAY, "upstream unavailable");
            }
        }
    }

    if last_error.is_some() {
        text(StatusCode::BAD_GATEWAY, "upstream unavailable")
    } else {
        text(StatusCode::SERVICE_UNAVAILABLE, "no backend for route")
    }
}

fn targets_for(route: &Route, services: &ServiceIndex) -> Vec<Target> {
    let mut targets = Vec::new();
    let mut seen = BTreeSet::new();
    if let Some(upstream) = &route.upstream {
        if let Ok(base) = reqwest::Url::parse(upstream) {
            if seen.insert(base.to_string()) {
                targets.push(Target {
                    base,
                    remote: false,
                });
            }
        }
    }
    if let Some(kind) = &route.service_kind {
        for candidate in services.candidates(kind) {
            if seen.insert(candidate.url.to_string()) {
                targets.push(Target {
                    base: candidate.url.clone(),
                    remote: !candidate.local,
                });
            }
        }
    }
    targets
}

fn remote_authorization(route: &Route) -> Result<Option<String>, String> {
    let Some(name) = route.remote_token_env.as_deref() else {
        return Ok(None);
    };
    let token = std::env::var(name).map_err(|_| format!("remote_token_env {name} is not set"))?;
    let token = token.trim();
    if token.is_empty() {
        return Err(format!("remote_token_env {name} is empty"));
    }
    Ok(Some(format!("Bearer {token}")))
}

async fn relay(upstream: reqwest::Response) -> Response<Body> {
    let status = upstream.status();
    let headers = upstream.headers().clone();
    // Stream the response instead of buffering it. AI clients depend on SSE
    // arriving token by token, and large downloads should not sit in memory.
    let stream = upstream
        .bytes_stream()
        .map(|chunk| chunk.map_err(|error| Error::other(error.to_string())));
    let mut response = Response::builder().status(status);
    for (name, value) in &headers {
        if should_copy_response_header(name.as_str()) {
            response = response.header(name, value);
        }
    }
    response
        .body(Body::from_stream(stream))
        .unwrap_or_else(|_| text(StatusCode::INTERNAL_SERVER_ERROR, "invalid response"))
}

fn text(status: StatusCode, message: &'static str) -> Response<Body> {
    let mut response = Response::new(Body::from(message));
    *response.status_mut() = status;
    response
}

fn upstream_url(upstream: &reqwest::Url, uri: &Uri) -> Option<reqwest::Url> {
    let mut url = upstream.clone();
    let base = url.path().trim_end_matches('/');
    let path = format!("{base}{}", uri.path());
    url.set_path(&path);
    url.set_query(uri.query());
    Some(url)
}

fn should_copy_response_header(name: &str) -> bool {
    !matches!(
        name.to_lowercase().as_str(),
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailers"
            | "transfer-encoding"
            | "upgrade"
    )
}

fn skip_header(name: &str) -> bool {
    matches!(
        name.to_lowercase().as_str(),
        "host"
            | "connection"
            | "content-length"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailers"
            | "transfer-encoding"
            | "upgrade"
    )
}

fn authorized(request: &Request<Body>, expected: Option<&str>) -> bool {
    let Some(expected) = expected else {
        return true;
    };
    let Some(header) = request.headers().get("authorization") else {
        return false;
    };
    let Ok(value) = header.to_str() else {
        return false;
    };
    let token = value
        .strip_prefix("Bearer ")
        .or_else(|| value.strip_prefix("bearer "))
        .map(str::trim);
    token == Some(expected)
}

fn mtime(path: &Path) -> Option<std::time::SystemTime> {
    std::fs::metadata(path).ok()?.modified().ok()
}

fn default_config() -> GatewayConfig {
    GatewayConfig {
        routes: default_routes(),
        default_route: Some("default".into()),
        ..GatewayConfig::default()
    }
}

fn default_routes() -> Vec<Route> {
    vec![Route {
        name: "default".into(),
        hosts: vec!["*".into()],
        upstream: Some("http://127.0.0.1:4000".into()),
        service_kind: None,
        remote_token_env: None,
        priority: 0,
    }]
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn uri(value: &str) -> Uri {
        value.parse().unwrap()
    }

    #[test]
    fn joins_base_paths_without_losing_the_request_path() {
        let base = reqwest::Url::parse("http://127.0.0.1:4000").unwrap();
        assert_eq!(
            upstream_url(&base, &uri("/v1/models?scope=all"))
                .unwrap()
                .as_str(),
            "http://127.0.0.1:4000/v1/models?scope=all"
        );
        let base = reqwest::Url::parse("http://127.0.0.1:4000/api/").unwrap();
        assert_eq!(
            upstream_url(&base, &uri("/v1/models")).unwrap().as_str(),
            "http://127.0.0.1:4000/api/v1/models"
        );
    }

    #[test]
    fn strips_hop_by_hop_headers() {
        assert!(skip_header("Connection"));
        assert!(!skip_header("Authorization"));
        assert!(should_copy_response_header("Content-Type"));
        assert!(!should_copy_response_header("Transfer-Encoding"));
    }
}
