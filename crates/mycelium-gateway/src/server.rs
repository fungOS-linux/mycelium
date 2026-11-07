use crate::config::GatewayConfig;
use crate::route::RouteTable;
use axum::body::Body;
use axum::extract::State;
use axum::http::{Request, Response, StatusCode, Uri};
use axum::routing::get;
use axum::Router;
use serde_json::json;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;

#[derive(Clone)]
pub(crate) struct GatewayState {
    client: reqwest::Client,
    table: Arc<std::sync::RwLock<RouteTable>>,
    auth_token: Option<Arc<str>>,
    max_body_bytes: usize,
}

pub async fn run(
    listen: SocketAddr,
    config_path: Option<PathBuf>,
    auth_token: Option<String>,
    reload_secs: u64,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let table = Arc::new(std::sync::RwLock::new(RouteTable::new(
        default_routes(),
        None,
    )));
    let state = GatewayState {
        client: reqwest::Client::builder()
            .timeout(Duration::from_secs(300))
            .pool_max_idle_per_host(64)
            .build()?,
        table: table.clone(),
        auth_token: auth_token.map(Arc::from),
        max_body_bytes: 32 * 1024 * 1024,
    };

    if config_path.is_some() {
        match GatewayConfig::load(config_path.as_ref().unwrap()) {
            Ok(config) => {
                *table.write().unwrap() =
                    RouteTable::new(config.routes, config.default_route);
            }
            Err(error) => eprintln!("mycelium-gateway: initial config ignored: {error}"),
        }
    }

    if let Some(path) = config_path.clone() {
        if reload_secs > 0 {
            tokio::spawn(async move {
                let mut last_mtime = mtime(&path);
                loop {
                    tokio::time::sleep(Duration::from_secs(reload_secs)).await;
                    let current = mtime(&path);
                    if current == last_mtime {
                        continue;
                    }
                    match GatewayConfig::load(&path) {
                        Ok(config) => {
                            *table.write().unwrap() = RouteTable::new(config.routes, config.default_route);
                            last_mtime = current;
                        }
                        Err(error) => {
                            eprintln!("mycelium-gateway: config reload failed: {error}");
                        }
                    }
                }
            });
        }
    }

    let app = routes(state);

    let listener = TcpListener::bind(listen).await?;

    eprintln!("mycelium-gateway: listening on {listen}; routing by Host");
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    Ok(())
}

fn routes(state: GatewayState) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .fallback(proxy)
        .with_state(state)
}

async fn healthz(State(state): State<GatewayState>) -> impl axum::response::IntoResponse {
    let table = state.table.read().unwrap();
    axum::Json(json!({
        "ok": true,
        "routes": table.routes().len(),
        "auth_required": state.auth_token.is_some()
    }))
}

async fn proxy(State(state): State<GatewayState>, request: Request<Body>) -> Result<Response<Body>, StatusCode> {
    if !authorized(&request, state.auth_token.as_deref()) {
        let mut response = Response::new(Body::empty());
        *response.status_mut() = StatusCode::UNAUTHORIZED;
        return Err(StatusCode::UNAUTHORIZED);
    }

    let host = request
        .headers()
        .get("host")
        .and_then(|value| value.to_str().ok())
        .map(crate::route::normalize_host)
        .unwrap_or_default();

    let route = {
        let table = state.table.read().unwrap();
        table.select(&host)
    };

    let Some(route) = route else {
        let mut response = Response::new(Body::from("no route"));
        *response.status_mut() = StatusCode::NOT_FOUND;
        return Err(StatusCode::NOT_FOUND);
    };

    let target = state.client.request(
        request.method().clone(),
        build_upstream_url(&route.upstream, request.uri())?,
    );

    let mut forwarded = target;
    for (name, value) in request.headers() {
        if skip_header(name.as_str()) {
            continue;
        }
        forwarded = forwarded.header(name.clone(), value.clone());
    }
    if let Some(forwarded_host) = request
        .headers()
        .get("host")
        .and_then(|value| value.to_str().ok())
    {
        forwarded = forwarded.header("x-forwarded-host", forwarded_host);
    }
    forwarded = forwarded.header("x-forwarded-proto", "https");

    let body = axum::body::to_bytes(request.into_body(), state.max_body_bytes)
        .await
        .map_err(|_| StatusCode::PAYLOAD_TOO_LARGE)?;
    forwarded = forwarded.body(body);

    let upstream = forwarded.send().await.map_err(|_| StatusCode::BAD_GATEWAY)?;
    let status = upstream.status();
    let mut response = Response::builder().status(status);
    for (name, value) in upstream.headers() {
        if should_copy_response_header(name.as_str()) {
            response = response.header(name.clone(), value.clone());
        }
    }
    let bytes = upstream
        .bytes()
        .await
        .map_err(|_| StatusCode::BAD_GATEWAY)?;
    response
        .body(Body::from(bytes))
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}

fn build_upstream_url(
    upstream: &str,
    uri: &Uri,
) -> Result<reqwest::Url, StatusCode> {
    let mut url = reqwest::Url::parse(upstream).map_err(|_| StatusCode::BAD_GATEWAY)?;
    let path = uri.path();
    if !path.is_empty() && path != "/" {
        let joined = url.join(path).map_err(|_| StatusCode::BAD_GATEWAY)?;
        url = joined;
    }
    if let Some(query) = uri.query() {
        url.set_query(Some(query));
    }
    Ok(url)
}

fn should_copy_response_header(name: &str) -> bool {
    !matches!(
        name.to_lowercase().as_str(),
        "connection" | "keep-alive" | "proxy-authenticate" | "proxy-authorization" | "te" | "trailers" | "transfer-encoding" | "upgrade"
    )
}

fn skip_header(name: &str) -> bool {
    matches!(
        name.to_lowercase().as_str(),
        "host" | "connection" | "content-length" | "keep-alive" | "proxy-authenticate" | "proxy-authorization" | "te" | "trailers" | "transfer-encoding" | "upgrade"
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
    let Some(token) = value
        .strip_prefix("Bearer ")
        .map(str::trim)
        .or_else(|| value.strip_prefix("bearer ").map(str::trim))
    else {
        return false;
    };
    token == expected
}

fn mtime(path: &std::path::PathBuf) -> Option<std::time::SystemTime> {
    std::fs::metadata(path).ok()?.modified().ok()
}


fn default_routes() -> Vec<crate::config::Route> {
    vec![crate::config::Route {
        name: "default".into(),
        hosts: vec!["*".into()],
        upstream: "http://127.0.0.1:4000".into(),
        priority: 0,
    }]
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
}
