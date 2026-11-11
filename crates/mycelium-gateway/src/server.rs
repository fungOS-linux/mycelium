use crate::config::{GatewayConfig, MeteringConfig, Route};
use crate::discovery::{is_loopback, ServiceIndex};
use crate::route::RouteTable;
use crate::usage::{self, Metering, StreamUsage, UsageStore};
use axum::body::{Body, Bytes};
use axum::extract::State;
use axum::http::{Request, Response, StatusCode, Uri};
use axum::routing::get;
use axum::Router;
use futures_util::{Stream, StreamExt};
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::service::TowerToHyperService;
use mycelium_peer_protocol::gateway_usage::GatewayUsageSnapshot;
use serde_json::json;
use std::collections::BTreeSet;
use std::fs::File;
use std::io::{BufReader, Error, ErrorKind};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

const MAX_BODY_BYTES: usize = 32 * 1024 * 1024;
/// A successful completion body larger than this is not buffered for metering;
/// it is relayed as a stream and counted as unmetered.
const MAX_METERED_BODY_BYTES: usize = 32 * 1024 * 1024;
const USAGE_PERSIST_SECS: u64 = 15;

#[derive(Clone)]
struct GatewayState {
    client: reqwest::Client,
    table: Arc<std::sync::RwLock<RouteTable>>,
    services: Arc<std::sync::RwLock<ServiceIndex>>,
    usage: Arc<UsageStore>,
    metering: MeteringConfig,
    auth_token: Option<Arc<str>>,
    forwarded_proto: &'static str,
}

#[derive(Clone, Debug)]
struct Target {
    base: reqwest::Url,
    /// Not loopback: the address belongs to another machine.
    remote: bool,
    /// Written down in the route table rather than discovered from the mesh.
    configured: bool,
}

/// Everything needed to attribute one response once it finishes.
struct RelayMeter {
    store: Arc<UsageStore>,
    route: String,
    model: Option<String>,
    metering: Metering,
    started: Instant,
}

pub async fn run(
    listen: SocketAddr,
    config_path: Option<PathBuf>,
    token_file: Option<PathBuf>,
    reload_secs: u64,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    run_with_tls(listen, config_path, token_file, reload_secs, None).await
}

pub async fn run_with_tls(
    listen: SocketAddr,
    config_path: Option<PathBuf>,
    token_file: Option<PathBuf>,
    reload_secs: u64,
    tls: Option<(PathBuf, PathBuf)>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    run_with_options(
        vec![listen],
        config_path,
        token_file,
        reload_secs,
        tls,
        None,
    )
    .await
}

/// `usage_path` is where token counters are persisted for `myceliumd` to
/// gossip. Without it the gateway still meters and serves `/.mycelium/usage`,
/// but nothing survives a restart and nothing leaves the machine.
pub async fn run_with_options(
    listeners: Vec<SocketAddr>,
    config_path: Option<PathBuf>,
    token_file: Option<PathBuf>,
    reload_secs: u64,
    tls: Option<(PathBuf, PathBuf)>,
    usage_path: Option<PathBuf>,
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

    let usage = Arc::new(UsageStore::open(usage_path.clone()));
    if let Some(path) = usage_path.as_deref() {
        spawn_usage_persist(usage.clone());
        eprintln!(
            "mycelium-gateway: recording token usage in {}",
            path.display()
        );
    }

    let forwarded_proto = if tls.is_some() { "https" } else { "http" };
    let state = GatewayState {
        client: reqwest::Client::builder()
            .timeout(Duration::from_secs(300))
            .pool_max_idle_per_host(64)
            .build()?,
        table: table.clone(),
        services,
        usage: usage.clone(),
        metering: config.metering.clone(),
        auth_token: auth_token.map(Arc::from),
        forwarded_proto,
    };

    if let (Some(path), true) = (config_path, reload_secs > 0) {
        spawn_reload(path, table, initial_mtime, reload_secs);
    }

    // Bind every address before serving any of them. A gateway that came up on
    // one of several configured addresses would answer its own health check and
    // serve half the mesh, which is the failure this whole change exists to
    // remove.
    let mut bound = Vec::with_capacity(listeners.len());
    for address in &listeners {
        bound.push((*address, TcpListener::bind(address).await?));
    }
    let app = routes(state);
    let mut tasks = tokio::task::JoinSet::new();
    for (address, listener) in bound {
        let app = app.clone();
        let tls = tls.clone();
        tasks.spawn(async move {
            match tls {
                Some((cert, key)) => {
                    let config = tls_config(&cert, &key).map_err(|error| error.to_string())?;
                    eprintln!("mycelium-gateway: listening on https://{address}; routing by Host");
                    serve_tls(listener, app, config)
                        .await
                        .map_err(|error| error.to_string())
                }
                None => {
                    eprintln!("mycelium-gateway: listening on http://{address}; routing by Host");
                    axum::serve(listener, app)
                        .with_graceful_shutdown(shutdown_signal())
                        .await
                        .map_err(|error| error.to_string())
                }
            }
        });
    }
    while let Some(joined) = tasks.join_next().await {
        match joined {
            Ok(Ok(())) => {}
            Ok(Err(error)) => return Err(error.into()),
            Err(error) => return Err(format!("listener task failed: {error}").into()),
        }
    }
    // Final write so a restart continues from the counters it stopped at.
    if let Err(error) = usage.persist() {
        eprintln!("mycelium-gateway: writing token usage failed: {error}");
    }
    Ok(())
}

fn spawn_usage_persist(usage: Arc<UsageStore>) {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(USAGE_PERSIST_SECS)).await;
            let writer = usage.clone();
            match tokio::task::spawn_blocking(move || writer.persist()).await {
                Ok(Ok(_)) => {}
                Ok(Err(error)) => {
                    eprintln!("mycelium-gateway: writing token usage failed: {error}")
                }
                Err(error) => eprintln!("mycelium-gateway: token usage task failed: {error}"),
            }
        }
    });
}

fn tls_config(
    cert_path: &Path,
    key_path: &Path,
) -> Result<Arc<rustls::ServerConfig>, Box<dyn std::error::Error + Send + Sync>> {
    let certificates = rustls_pemfile::certs(&mut BufReader::new(File::open(cert_path)?))
        .collect::<Result<Vec<_>, _>>()?;
    if certificates.is_empty() {
        return Err(format!("{} contains no certificates", cert_path.display()).into());
    }
    let key = rustls_pemfile::private_key(&mut BufReader::new(File::open(key_path)?))?
        .ok_or_else(|| format!("{} contains no private key", key_path.display()))?;
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let mut config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_single_cert(certificates, key)?;
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}

async fn serve_tls(
    listener: TcpListener,
    app: Router,
    config: Arc<rustls::ServerConfig>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let acceptor = TlsAcceptor::from(config);
    let shutdown = shutdown_signal();
    tokio::pin!(shutdown);
    loop {
        tokio::select! {
            _ = &mut shutdown => break,
            accepted = listener.accept() => {
                let (stream, peer) = accepted?;
                let acceptor = acceptor.clone();
                let service = TowerToHyperService::new(app.clone());
                tokio::spawn(async move {
                    let tls = match tokio::time::timeout(Duration::from_secs(10), acceptor.accept(stream)).await {
                        Ok(Ok(tls)) => tls,
                        Ok(Err(error)) => {
                            eprintln!("mycelium-gateway: TLS handshake from {peer} failed: {error}");
                            return;
                        }
                        Err(_) => {
                            eprintln!("mycelium-gateway: TLS handshake from {peer} timed out");
                            return;
                        }
                    };
                    let io = TokioIo::new(tls);
                    if let Err(error) = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new())
                        .serve_connection_with_upgrades(io, service)
                        .await
                    {
                        eprintln!("mycelium-gateway: HTTPS connection from {peer} failed: {error}");
                    }
                });
            }
        }
    }
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
        .route("/.mycelium/usage", get(usage_report))
        .route("/.mycelium/metrics", get(metrics_report))
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
        "auth_required": state.auth_token.is_some(),
        "metering": {"stream_usage": state.metering.stream_usage},
        "tls": state.forwarded_proto == "https"
    }))
}

/// Token counters for this machine, in the shape `mycelium gateway usage`
/// prints and `myceliumd` gossips.
async fn usage_report(State(state): State<GatewayState>) -> axum::Json<GatewayUsageSnapshot> {
    axum::Json(state.usage.snapshot())
}

async fn metrics_report(State(state): State<GatewayState>) -> Response<Body> {
    let snapshot = state.usage.snapshot();
    Response::builder()
        .header("content-type", "text/plain; version=0.0.4; charset=utf-8")
        .body(Body::from(prometheus(&snapshot)))
        .unwrap_or_else(|_| text(StatusCode::INTERNAL_SERVER_ERROR, "invalid response"))
}

fn prometheus(snapshot: &GatewayUsageSnapshot) -> String {
    let totals = &snapshot.totals;
    let mut body = String::new();
    for (name, kind, value) in [
        ("requests_total", "counter", totals.requests.to_string()),
        (
            "metered_requests_total",
            "counter",
            totals.metered_requests.to_string(),
        ),
        (
            "prompt_tokens_total",
            "counter",
            totals.prompt_tokens.to_string(),
        ),
        (
            "completion_tokens_total",
            "counter",
            totals.completion_tokens.to_string(),
        ),
        (
            "cached_tokens_total",
            "counter",
            totals.cached_tokens.to_string(),
        ),
        (
            "tokens_per_second",
            "gauge",
            format!(
                "{:.3}",
                snapshot.window.tokens_per_second(snapshot.window_seconds)
            ),
        ),
        (
            "generation_tokens_per_second",
            "gauge",
            format!("{:.3}", snapshot.window.generation_tokens_per_second()),
        ),
    ] {
        let full = format!("mycelium_gateway_ai_{name}");
        body.push_str(&format!("# TYPE {full} {kind}\n{full} {value}\n"));
    }
    for (label, counts) in [("route", &snapshot.routes), ("model", &snapshot.models)] {
        let full = format!("mycelium_gateway_ai_{label}_completion_tokens_total");
        body.push_str(&format!("# TYPE {full} counter\n"));
        for (value, counts) in counts {
            body.push_str(&format!(
                "{full}{{{label}=\"{}\"}} {}\n",
                escape_label(value),
                counts.completion_tokens
            ));
        }
    }
    body
}

/// Prometheus label values are double-quoted; a model name comes from the
/// client, so it must not be able to break the exposition format.
fn escape_label(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

async fn proxy(State(state): State<GatewayState>, request: Request<Body>) -> Response<Body> {
    if !authorized(&request, state.auth_token.as_deref()) {
        return text(StatusCode::UNAUTHORIZED, "unauthorized");
    }

    let host = request_host(&request);
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
    let caller_credential = headers
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let body = match axum::body::to_bytes(request.into_body(), MAX_BODY_BYTES).await {
        Ok(body) => body,
        Err(_) => return text(StatusCode::PAYLOAD_TOO_LARGE, "request body too large"),
    };
    let metering = usage::classify(uri.path(), &body);

    let mut last_error = None;
    for target in targets {
        let Some(url) = upstream_url(&target.base, &uri) else {
            last_error = Some("invalid upstream URL".to_owned());
            continue;
        };
        let mut payload = body.clone();
        if state.metering.stream_usage && matches!(metering, Metering::Streamed { .. }) {
            if let Some(rewritten) = usage::with_stream_usage(&body) {
                payload = Bytes::from(rewritten);
            }
        }
        let mut forwarded = state.client.request(method.clone(), url);
        for (name, value) in &headers {
            // Authorization is decided per target: a credential minted for the
            // local gateway must not be replayed to an unknown peer.
            if skip_header(name.as_str()) || name == "authorization" {
                continue;
            }
            forwarded = forwarded.header(name, value);
        }
        forwarded = forwarded
            .header("x-forwarded-host", &host)
            .header("x-forwarded-proto", state.forwarded_proto);
        match target_authorization(&route, &target, caller_credential.as_deref()) {
            Ok(Some(credential)) => {
                forwarded = forwarded.header("authorization", credential);
            }
            Ok(None) => {}
            Err(error) => {
                eprintln!("mycelium-gateway: {}", error);
                last_error = Some(error);
                continue;
            }
        }

        let started = Instant::now();
        match forwarded.body(payload).send().await {
            Ok(upstream) => {
                let meter = RelayMeter {
                    store: state.usage.clone(),
                    route: route.name.clone(),
                    model: metering.model().map(str::to_owned),
                    metering: metering.clone(),
                    started,
                };
                return relay(upstream, meter).await;
            }
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

fn request_host(request: &Request<Body>) -> String {
    request
        .headers()
        .get("host")
        .and_then(|value| value.to_str().ok())
        .or_else(|| {
            request
                .uri()
                .authority()
                .map(|authority| authority.as_str())
        })
        .map(crate::route::normalize_host)
        .unwrap_or_default()
}

/// Candidate order is a single rule: this machine first, then its mesh, then
/// the remote fallbacks an operator configured (the public edge). Loopback is
/// the only signal the gateway needs to tell local from off-host, so an operator
/// does not have to keep a second ordering knob in sync with the addresses they
/// already wrote down.
fn targets_for(route: &Route, services: &ServiceIndex) -> Vec<Target> {
    let mut local = Vec::new();
    let mut mesh = Vec::new();
    let mut fallback = Vec::new();
    let mut seen = BTreeSet::new();
    let mut push = |base: reqwest::Url, configured: bool| {
        if !seen.insert(base.to_string()) {
            return;
        }
        let target = Target {
            remote: !is_loopback(&base),
            configured,
            base,
        };
        match (target.remote, configured) {
            (false, _) => local.push(target),
            (true, false) => mesh.push(target),
            (true, true) => fallback.push(target),
        }
    };
    for base in route.upstream_urls() {
        push(base, true);
    }
    if let Some(kind) = &route.service_kind {
        for candidate in services.candidates(kind) {
            push(candidate.url.clone(), false);
        }
    }
    local.extend(mesh);
    local.extend(fallback);
    local
}

/// The credential this target receives.
///
/// A configured upstream was chosen by the operator, so the caller's credential
/// may reach it. A discovered peer is somebody else's machine: it receives only
/// a credential the operator configured for remote use, never the caller's.
fn target_authorization(
    route: &Route,
    target: &Target,
    caller: Option<&str>,
) -> Result<Option<String>, String> {
    if target.remote {
        if let Some(credential) = remote_credential(route)? {
            return Ok(Some(credential));
        }
        if !target.configured {
            return Err(format!(
                "{} is a discovered peer but route `{}` has no remote_token_env or remote_token_file",
                target.base, route.name
            ));
        }
    }
    Ok(caller.map(str::to_owned))
}

fn remote_credential(route: &Route) -> Result<Option<String>, String> {
    let token = match (&route.remote_token_env, &route.remote_token_file) {
        (Some(name), _) => {
            std::env::var(name).map_err(|_| format!("remote_token_env {name} is not set"))?
        }
        (None, Some(path)) => std::fs::read_to_string(path)
            .map_err(|error| format!("remote_token_file {}: {error}", path.display()))?,
        (None, None) => return Ok(None),
    };
    let token = token.trim();
    if token.is_empty() {
        return Err("the configured remote credential is empty".into());
    }
    Ok(Some(format!("Bearer {token}")))
}

async fn relay(upstream: reqwest::Response, meter: RelayMeter) -> Response<Body> {
    let status = upstream.status();
    let headers = upstream.headers().clone();
    // Failures are not usage. A 4xx/5xx completion response is relayed without
    // touching the counters, so client mistakes do not inflate the fleet.
    let counting = status.is_success() && !matches!(meter.metering, Metering::Skip);
    if counting && matches!(meter.metering, Metering::Buffered { .. }) {
        return relay_buffered(upstream, status, headers, meter).await;
    }
    relay_streamed(
        upstream.bytes_stream(),
        status,
        headers,
        counting.then_some(meter),
    )
}

/// Non-streaming completion responses are small and carry `usage` in the body,
/// so they are buffered to read it. Anything unreasonably large is relayed as a
/// stream and counted as unmetered rather than held in memory.
async fn relay_buffered(
    upstream: reqwest::Response,
    status: StatusCode,
    headers: axum::http::HeaderMap,
    meter: RelayMeter,
) -> Response<Body> {
    let mut collected: Vec<u8> = Vec::new();
    let mut stream = upstream.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = match chunk {
            Ok(chunk) => chunk,
            Err(error) => {
                eprintln!(
                    "mycelium-gateway: {} response body failed: {error}",
                    meter.route
                );
                meter.store.record(
                    &meter.route,
                    meter.model.as_deref(),
                    None,
                    meter.started.elapsed(),
                );
                return text(StatusCode::BAD_GATEWAY, "upstream response failed");
            }
        };
        if collected.len() + chunk.len() > MAX_METERED_BODY_BYTES {
            meter.store.record(
                &meter.route,
                meter.model.as_deref(),
                None,
                meter.started.elapsed(),
            );
            let prefix = std::mem::take(&mut collected);
            let head = futures_util::stream::once(async move { Ok(Bytes::from(prefix)) });
            let tail = stream.map(|chunk| chunk.map_err(|error| Error::other(error.to_string())));
            return relay_streamed(head.chain(tail), status, headers, None);
        }
        collected.extend_from_slice(&chunk);
    }
    let usage = serde_json::from_slice::<serde_json::Value>(&collected)
        .ok()
        .as_ref()
        .and_then(usage::reported_usage);
    meter.store.record(
        &meter.route,
        meter.model.as_deref(),
        usage,
        meter.started.elapsed(),
    );
    let mut response = Response::builder().status(status);
    for (name, value) in &headers {
        if should_copy_response_header(name.as_str()) {
            response = response.header(name, value);
        }
    }
    response
        .body(Body::from(collected))
        .unwrap_or_else(|_| text(StatusCode::INTERNAL_SERVER_ERROR, "invalid response"))
}

fn relay_streamed<S, E>(
    stream: S,
    status: StatusCode,
    headers: axum::http::HeaderMap,
    meter: Option<RelayMeter>,
) -> Response<Body>
where
    S: Stream<Item = Result<Bytes, E>> + Send + 'static,
    E: std::fmt::Display + Send + 'static,
{
    // Stream the response instead of buffering it. AI clients depend on SSE
    // arriving token by token, and large downloads should not sit in memory.
    let inner: Pin<Box<dyn Stream<Item = Result<Bytes, Error>> + Send>> =
        Box::pin(stream.map(|chunk| chunk.map_err(|error| Error::other(error.to_string()))));
    let stream = MeteredStream {
        inner,
        meter,
        sse: StreamUsage::default(),
        finished: false,
    };
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

/// Pass-through stream that watches SSE bytes for a usage event. It never
/// delays a chunk and never alters one.
struct MeteredStream {
    inner: Pin<Box<dyn Stream<Item = Result<Bytes, Error>> + Send>>,
    meter: Option<RelayMeter>,
    sse: StreamUsage,
    finished: bool,
}

impl MeteredStream {
    fn finish(&mut self) {
        if self.finished {
            return;
        }
        self.finished = true;
        let Some(meter) = self.meter.take() else {
            return;
        };
        let usage = std::mem::take(&mut self.sse).finish();
        meter.store.record(
            &meter.route,
            meter.model.as_deref(),
            usage,
            meter.started.elapsed(),
        );
    }
}

impl Stream for MeteredStream {
    type Item = Result<Bytes, Error>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        match this.inner.as_mut().poll_next(cx) {
            Poll::Ready(Some(Ok(chunk))) => {
                this.sse.feed(&chunk);
                Poll::Ready(Some(Ok(chunk)))
            }
            Poll::Ready(Some(Err(error))) => {
                this.finish();
                Poll::Ready(Some(Err(error)))
            }
            Poll::Ready(None) => {
                this.finish();
                Poll::Ready(None)
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl Drop for MeteredStream {
    fn drop(&mut self) {
        // A client that disconnects mid-stream still consumed the tokens the
        // upstream produced. Record whatever the stream reported before it went
        // away; a cancelled stream without usage stays unmetered.
        self.finish();
    }
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
        upstreams: vec!["http://127.0.0.1:4000".into()],
        service_kind: None,
        remote_token_env: None,
        remote_token_file: None,
        priority: 0,
    }]
}

async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    {
        let mut terminate =
            match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
                Ok(signal) => signal,
                Err(error) => {
                    eprintln!("mycelium-gateway: cannot install a SIGTERM handler: {error}");
                    ctrl_c.await;
                    return;
                }
            };
        tokio::select! {
            _ = ctrl_c => {}
            _ = terminate.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        ctrl_c.await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::discovery::ServiceIndex;

    fn uri(value: &str) -> Uri {
        value.parse().unwrap()
    }

    fn route(upstreams: &[&str], kind: Option<&str>) -> Route {
        Route {
            name: "ai".into(),
            hosts: vec!["ai.myc".into()],
            upstreams: upstreams.iter().map(|url| (*url).into()).collect(),
            service_kind: kind.map(str::to_owned),
            remote_token_env: None,
            remote_token_file: None,
            priority: 0,
        }
    }

    fn catalog() -> serde_json::Value {
        json!({
            "observations": [
                {
                    "expires_at": 200,
                    "provenance": {"observer": "remote-node"},
                    "value": {
                        "kind": "ai",
                        "endpoints": ["http://10.0.0.5:8122"],
                        "attributes": {"node_id": "remote-node"}
                    }
                },
                {
                    "expires_at": 200,
                    "provenance": {"observer": "local-node"},
                    "value": {
                        "kind": "ai",
                        "endpoints": ["http://127.0.0.1:8122"],
                        "attributes": {"node_id": "local-node"}
                    }
                }
            ]
        })
    }

    #[test]
    fn candidates_run_local_then_mesh_then_public_edge() {
        let index = ServiceIndex::from_catalog("local-node", &catalog(), 150).unwrap();
        // Declared with the public edge first: loopback still wins.
        let targets = targets_for(
            &route(&["https://ai.fpl.dev", "http://127.0.0.1:4000"], Some("ai")),
            &index,
        );
        assert_eq!(
            targets
                .iter()
                .map(|target| target.base.to_string())
                .collect::<Vec<_>>(),
            vec![
                "http://127.0.0.1:4000/",
                "http://127.0.0.1:8122/",
                "http://10.0.0.5:8122/",
                "https://ai.fpl.dev/",
            ]
        );
        assert!(!targets[0].remote && targets[0].configured);
        assert!(!targets[1].remote && !targets[1].configured);
        assert!(targets[2].remote && !targets[2].configured);
        assert!(targets[3].remote && targets[3].configured);
    }

    #[test]
    fn a_discovered_peer_never_receives_the_callers_credential() {
        let route = route(&["https://ai.fpl.dev"], Some("ai"));
        let caller = Some("Bearer local-only");
        let target = |base: &str, remote: bool, configured: bool| Target {
            base: reqwest::Url::parse(base).unwrap(),
            remote,
            configured,
        };
        assert_eq!(
            target_authorization(
                &route,
                &target("http://127.0.0.1:4000", false, false),
                caller
            )
            .unwrap(),
            caller.map(str::to_owned)
        );
        // A configured public fallback was chosen by the operator, so the
        // caller's key reaches it when no separate remote credential exists.
        assert_eq!(
            target_authorization(&route, &target("https://ai.fpl.dev", true, true), caller)
                .unwrap(),
            caller.map(str::to_owned)
        );
        assert!(
            target_authorization(&route, &target("http://10.0.0.5:8122", true, false), caller)
                .is_err()
        );
    }

    #[test]
    fn a_remote_credential_replaces_the_callers_for_remote_targets_only() {
        let dir = std::env::temp_dir().join(format!("mycelium-credential-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("token");
        std::fs::write(&path, "cloud-key\n").unwrap();
        let mut route = route(&["http://127.0.0.1:4000", "https://ai.fpl.dev"], None);
        route.remote_token_file = Some(path.clone());
        let caller = Some("Bearer local-only");
        let remote = Target {
            base: reqwest::Url::parse("https://ai.fpl.dev").unwrap(),
            remote: true,
            configured: true,
        };
        let local = Target {
            base: reqwest::Url::parse("http://127.0.0.1:4000").unwrap(),
            remote: false,
            configured: true,
        };
        assert_eq!(
            target_authorization(&route, &remote, caller).unwrap(),
            Some("Bearer cloud-key".into())
        );
        assert_eq!(
            target_authorization(&route, &local, caller).unwrap(),
            caller.map(str::to_owned)
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn prometheus_labels_cannot_break_the_exposition_format() {
        let mut snapshot = GatewayUsageSnapshot {
            schema_version: 1,
            generated_at: 10,
            window_seconds: 60,
            ..GatewayUsageSnapshot::default()
        };
        snapshot
            .models
            .insert("evil\"} 1\n".into(), Default::default());
        let body = prometheus(&snapshot);
        assert!(body.contains(r#"model="evil\"} 1\n""#));
        assert!(!body.contains("\n 1\n"));
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
    fn host_falls_back_to_http2_authority() {
        let request = Request::builder()
            .uri("https://ai.myc/hello")
            .body(Body::empty())
            .unwrap();
        assert_eq!(request_host(&request), "ai.myc");
        let request = Request::builder()
            .uri("/hello")
            .header("host", "mcp.myc:443")
            .body(Body::empty())
            .unwrap();
        assert_eq!(request_host(&request), "mcp.myc");
    }

    #[test]
    fn strips_hop_by_hop_headers() {
        assert!(skip_header("Connection"));
        assert!(!skip_header("Authorization"));
        assert!(should_copy_response_header("Content-Type"));
        assert!(!should_copy_response_header("Transfer-Encoding"));
    }
}
