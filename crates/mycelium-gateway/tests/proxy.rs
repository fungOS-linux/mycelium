use axum::body::Bytes;
use axum::http::StatusCode;
use axum::routing::get;
use axum::{Json, Router};
use futures_util::StreamExt;
use mycelium_gateway::server;
use reqwest::Client;
use serde_json::json;
use std::{fs, time::Duration};
use tokio::net::TcpListener;
use tokio::time::sleep;

fn temp_path(label: &str) -> std::path::PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let id = NEXT.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "mycelium-gateway-{label}-{}-{id}.json",
        std::process::id()
    ))
}

async fn wait_health(gateway: &std::net::SocketAddr, client: &Client) -> bool {
    for _ in 0..50 {
        if let Ok(response) = client
            .get(format!("http://127.0.0.1:{}/healthz", gateway.port()))
            .send()
            .await
        {
            if response.status().is_success() {
                return true;
            }
        }
        sleep(Duration::from_millis(50)).await;
    }
    false
}

async fn start_gateway(
    route_path: std::path::PathBuf,
    token_path: Option<std::path::PathBuf>,
) -> Result<(std::net::SocketAddr, tokio::task::JoinHandle<()>), Box<dyn std::error::Error>> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    drop(listener);
    let handle = tokio::spawn(async move {
        if let Err(error) = server::run(address, Some(route_path), token_path, 0).await {
            panic!("gateway exited: {error}");
        }
    });
    Ok((address, handle))
}

#[tokio::test]
async fn routes_by_host_and_requires_auth() -> Result<(), Box<dyn std::error::Error>> {
    let upstream = TcpListener::bind("127.0.0.1:0").await?;
    let upstream_addr = upstream.local_addr()?;
    let upstream_handle = tokio::spawn(async move {
        axum::serve(
            upstream,
            Router::new().route("/hello", get(|| async { Json(json!({"backend": "ai"})) })),
        )
        .await
        .expect("upstream serve should succeed");
    });

    let token_path = temp_path("token");
    let token = "top-secret";
    fs::write(&token_path, token)?;

    let route_path = temp_path("routes");
    fs::write(
        &route_path,
        format!(
            r#"{{
              "routes": [
                {{
                  "name": "ai",
                  "hosts": ["ai.myc", "api.myc"],
                  "upstream": "http://127.0.0.1:{}",
                  "priority": 10
                }}
              ]
            }}"#,
            upstream_addr.port()
        ),
    )?;

    let (gateway_addr, gateway) =
        start_gateway(route_path.clone(), Some(token_path.clone())).await?;

    let client = Client::new();
    assert!(
        wait_health(&gateway_addr, &client).await,
        "gateway did not become healthy"
    );

    let denied = client
        .get(format!("http://127.0.0.1:{}/hello", gateway_addr.port()))
        .header("host", "ai.myc")
        .send()
        .await?;
    assert_eq!(denied.status(), StatusCode::UNAUTHORIZED);

    let allowed = client
        .get(format!("http://127.0.0.1:{}/hello", gateway_addr.port()))
        .header("host", "ai.myc")
        .header("authorization", format!("Bearer {token}"))
        .send()
        .await?;
    assert_eq!(allowed.status(), StatusCode::OK);
    let backend: serde_json::Value = allowed.json().await?;
    assert_eq!(backend["backend"], json!("ai"));

    let missing = client
        .get(format!("http://127.0.0.1:{}/hello", gateway_addr.port()))
        .header("host", "no-route.myc")
        .header("authorization", format!("Bearer {token}"))
        .send()
        .await?;
    assert_eq!(missing.status(), StatusCode::NOT_FOUND);

    let bad = client
        .get(format!("http://127.0.0.1:{}/hello", gateway_addr.port()))
        .header("host", "ai.myc")
        .header("authorization", "Bearer wrong")
        .send()
        .await?;
    assert_eq!(bad.status(), StatusCode::UNAUTHORIZED);

    gateway.abort();
    upstream_handle.abort();
    let _ = fs::remove_file(token_path);
    let _ = fs::remove_file(route_path);
    Ok(())
}

#[tokio::test]
async fn health_reports_routes_and_auth() -> Result<(), Box<dyn std::error::Error>> {
    let route_path = temp_path("health");
    fs::write(
        &route_path,
        r#"{
          "routes": [
            {
              "name": "default",
              "hosts": ["*"],
              "upstream": "http://127.0.0.1:4000",
              "priority": 0
            }
          ]
        }"#,
    )?;

    let (addr, gateway) = start_gateway(route_path.clone(), None).await?;
    let client = Client::new();
    let health = loop {
        if let Ok(response) = client
            .get(format!("http://127.0.0.1:{}/healthz", addr.port()))
            .send()
            .await
        {
            if response.status().is_success() {
                break response.json::<serde_json::Value>().await?;
            }
        }
        sleep(Duration::from_millis(50)).await;
    };

    assert_eq!(health["ok"], json!(true));
    assert_eq!(health["routes"], json!(1));
    assert_eq!(health["auth_required"], json!(false));

    gateway.abort();
    let _ = fs::remove_file(route_path);
    Ok(())
}

#[tokio::test]
async fn refresh_keeps_previous_routes_on_bad_edit() -> Result<(), Box<dyn std::error::Error>> {
    let upstream = TcpListener::bind("127.0.0.1:0").await?;
    let upstream_addr = upstream.local_addr()?;
    let upstream_handle = tokio::spawn(async move {
        axum::serve(
            upstream,
            Router::new().route("/hello", get(|| async { Json(json!({"ok": true})) })),
        )
        .await
        .expect("upstream serve should succeed");
    });

    let route_path = temp_path("reload");
    fs::write(
        &route_path,
        format!(
            r#"{{"routes": [{{"name": "ai", "hosts": ["ai.myc"],
                "upstream": "http://127.0.0.1:{}"}}]}}"#,
            upstream_addr.port()
        ),
    )?;
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    drop(listener);
    let gateway = tokio::spawn(server::run(addr, Some(route_path.clone()), None, 1));

    let client = Client::new();
    assert!(wait_health(&addr, &client).await);

    sleep(Duration::from_millis(1100)).await;
    fs::write(&route_path, "not json")?;
    sleep(Duration::from_millis(1600)).await;

    let response = client
        .get(format!("http://127.0.0.1:{}/hello", addr.port()))
        .header("host", "ai.myc")
        .send()
        .await?;
    assert_eq!(response.status(), StatusCode::OK);

    gateway.abort();
    upstream_handle.abort();
    let _ = fs::remove_file(route_path);
    Ok(())
}

#[tokio::test]
async fn streams_upstream_chunks_without_buffering() -> Result<(), Box<dyn std::error::Error>> {
    let upstream = TcpListener::bind("127.0.0.1:0").await?;
    let upstream_addr = upstream.local_addr()?;
    let upstream_handle = tokio::spawn(async move {
        let app = Router::new().route(
            "/stream",
            get(|| async {
                let chunks = futures_util::stream::iter(vec![
                    Ok::<_, std::io::Error>(Bytes::from("first")),
                    Ok(Bytes::from("second")),
                ])
                .then(|chunk| async move {
                    if !chunk.as_ref().is_ok_and(|value| value == "first") {
                        sleep(Duration::from_millis(500)).await;
                    }
                    chunk
                });
                axum::body::Body::from_stream(chunks)
            }),
        );
        axum::serve(upstream, app).await.expect("upstream serve");
    });

    let route_path = temp_path("stream");
    fs::write(
        &route_path,
        format!(
            r#"{{"routes": [{{"name": "ai", "hosts": ["ai.myc"],
                "upstream": "http://127.0.0.1:{}"}}]}}"#,
            upstream_addr.port()
        ),
    )?;
    let (addr, gateway) = start_gateway(route_path.clone(), None).await?;
    let client = Client::new();
    assert!(wait_health(&addr, &client).await);

    let mut response = client
        .get(format!("http://127.0.0.1:{}/stream", addr.port()))
        .header("host", "ai.myc")
        .send()
        .await?;
    let first = tokio::time::timeout(Duration::from_millis(300), response.chunk()).await??;
    assert_eq!(first.as_deref(), Some(&b"first"[..]));

    gateway.abort();
    upstream_handle.abort();
    let _ = fs::remove_file(route_path);
    Ok(())
}

#[tokio::test]
async fn refuses_to_start_with_missing_inputs() {
    let address = "127.0.0.1:0".parse().unwrap();
    let missing_token = std::env::temp_dir().join("mycelium-gateway-missing-token");
    let result = server::run(address, None, Some(missing_token), 0).await;
    assert!(result.is_err());

    let missing_config = std::env::temp_dir().join("mycelium-gateway-missing-routes");
    let result = server::run(address, Some(missing_config), None, 0).await;
    assert!(result.is_err());
}
