use axum::http::StatusCode;
use axum::routing::get;
use axum::{Json, Router};
use mycelium_gateway::server;
use reqwest::Client;
use serde_json::json;
use std::{fs, time::Duration};
use tokio::net::TcpListener;
use tokio::time::sleep;

fn temp_path(label: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!(
        "mycelium-gateway-{label}-{}.json",
        uuid::Uuid::new_v4()
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

    let gateway_addr = "127.0.0.1:0".parse::<std::net::SocketAddr>()?;
    let gateway_listener = TcpListener::bind(gateway_addr).await?;
    let gateway_port = gateway_listener.local_addr()?.port();
    drop(gateway_listener);
    let gateway_addr: std::net::SocketAddr = format!("127.0.0.1:{gateway_port}").parse()?;

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

    let gateway = tokio::spawn(server::run(
        gateway_addr,
        Some(route_path.clone()),
        Some(token.to_owned()),
        0,
    ));

    let client = Client::new();
    assert!(
        wait_health(&gateway_addr, &client).await,
        "gateway did not become healthy"
    );

    let denied = client
        .get(format!("http://127.0.0.1:{gateway_port}/hello"))
        .header("host", "ai.myc")
        .send()
        .await?;
    assert_eq!(denied.status(), StatusCode::UNAUTHORIZED);

    let allowed = client
        .get(format!("http://127.0.0.1:{gateway_port}/hello"))
        .header("host", "ai.myc")
        .header("authorization", format!("Bearer {token}"))
        .send()
        .await?;
    assert_eq!(allowed.status(), StatusCode::OK);
    let backend: serde_json::Value = allowed.json().await?;
    assert_eq!(backend["backend"], json!("ai"));

    let missing = client
        .get(format!("http://127.0.0.1:{gateway_port}/hello"))
        .header("host", "no-route.myc")
        .header("authorization", format!("Bearer {token}"))
        .send()
        .await?;
    assert_eq!(missing.status(), StatusCode::NOT_FOUND);

    let bad = client
        .get(format!("http://127.0.0.1:{gateway_port}/hello"))
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

    let addr = "127.0.0.1:0".parse::<std::net::SocketAddr>()?;
    let listener = TcpListener::bind(addr).await?;
    let port = listener.local_addr()?.port();
    drop(listener);
    let addr = format!("127.0.0.1:{port}").parse()?;

    let gateway = tokio::spawn(server::run(addr, Some(route_path.clone()), None, 0));
    let client = Client::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    let health = loop {
        if tokio::time::Instant::now() > deadline {
            gateway.abort();
            return Err("gateway did not become healthy".into());
        }
        if let Ok(response) = client
            .get(format!("http://127.0.0.1:{port}/healthz"))
            .send()
            .await
        {
            if response.status().is_success() {
                break response.json::<serde_json::Value>().await?;
            }
        }
        sleep(Duration::from_millis(50)).await;
    };

    assert_eq!(health["ok"], serde_json::json!(true));
    assert_eq!(health["routes"], serde_json::json!(1));
    assert_eq!(health["auth_required"], serde_json::json!(false));

    gateway.abort();
    let _ = fs::remove_file(route_path);
    Ok(())
}
