use axum::body::Bytes;
use axum::http::StatusCode;
use axum::routing::get;
use axum::{Json, Router};
use futures_util::StreamExt;
use mycelium_frontdoor::server;
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
        "mycelium-frontdoor-{label}-{}-{id}.json",
        std::process::id()
    ))
}

async fn wait_health(frontdoor: &std::net::SocketAddr, client: &Client) -> bool {
    for _ in 0..50 {
        if let Ok(response) = client
            .get(format!("http://127.0.0.1:{}/healthz", frontdoor.port()))
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

async fn start_frontdoor(
    route_path: std::path::PathBuf,
    token_path: Option<std::path::PathBuf>,
) -> Result<(std::net::SocketAddr, tokio::task::JoinHandle<()>), Box<dyn std::error::Error>> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    drop(listener);
    let handle = tokio::spawn(async move {
        if let Err(error) = server::run(address, Some(route_path), token_path, 0).await {
            panic!("frontdoor exited: {error}");
        }
    });
    Ok((address, handle))
}

async fn start_frontdoor_tls(
    route_path: std::path::PathBuf,
    cert_path: std::path::PathBuf,
    key_path: std::path::PathBuf,
) -> Result<(std::net::SocketAddr, tokio::task::JoinHandle<()>), Box<dyn std::error::Error>> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    drop(listener);
    let handle = tokio::spawn(async move {
        if let Err(error) = server::run_with_tls(
            address,
            Some(route_path),
            None,
            0,
            Some((cert_path, key_path)),
        )
        .await
        {
            panic!("frontdoor exited: {error}");
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

    let (frontdoor_addr, frontdoor) =
        start_frontdoor(route_path.clone(), Some(token_path.clone())).await?;

    let client = Client::new();
    assert!(
        wait_health(&frontdoor_addr, &client).await,
        "frontdoor did not become healthy"
    );

    let denied = client
        .get(format!("http://127.0.0.1:{}/hello", frontdoor_addr.port()))
        .header("host", "ai.myc")
        .send()
        .await?;
    assert_eq!(denied.status(), StatusCode::UNAUTHORIZED);

    let allowed = client
        .get(format!("http://127.0.0.1:{}/hello", frontdoor_addr.port()))
        .header("host", "ai.myc")
        .header("authorization", format!("Bearer {token}"))
        .send()
        .await?;
    assert_eq!(allowed.status(), StatusCode::OK);
    let backend: serde_json::Value = allowed.json().await?;
    assert_eq!(backend["backend"], json!("ai"));

    let missing = client
        .get(format!("http://127.0.0.1:{}/hello", frontdoor_addr.port()))
        .header("host", "no-route.myc")
        .header("authorization", format!("Bearer {token}"))
        .send()
        .await?;
    assert_eq!(missing.status(), StatusCode::NOT_FOUND);

    let bad = client
        .get(format!("http://127.0.0.1:{}/hello", frontdoor_addr.port()))
        .header("host", "ai.myc")
        .header("authorization", "Bearer wrong")
        .send()
        .await?;
    assert_eq!(bad.status(), StatusCode::UNAUTHORIZED);

    frontdoor.abort();
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

    let (addr, frontdoor) = start_frontdoor(route_path.clone(), None).await?;
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
    assert_eq!(health["tls"], json!(false));

    frontdoor.abort();
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
    let frontdoor = tokio::spawn(server::run(addr, Some(route_path.clone()), None, 1));

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

    frontdoor.abort();
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
    let (addr, frontdoor) = start_frontdoor(route_path.clone(), None).await?;
    let client = Client::new();
    assert!(wait_health(&addr, &client).await);

    let mut response = client
        .get(format!("http://127.0.0.1:{}/stream", addr.port()))
        .header("host", "ai.myc")
        .send()
        .await?;
    let first = tokio::time::timeout(Duration::from_millis(300), response.chunk()).await??;
    assert_eq!(first.as_deref(), Some(&b"first"[..]));

    frontdoor.abort();
    upstream_handle.abort();
    let _ = fs::remove_file(route_path);
    Ok(())
}

#[tokio::test]
async fn serves_https_and_reports_the_forwarded_proto() -> Result<(), Box<dyn std::error::Error>> {
    use axum::http::HeaderMap;
    use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair};

    let upstream = TcpListener::bind("127.0.0.1:0").await?;
    let upstream_addr = upstream.local_addr()?;
    let upstream_handle = tokio::spawn(async move {
        axum::serve(
            upstream,
            Router::new().route(
                "/proto",
                get(|headers: HeaderMap| async move {
                    Json(json!({
                        "proto": headers.get("x-forwarded-proto")
                            .and_then(|value| value.to_str().ok())
                    }))
                }),
            ),
        )
        .await
        .expect("upstream serve should succeed");
    });

    let mut ca_params = CertificateParams::new(vec!["frontdoor-test-ca".into()])?;
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca_key = KeyPair::generate()?;
    let ca = ca_params.self_signed(&ca_key)?;
    let leaf_key = KeyPair::generate()?;
    let leaf =
        CertificateParams::new(vec!["127.0.0.1".into()])?.signed_by(&leaf_key, &ca, &ca_key)?;

    let cert_path = temp_path("tls-cert").with_extension("pem");
    let key_path = temp_path("tls-key").with_extension("pem");
    fs::write(&cert_path, leaf.pem())?;
    fs::write(&key_path, leaf_key.serialize_pem())?;

    let route_path = temp_path("tls-routes");
    fs::write(
        &route_path,
        format!(
            r#"{{"routes": [{{"name": "ai", "hosts": ["ai.myc"],
                "upstream": "http://127.0.0.1:{}"}}]}}"#,
            upstream_addr.port()
        ),
    )?;

    let (addr, frontdoor) =
        start_frontdoor_tls(route_path.clone(), cert_path.clone(), key_path.clone()).await?;
    let client = Client::builder()
        .add_root_certificate(reqwest::Certificate::from_pem(ca.pem().as_bytes())?)
        .build()?;
    let base = format!("https://127.0.0.1:{}", addr.port());
    let health = loop {
        if let Ok(response) = client.get(format!("{base}/healthz")).send().await {
            if response.status().is_success() {
                break response.json::<serde_json::Value>().await?;
            }
        }
        sleep(Duration::from_millis(50)).await;
    };
    assert_eq!(health["tls"], json!(true));

    let response = client
        .get(format!("{base}/proto"))
        .header("host", "ai.myc")
        .send()
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let body: serde_json::Value = response.json().await?;
    assert_eq!(body["proto"], json!("https"));

    frontdoor.abort();
    upstream_handle.abort();
    let _ = fs::remove_file(cert_path);
    let _ = fs::remove_file(key_path);
    let _ = fs::remove_file(route_path);
    Ok(())
}

#[tokio::test]
async fn refuses_to_start_with_missing_inputs() {
    let address = "127.0.0.1:0".parse().unwrap();
    let missing_token = std::env::temp_dir().join("mycelium-frontdoor-missing-token");
    let result = server::run(address, None, Some(missing_token), 0).await;
    assert!(result.is_err());

    let missing_config = std::env::temp_dir().join("mycelium-frontdoor-missing-routes");
    let result = server::run(address, Some(missing_config), None, 0).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn falls_back_to_a_discovered_local_service() -> Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::fs::PermissionsExt;

    let upstream = TcpListener::bind("127.0.0.1:0").await?;
    let upstream_addr = upstream.local_addr()?;
    let upstream_handle = tokio::spawn(async move {
        axum::serve(
            upstream,
            Router::new().route(
                "/hello",
                get(|| async { Json(json!({"backend": "discovered"})) }),
            ),
        )
        .await
        .expect("upstream serve should succeed");
    });

    let closed = TcpListener::bind("127.0.0.1:0").await?;
    let closed_port = closed.local_addr()?.port();
    drop(closed);

    let dir = temp_path("discovery").with_extension("d");
    fs::create_dir_all(&dir)?;
    let catalog = dir.join("catalog.json");
    let expires_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs()
        + 3600;
    fs::write(
        &catalog,
        format!(
            r#"{{"schema_version": 1, "observations":[{{
                "schema_version": 1,
                "service_id": "service/ai-local",
                "observed_at": 0,
                "expires_at": {expires_at},
                "provenance": {{"provider": "local", "observer": "local"}},
                "confidence": "strong",
                "value": {{
                    "kind": "ai",
                    "endpoints": ["http://127.0.0.1:{}"],
                    "attributes": {{"node_id": "local"}}
                }}
            }}]}}"#,
            upstream_addr.port()
        ),
    )?;
    let fake = dir.join("mycelium");
    fs::write(
        &fake,
        r#"#!/bin/sh
dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
case "$1" in
  node) printf '%s\n' '{"node":{"hello":{"node_id":"local"}}}' ;;
  services) cat "$dir/catalog.json" ;;
  *) exit 2 ;;
esac
"#,
    )?;
    fs::set_permissions(&fake, fs::Permissions::from_mode(0o755))?;

    let route_path = dir.join("routes.json");
    fs::write(
        &route_path,
        format!(
            r#"{{
              "mycelium_bin": "{}",
              "service_refresh_secs": 5,
              "routes": [{{
                "name": "ai",
                "hosts": ["ai.myc"],
                "upstream": "http://127.0.0.1:{}",
                "service_kind": "ai"
              }}]
            }}"#,
            fake.display(),
            closed_port
        ),
    )?;

    let (addr, frontdoor) = start_frontdoor(route_path, None).await?;
    let client = Client::new();
    assert!(wait_health(&addr, &client).await);
    let response = client
        .get(format!("http://127.0.0.1:{}/hello", addr.port()))
        .header("host", "ai.myc")
        .send()
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let body: serde_json::Value = response.json().await?;
    assert_eq!(body["backend"], json!("discovered"));

    frontdoor.abort();
    upstream_handle.abort();
    let _ = fs::remove_dir_all(dir);
    Ok(())
}
