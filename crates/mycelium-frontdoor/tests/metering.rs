use axum::body::Bytes;
use axum::extract::State;
use axum::http::{header, StatusCode};
use axum::response::IntoResponse;
use axum::routing::post;
use axum::{Json, Router};
use mycelium_frontdoor::server;
use reqwest::Client;
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::time::sleep;

fn temp_path(label: &str) -> std::path::PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let id = NEXT.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "mycelium-frontdoor-metering-{label}-{}-{id}.json",
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

async fn wait_for_requests(
    frontdoor: &std::net::SocketAddr,
    client: &Client,
    expected: u64,
) -> Value {
    let mut last = Value::Null;
    for _ in 0..50 {
        if let Ok(response) = client
            .get(format!(
                "http://127.0.0.1:{}/.mycelium/usage",
                frontdoor.port()
            ))
            .send()
            .await
        {
            last = response.json::<Value>().await.unwrap_or(Value::Null);
            if last["totals"]["requests"].as_u64() == Some(expected) {
                return last;
            }
        }
        sleep(Duration::from_millis(50)).await;
    }
    panic!("usage never reported {expected} requests: {last}");
}

struct FakeUpstream {
    address: std::net::SocketAddr,
    seen: Arc<Mutex<Vec<Value>>>,
    handle: tokio::task::JoinHandle<()>,
}

async fn fake_upstream(stream: bool) -> FakeUpstream {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let seen: Arc<Mutex<Vec<Value>>> = Arc::new(Mutex::new(Vec::new()));
    let state = seen.clone();
    let handle = tokio::spawn(async move {
        let app = Router::new()
            .route(
                "/v1/chat/completions",
                post(move |State(seen): State<Arc<Mutex<Vec<Value>>>>, body: Bytes| async move {
                    let value: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
                    seen.lock().unwrap().push(value.clone());
                    if stream {
                        (
                            StatusCode::OK,
                            [(header::CONTENT_TYPE, "text/event-stream")],
                            "data: {\"choices\":[{\"delta\":{\"content\":\"hi\"}}]}\n\n\
                             data: {\"choices\":[],\"usage\":{\"prompt_tokens\":7,\"completion_tokens\":5,\"total_tokens\":12}}\n\n\
                             data: [DONE]\n\n",
                        )
                            .into_response()
                    } else {
                        Json(json!({
                            "choices": [{"message": {"role": "assistant", "content": "hi"}}],
                            "usage": {"prompt_tokens": 11, "completion_tokens": 3,
                                "prompt_tokens_details": {"cached_tokens": 2}}
                        }))
                        .into_response()
                    }
                }),
            )
            .with_state(state);
        axum::serve(listener, app).await.unwrap();
    });
    FakeUpstream {
        address,
        seen,
        handle,
    }
}

async fn start_frontdoor(
    upstreams: &[&str],
    usage_path: std::path::PathBuf,
) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    drop(listener);
    let route_path = temp_path("routes");
    std::fs::write(
        &route_path,
        json!({
            "routes": [{
                "name": "ai",
                "hosts": ["ai.myc"],
                "upstream": upstreams,
            }]
        })
        .to_string(),
    )
    .unwrap();
    let handle = tokio::spawn(async move {
        server::run_with_options(
            vec![address],
            Some(route_path),
            None,
            0,
            None,
            Some(usage_path),
        )
        .await
        .expect("frontdoor should run");
    });
    (address, handle)
}

#[tokio::test]
async fn counts_tokens_from_a_buffered_completion() {
    let upstream = fake_upstream(false).await;
    let (frontdoor, _handle) = start_frontdoor(
        &[&format!("http://{}", upstream.address)],
        temp_path("usage"),
    )
    .await;
    let client = Client::new();
    assert!(wait_health(&frontdoor, &client).await);

    let response = client
        .post(format!(
            "http://127.0.0.1:{}/v1/chat/completions",
            frontdoor.port()
        ))
        .header("host", "ai.myc")
        .json(&json!({"model": "fpl/coder", "messages": []}))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = response.json().await.unwrap();
    assert_eq!(body["choices"][0]["message"]["content"], json!("hi"));

    let usage = wait_for_requests(&frontdoor, &client, 1).await;
    assert_eq!(usage["totals"]["metered_requests"], json!(1));
    assert_eq!(usage["totals"]["prompt_tokens"], json!(11));
    assert_eq!(usage["totals"]["completion_tokens"], json!(3));
    assert_eq!(usage["totals"]["cached_tokens"], json!(2));
    assert_eq!(usage["routes"]["ai"]["completion_tokens"], json!(3));
    assert_eq!(usage["models"]["fpl/coder"]["prompt_tokens"], json!(11));
    upstream.handle.abort();
}

#[tokio::test]
async fn streaming_requests_ask_for_usage_and_count_it() {
    let upstream = fake_upstream(true).await;
    let (frontdoor, _handle) = start_frontdoor(
        &[&format!("http://{}", upstream.address)],
        temp_path("usage-stream"),
    )
    .await;
    let client = Client::new();
    assert!(wait_health(&frontdoor, &client).await);

    let body = client
        .post(format!(
            "http://127.0.0.1:{}/v1/chat/completions",
            frontdoor.port()
        ))
        .header("host", "ai.myc")
        .json(&json!({"model": "fpl/coder", "stream": true, "messages": []}))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(body.contains("\"completion_tokens\":5"), "{body}");
    assert_eq!(
        upstream.seen.lock().unwrap()[0]["stream_options"]["include_usage"],
        json!(true)
    );

    let usage = wait_for_requests(&frontdoor, &client, 1).await;
    assert_eq!(usage["totals"]["prompt_tokens"], json!(7));
    assert_eq!(usage["totals"]["completion_tokens"], json!(5));
    upstream.handle.abort();
}

#[tokio::test]
async fn an_unreachable_first_upstream_falls_through_to_the_next() {
    let closed = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let closed_address = closed.local_addr().unwrap();
    drop(closed);
    let upstream = fake_upstream(false).await;
    let (frontdoor, _handle) = start_frontdoor(
        &[
            &format!("http://{}", closed_address),
            &format!("http://{}", upstream.address),
        ],
        temp_path("usage-fallback"),
    )
    .await;
    let client = Client::new();
    assert!(wait_health(&frontdoor, &client).await);

    let response = client
        .post(format!(
            "http://127.0.0.1:{}/v1/chat/completions",
            frontdoor.port()
        ))
        .header("host", "ai.myc")
        .json(&json!({"model": "fpl/coder", "messages": []}))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(upstream.seen.lock().unwrap().len(), 1);
    upstream.handle.abort();
}
