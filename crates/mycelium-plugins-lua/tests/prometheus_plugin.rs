use mycelium_core::{
    CredentialSet, Driver, ExecContext, Inventory, Params, RecordingTransport, Target, Transport,
    Value,
};
use mycelium_plugins_lua::Plugin;
use std::sync::Arc;

const PROMETHEUS: &str = include_str!("../plugins/prometheus.lua");

/// The exact command the plugin host renders for a bounded scrape. The URL
/// is passed as `$1`, so it is never interpolated into the script text.
fn scrape_command(url: &str, limit: u32) -> String {
    format!(
        "sh '-c' 'curl --silent --show-error --max-time 5 --proto \"=http\" --write-out \"\\n#mycelium-http-status:%{{http_code}}\" \"$1\" | head -c {limit}' 'sh' '{url}'"
    )
}

const DEFAULT_URL: &str = "http://127.0.0.1:9090/metrics";

const EXPOSITION: &str = "\
# HELP prometheus_build_info A metric with a constant '1' value.
# TYPE prometheus_build_info gauge
prometheus_build_info{branch=\"HEAD\",version=\"2.53.0\"} 1
# HELP up Target scrape health.
# TYPE up gauge
up{instance=\"127.0.0.1:9090\",job=\"prometheus\"} 1
# HELP scrape_duration_seconds Duration of a scrape.
# TYPE scrape_duration_seconds gauge
scrape_duration_seconds 0.012
";

fn scrape_reply(body: &str, status: &str) -> String {
    format!("{body}\n#mycelium-http-status:{status}")
}

fn transport() -> Arc<RecordingTransport> {
    let transport = Arc::new(RecordingTransport::new());
    transport.reply(
        scrape_command(DEFAULT_URL, 4096),
        scrape_reply(EXPOSITION, "200"),
    );
    transport.reply(
        scrape_command(DEFAULT_URL, 1048576),
        scrape_reply(EXPOSITION, "200"),
    );
    transport.reply("hostname", "metrics-host\n");
    transport
}

async fn attach(source: &str, transport: Arc<RecordingTransport>) -> (Inventory, String) {
    let plugin = Arc::new(Plugin::load(source).unwrap());
    let driver = plugin.driver(Arc::new(move |_: Target, _: CredentialSet| {
        let transport = transport.clone();
        async move { Ok(transport as Arc<dyn Transport>) }
    }));
    let inventory = Inventory::new();
    let id = driver
        .attach(
            &Target::host("metrics.example"),
            &CredentialSet::default(),
            &inventory,
        )
        .await
        .unwrap();
    (inventory, id.to_string())
}

async fn attach_expecting_failure(
    source: &str,
    transport: Arc<RecordingTransport>,
) -> mycelium_core::MyceliumError {
    let plugin = Arc::new(Plugin::load(source).unwrap());
    let driver = plugin.driver(Arc::new(move |_: Target, _: CredentialSet| {
        let transport = transport.clone();
        async move { Ok(transport as Arc<dyn Transport>) }
    }));
    let inventory = Inventory::new();
    driver
        .attach(
            &Target::host("metrics.example"),
            &CredentialSet::default(),
            &inventory,
        )
        .await
        .expect_err("a non-metrics endpoint must not attach")
}

#[tokio::test]
async fn recognition_requires_a_prometheus_exposition() {
    for (body, expected) in [
        (scrape_reply(EXPOSITION, "200"), true),
        (
            scrape_reply("<!DOCTYPE html>\n<html><body>hi</body></html>\n", "200"),
            false,
        ),
        (scrape_reply("404 page not found\n", "404"), false),
        (scrape_reply("{\"status\":\"ok\"}\n", "200"), false),
        (scrape_reply("", "200"), false),
    ] {
        let transport = Arc::new(RecordingTransport::new());
        transport.reply(scrape_command(DEFAULT_URL, 4096), body);
        let plugin = Arc::new(Plugin::load(PROMETHEUS).unwrap());
        let driver = plugin.driver(Arc::new(move |_: Target, _: CredentialSet| {
            let transport = transport.clone();
            async move { Ok(transport as Arc<dyn Transport>) }
        }));
        assert_eq!(
            driver
                .recognizes(&Target::host("metrics.example"), &CredentialSet::default())
                .await
                .unwrap(),
            expected
        );
    }
}

#[tokio::test]
async fn identity_reports_the_exposition_not_the_host() {
    let (inventory, id) = attach(PROMETHEUS, transport()).await;
    assert_eq!(id, "prometheus-metrics-host");
    let device = inventory.get(&id).unwrap();
    let meta = device.meta();
    assert_eq!(meta.vendor.as_deref(), Some("Prometheus"));
    assert_eq!(meta.model.as_deref(), Some("prometheus"));
    assert_eq!(meta.firmware.as_deref(), Some("2.53.0"));
    // The adapter observes a metrics endpoint; it exposes no write path.
    assert!(!device.capabilities().contains_key("prometheus.write"));
}

#[tokio::test]
async fn metrics_capability_summarises_the_exposition() {
    let (inventory, id) = attach(PROMETHEUS, transport()).await;
    let device = inventory.get(&id).unwrap();
    let result = device
        .invoke(
            &ExecContext::readonly("prometheus.metrics"),
            "prometheus.metrics",
            Params::new(),
        )
        .await
        .unwrap();
    let rendered = format!("{:?}", result.output);
    assert!(rendered.contains("\"families\": Int(3)"), "{rendered}");
    assert!(rendered.contains("\"samples\": Int(3)"), "{rendered}");
    assert!(rendered.contains("\"up\": Str(\"1\")"), "{rendered}");
    assert!(rendered.contains("2.53.0"), "{rendered}");
}

#[tokio::test]
async fn non_metrics_responses_are_refused() {
    for (body, expected) in [
        (
            scrape_reply("<!DOCTYPE html>\n<html></html>\n", "200"),
            "HTML",
        ),
        (scrape_reply("404 page not found\n", "404"), "404"),
        (
            scrape_reply("{\"status\":\"ok\"}\n", "200"),
            "not a Prometheus sample",
        ),
    ] {
        let transport = Arc::new(RecordingTransport::new());
        transport.reply(scrape_command(DEFAULT_URL, 4096), body.clone());
        transport.reply(scrape_command(DEFAULT_URL, 1048576), body);
        transport.reply("hostname", "metrics-host\n");
        // Identity refuses the same evidence, so the device never attaches.
        let error = attach_expecting_failure(PROMETHEUS, transport).await;
        assert!(
            format!("{error:?}").contains(expected),
            "expected {expected} in {error:?}"
        );
    }
}

#[tokio::test]
async fn target_inventory_drops_urls_and_errors() {
    let transport = transport();
    transport.reply(
        "curl '--silent' '--show-error' '--max-time' '5' '--proto' '=http' 'http://127.0.0.1:9090/api/v1/targets'",
        r#"{"status":"success","data":{"activeTargets":[
            {"labels":{"job":"node","instance":"10.0.0.5:9100"},"scrapeUrl":"http://user:secret@10.0.0.5:9100/metrics","health":"up","lastError":""},
            {"labels":{"job":"node","instance":"10.0.0.6:9100"},"scrapeUrl":"http://10.0.0.6:9100/metrics","health":"down","lastError":"dial tcp 10.0.0.6:9100: connection refused"}
        ]}}"#,
    );
    let (inventory, id) = attach(PROMETHEUS, transport).await;
    let device = inventory.get(&id).unwrap();
    let result = device
        .invoke(
            &ExecContext::readonly("prometheus.targets"),
            "prometheus.targets",
            Params::new(),
        )
        .await
        .unwrap();
    let rendered = format!("{:?}", result.output);
    assert!(rendered.contains("\"active\": Int(2)"), "{rendered}");
    assert!(rendered.contains("\"healthy\": Int(1)"), "{rendered}");
    assert!(rendered.contains("10.0.0.5:9100"), "{rendered}");
    // A scrape URL or a last error can carry credentials: neither is projected.
    assert!(!rendered.contains("secret"), "{rendered}");
    assert!(!rendered.contains("scrapeUrl"), "{rendered}");
    assert!(!rendered.contains("lastError"), "{rendered}");
}

#[tokio::test]
async fn the_endpoint_cannot_leave_loopback_or_carry_credentials() {
    let (inventory, id) = attach(PROMETHEUS, transport()).await;
    let device = inventory.get(&id).unwrap();
    for params in [
        Params::from([("path".into(), Value::Str("/metrics?token=secret".into()))]),
        Params::from([(
            "path".into(),
            Value::Str("http://user:pass@host/metrics".into()),
        )]),
        Params::from([("path".into(), Value::Str("/metrics/../secret".into()))]),
        Params::from([("port".into(), Value::Str("0".into()))]),
        Params::from([("port".into(), Value::Str("not-a-port".into()))]),
    ] {
        let error = device
            .invoke(
                &ExecContext::readonly("prometheus.metrics"),
                "prometheus.metrics",
                params,
            )
            .await
            .unwrap_err();
        let rendered = format!("{error:?}");
        assert!(
            rendered.contains("path must be") || rendered.contains("port must be"),
            "{rendered}"
        );
    }
}
