use mycelium_core::{
    CredentialSet, Driver, ExecContext, Inventory, Params, RecordingTransport, Target, Transport,
    Value,
};
use mycelium_plugins_lua::Plugin;
use std::sync::Arc;

const GRAFANA: &str = include_str!("../plugins/grafana.lua");

const DEFAULT_URL: &str = "http://127.0.0.1:3000/api/health";

fn health_command(url: &str) -> String {
    format!("curl '--silent' '--show-error' '--max-time' '5' '--proto' '=http' '{url}'")
}

const HEALTH: &str = r#"{"commit":"1f0a2b3","database":"ok","version":"11.1.0"}"#;

fn transport() -> Arc<RecordingTransport> {
    let transport = Arc::new(RecordingTransport::new());
    transport.reply(health_command(DEFAULT_URL), HEALTH);
    transport.reply("hostname", "dashboards.example\n");
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
            &Target::host("dashboards.example"),
            &CredentialSet::default(),
            &inventory,
        )
        .await
        .unwrap();
    (inventory, id.to_string())
}

#[tokio::test]
async fn recognition_requires_the_grafana_health_document() {
    for (body, expected) in [
        (HEALTH, true),
        (r#"{"status":"ok"}"#, false),
        ("<!DOCTYPE html>\n<html></html>\n", false),
    ] {
        let transport = Arc::new(RecordingTransport::new());
        transport.reply(health_command(DEFAULT_URL), body);
        let plugin = Arc::new(Plugin::load(GRAFANA).unwrap());
        let driver = plugin.driver(Arc::new(move |_: Target, _: CredentialSet| {
            let transport = transport.clone();
            async move { Ok(transport as Arc<dyn Transport>) }
        }));
        assert_eq!(
            driver
                .recognizes(
                    &Target::host("dashboards.example"),
                    &CredentialSet::default()
                )
                .await
                .unwrap(),
            expected
        );
    }
}

#[tokio::test]
async fn identity_and_health_project_only_declared_facts() {
    let (inventory, id) = attach(GRAFANA, transport()).await;
    assert_eq!(id, "grafana-dashboards-example");
    let device = inventory.get(&id).unwrap();
    assert_eq!(device.meta().vendor.as_deref(), Some("Grafana"));
    assert_eq!(device.meta().firmware.as_deref(), Some("11.1.0"));
    let result = device
        .invoke(
            &ExecContext::readonly("grafana.health"),
            "grafana.health",
            Params::new(),
        )
        .await
        .unwrap();
    let rendered = format!("{:?}", result.output);
    assert!(rendered.contains("\"database\": Str(\"ok\")"), "{rendered}");
    assert!(rendered.contains("11.1.0"), "{rendered}");
    // The build commit is not part of the declared projection.
    assert!(!rendered.contains("1f0a2b3"), "{rendered}");
}

#[tokio::test]
async fn the_health_endpoint_cannot_leave_loopback() {
    let (inventory, id) = attach(GRAFANA, transport()).await;
    let device = inventory.get(&id).unwrap();
    for params in [
        Params::from([("path".into(), Value::Str("/api/health?token=x".into()))]),
        Params::from([("path".into(), Value::Str("/api/admin".into()))]),
        Params::from([("port".into(), Value::Str("70000".into()))]),
    ] {
        let error = device
            .invoke(
                &ExecContext::readonly("grafana.health"),
                "grafana.health",
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
