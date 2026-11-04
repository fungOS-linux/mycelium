use mycelium_core::ServiceAdvertisement;
use mycelium_plugins_lua::AdvertisementRecognizer;
use std::collections::{BTreeMap, BTreeSet};

const PROMETHEUS: &str = include_str!("../recognizers/prometheus.lua");

fn advertisement(service_type: &str, txt: &[&str]) -> ServiceAdvertisement {
    ServiceAdvertisement {
        instance: "metrics.local".into(),
        service_type: service_type.into(),
        domain: "local.".into(),
        target: Some("metrics.local".into()),
        addresses: BTreeSet::from(["10.0.0.9".parse().unwrap()]),
        port: Some(9090),
        txt: txt.iter().map(|entry| entry.to_string()).collect(),
        interface: Some("eth0".into()),
        ttl: Some(120),
        first_seen: 10,
        last_seen: 20,
        origins: BTreeSet::from(["mdns".into()]),
    }
}

#[test]
fn prometheus_advertisements_become_stable_device_facts() {
    let recognizer = AdvertisementRecognizer::load(PROMETHEUS).unwrap();
    let device = recognizer
        .recognize(&advertisement(
            "_prometheus._tcp",
            &["id=abc-123", "path=/metrics"],
        ))
        .unwrap()
        .expect("a metrics advertisement is recognized");
    assert_eq!(device.stable_id, "prometheus:abc-123");
    assert_eq!(device.kind, "metrics.server");
    assert_eq!(device.vendor.as_deref(), Some("Prometheus"));
    assert_eq!(device.model.as_deref(), Some("prometheus"));
    assert_eq!(device.serial.as_deref(), Some("abc-123"));
    assert_eq!(device.observed_at, 20);
    assert_eq!(device.services.len(), 1);
    assert_eq!(device.services[0].port, 9090);
    assert_eq!(
        device.attributes.get("metrics_path").map(String::as_str),
        Some("/metrics")
    );
}

#[test]
fn exporter_advertisements_are_observers_not_authorizations() {
    let recognizer = AdvertisementRecognizer::load(PROMETHEUS).unwrap();
    let device = recognizer
        .recognize(&advertisement("_node-exporter._tcp", &["uuid=def-456"]))
        .unwrap()
        .expect("an exporter advertisement is recognized");
    assert_eq!(device.kind, "metrics.exporter");
    assert_eq!(device.model.as_deref(), Some("node_exporter"));
    assert_eq!(device.stable_id, "prometheus:def-456");
}

#[test]
fn unrelated_or_anonymous_advertisements_are_ignored() {
    let recognizer = AdvertisementRecognizer::load(PROMETHEUS).unwrap();
    // Another service type is not a metrics endpoint.
    assert!(recognizer
        .recognize(&advertisement("_http._tcp", &["id=abc-123"]))
        .unwrap()
        .is_none());
    // Without an explicit identity the advertisement stays anonymous.
    assert!(recognizer
        .recognize(&advertisement("_prometheus._tcp", &["path=/metrics"]))
        .unwrap()
        .is_none());
}

#[test]
fn a_traversal_path_falls_back_to_the_standard_endpoint() {
    let recognizer = AdvertisementRecognizer::load(PROMETHEUS).unwrap();
    let device = recognizer
        .recognize(&advertisement(
            "_prometheus._tcp",
            &["id=abc-123", "path=/metrics/../../secret"],
        ))
        .unwrap()
        .expect("the advertisement is still recognized");
    let attributes: BTreeMap<&str, &str> = device
        .attributes
        .iter()
        .map(|(key, value)| (key.as_str(), value.as_str()))
        .collect();
    assert_eq!(attributes.get("metrics_path"), Some(&"/metrics"));
}
