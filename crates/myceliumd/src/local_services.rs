//! Generic application-owned leases carried by existing signed topology gossip.
//! No application protocol, Unibus dependency, proxying, or permission issuance.
//!
//! A lease carries the labels its service asks for. The zone composes them into
//! names, so a name exists exactly as long as a fresh lease claims it, and DNS
//! and routing answer the same name because the daemon publishes it once.
use fpl_resource_observation::{ServiceCatalog, ServiceObservation, SCHEMA_VERSION};
use mycelium_core::{Observation, Origin, ServiceAdvertisement};
use std::{collections::BTreeSet, io::Read, path::Path};

const SERVICE_TYPE: &str = "_application-owner._tcp";
pub const MAX_DOCUMENT_BYTES: usize = 65536;

fn validate(observation: &ServiceObservation, node: &str) -> Result<(), String> {
    let label = |s: &str| {
        !s.is_empty()
            && s.len() <= 256
            && s.bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"-_.:/".contains(&b))
    };
    if observation.schema_version != SCHEMA_VERSION
        || !label(&observation.service_id.0)
        || !label(&observation.value.kind)
        || observation.provenance.observer != node
        || observation
            .value
            .attributes
            .get("node_id")
            .is_some_and(|id| id != node)
        || observation.expires_at <= observation.observed_at
        || observation.expires_at - observation.observed_at > 300
    {
        return Err("invalid application lease identity, owner or validity".into());
    }
    let mut names = BTreeSet::new();
    if observation.value.names.len() > 8
        || !observation
            .value
            .names
            .iter()
            .all(|name| mycelium_dns_policy::service_names::valid_label(name) && names.insert(name))
    {
        return Err("application lease names must be 1-8 unique DNS labels".into());
    }
    if observation.value.endpoints.is_empty()
        || observation.value.endpoints.len() > 32
        || observation.value.attributes.len() > 32
        || serde_json::to_vec(observation)
            .map_err(|e| e.to_string())?
            .len()
            > 8192
    {
        return Err("application lease exceeds bounds".into());
    }
    for endpoint in &observation.value.endpoints {
        let url = reqwest::Url::parse(endpoint).map_err(|_| "invalid application endpoint")?;
        if !matches!(url.scheme(), "http" | "https" | "tcp" | "quic" | "iroh")
            || url.host_str().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return Err("application endpoints must be credential-free connection hints".into());
        }
    }
    Ok(())
}

/// Read-only owner file. An absent file disables this source; never renew an
/// expired lease or infer public addresses for a loopback endpoint.
pub fn observe_file(path: &Path, node: &str, now: u64) -> Result<Vec<Observation>, String> {
    let file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(vec![]),
        Err(_) => return Err("cannot read application owner leases".into()),
    };
    let mut bytes = Vec::new();
    file.take(MAX_DOCUMENT_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "cannot read application owner leases")?;
    observe(&bytes, node, now)
}
pub fn observe(bytes: &[u8], node: &str, now: u64) -> Result<Vec<Observation>, String> {
    if bytes.len() > MAX_DOCUMENT_BYTES {
        return Err("application lease document exceeds bound".into());
    }
    let document: ServiceCatalog =
        serde_json::from_slice(bytes).map_err(|_| "invalid application lease document")?;
    if document.schema_version != SCHEMA_VERSION || document.observations.len() > 128 {
        return Err("unsupported or oversized application lease document".into());
    }
    let mut seen = BTreeSet::new();
    let mut claimed = BTreeSet::new();
    let mut observations = Vec::new();
    for observation in document.observations {
        validate(&observation, node)?;
        for name in &observation.value.names {
            if !claimed.insert(name.clone()) {
                return Err(format!("two application leases claim `{name}`"));
            }
        }
        if !seen.insert(observation.service_id.clone()) || observation.observed_at > now {
            return Err("duplicate or future application owner lease".into());
        }
        if !observation.is_fresh_at(now) {
            continue;
        }
        let encoded = serde_json::to_string(&observation).map_err(|e| e.to_string())?;
        observations.push(Observation::ServiceAdvertisement {
            advertisement: ServiceAdvertisement {
                instance: observation.service_id.0,
                service_type: SERVICE_TYPE.into(),
                domain: format!("{node}.mycelium"),
                target: Some(node.into()),
                addresses: BTreeSet::new(),
                port: None,
                txt: BTreeSet::from([format!("observation={encoded}")]),
                interface: None,
                ttl: Some((observation.expires_at - observation.observed_at) as u32),
                first_seen: observation.observed_at,
                last_seen: observation.observed_at,
                origins: BTreeSet::from([node.into()]),
            },
            origin: Origin::new(node, "application-owner-lease"),
        });
    }
    Ok(observations)
}
pub fn project(ad: &ServiceAdvertisement) -> Result<Option<ServiceObservation>, String> {
    if ad.service_type != SERVICE_TYPE {
        return Ok(None);
    }
    let node = ad
        .target
        .as_deref()
        .ok_or("application lease has no owner")?;
    if ad.domain != format!("{node}.mycelium") || !ad.origins.contains(node) {
        return Err("application owner provenance mismatch".into());
    }
    let mut values = ad.txt.iter().filter_map(|v| v.strip_prefix("observation="));
    let bytes = values.next().ok_or("missing application lease")?;
    if values.next().is_some() || bytes.len() > 8192 {
        return Err("ambiguous or oversized application lease".into());
    }
    let mut observation: ServiceObservation =
        serde_json::from_str(bytes).map_err(|_| "invalid application lease projection")?;
    validate(&observation, node)?;
    if observation.service_id.0 != ad.instance
        || observation.observed_at != ad.last_seen
        || ad.ttl != Some((observation.expires_at - observation.observed_at) as u32)
    {
        return Err("application lease and advertisement disagree".into());
    }
    observation.provenance.provider = "mycelium-application-owner-lease".into();
    observation.provenance.source_id = Some(ad.key());
    Ok(Some(observation))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn document() -> serde_json::Value {
        serde_json::json!({"schema_version":1,"observations":[{
            "schema_version":1,"service_id":"service/peer/application/test","observed_at":100,"expires_at":160,
            "provenance":{"provider":"application","observer":"peer"},"confidence":"strong",
            "value":{"kind":"unibus-gateway","endpoints":["http://127.0.0.1:9000"],"attributes":{"node_id":"peer"}}
        }]})
    }
    #[test]
    fn owner_lease_round_trip_preserves_loopback_and_expiry() {
        let bytes = serde_json::to_vec(&document()).unwrap();
        let mut observations = observe(&bytes, "peer", 100).unwrap();
        let Observation::ServiceAdvertisement { advertisement, .. } = observations.remove(0) else {
            panic!()
        };
        let result = project(&advertisement).unwrap().unwrap();
        assert_eq!(result.expires_at, 160);
        assert!(result.value.endpoints.contains("http://127.0.0.1:9000"));
        assert_eq!(result.provenance.observer, "peer");
        assert!(observe(&bytes, "peer", 160).unwrap().is_empty());
        assert!(observe(&bytes, "other", 100).is_err());
        assert!(observe(&bytes, "peer", 99).is_err());
    }
    #[test]
    fn application_lease_survives_topology_serialization_and_catalog_projection() {
        let observations = observe(&serde_json::to_vec(&document()).unwrap(), "peer", 100).unwrap();
        let mut topology = mycelium_core::Topology::default();
        topology.observe_all(observations);
        let transferred: mycelium_core::Topology =
            serde_json::from_slice(&serde_json::to_vec(&topology).unwrap()).unwrap();
        let catalog = crate::services::project(&transferred);
        assert_eq!(catalog.observations.len(), 1);
        assert_eq!(catalog.observations[0].value.kind, "unibus-gateway");
        assert_eq!(catalog.observations[0].expires_at, 160);
        let mut ad = transferred.advertisements.values().next().unwrap().clone();
        ad.target = Some("other".into());
        assert!(project(&ad).is_err());
    }
    #[test]
    fn credentials_duplicate_ids_and_oversized_documents_fail() {
        let mut doc = document();
        doc["observations"][0]["value"]["endpoints"] =
            serde_json::json!(["http://user:password@host.test/"]);
        assert!(observe(&serde_json::to_vec(&doc).unwrap(), "peer", 100).is_err());
        let mut doc = document();
        let duplicate = doc["observations"][0].clone();
        doc["observations"].as_array_mut().unwrap().push(duplicate);
        assert!(observe(&serde_json::to_vec(&doc).unwrap(), "peer", 100).is_err());
        assert!(observe(&vec![0; MAX_DOCUMENT_BYTES + 1], "peer", 100).is_err());
    }
    #[test]
    #[ignore = "cross-project fixture: set FPL_TEST_OWNER_CATALOG_FILE to an Unibus-exported catalog"]
    fn consumes_actual_unibus_owner_document_without_unibus_dependency() {
        let path = std::env::var_os("FPL_TEST_OWNER_CATALOG_FILE")
            .expect("explicit test fixture required");
        let observations = observe_file(Path::new(&path), "host", 100).unwrap();
        let mut topology = mycelium_core::Topology::default();
        topology.observe_all(observations);
        let catalog = crate::services::project(&topology);
        assert_eq!(catalog.observations.len(), 1);
        let observation = &catalog.observations[0];
        assert_eq!(observation.value.kind, "unibus-gateway");
        assert_eq!(observation.provenance.observer, "host");
        assert_eq!(observation.expires_at, 160);
        assert!(observation.value.attributes.contains_key("gateway_lease"));
    }

    #[test]
    fn names_must_be_unique_labels_and_travel_with_the_lease() {
        let mut document = document();
        document["observations"][0]["value"]["names"] = serde_json::json!(["files", "docs"]);
        let bytes = serde_json::to_vec(&document).unwrap();
        let mut observations = observe(&bytes, "peer", 100).unwrap();
        let Observation::ServiceAdvertisement { advertisement, .. } = observations.remove(0) else {
            panic!()
        };
        let result = project(&advertisement).unwrap().unwrap();
        assert_eq!(
            result.value.names,
            vec!["files".to_owned(), "docs".to_owned()]
        );

        for names in [
            serde_json::json!(["Files"]),
            serde_json::json!(["files.myc"]),
            serde_json::json!(["-files"]),
            serde_json::json!(["files", "files"]),
            serde_json::json!(["a", "b", "c", "d", "e", "f", "g", "h", "i"]),
        ] {
            document["observations"][0]["value"]["names"] = names;
            assert!(observe(&serde_json::to_vec(&document).unwrap(), "peer", 100).is_err());
        }
    }

    #[test]
    fn two_leases_in_one_document_cannot_claim_one_name() {
        let mut document = document();
        document["observations"][0]["value"]["names"] = serde_json::json!(["files"]);
        let mut second = document["observations"][0].clone();
        second["service_id"] = serde_json::json!("service/peer/application/other");
        document["observations"]
            .as_array_mut()
            .unwrap()
            .push(second);
        assert!(observe(&serde_json::to_vec(&document).unwrap(), "peer", 100).is_err());
    }
}
