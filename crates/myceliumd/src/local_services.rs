//! Generic application-owned leases carried by existing signed topology gossip.
//! No application protocol, Unibus dependency, proxying, or permission issuance.
//!
//! An owner may declare the names it answers on with a comma-separated `hosts`
//! attribute. That attribute is the only way a service becomes reachable by name
//! anywhere in the fleet: the gateway derives its host table from the catalog,
//! so a name exists exactly as long as a fresh lease claims it.
use fpl_resource_observation::{SCHEMA_VERSION, ServiceCatalog, ServiceObservation};
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
    if let Some(hosts) = observation.value.attributes.get("hosts") {
        validate_hosts(hosts)?;
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

/// Names an owner may claim. Bounded, lowercase, credential-free DNS names: an
/// owner that could claim a wildcard or an absolute URL could shadow every other
/// service in the fleet.
fn validate_hosts(hosts: &str) -> Result<(), String> {
    let names = hosts
        .split(',')
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .collect::<Vec<_>>();
    if names.is_empty() || names.len() > 8 {
        return Err("application hosts must list 1-8 names".into());
    }
    for name in names {
        let labels = name.split('.').collect::<Vec<_>>();
        if name.len() > 253
            || labels.len() < 2
            || !name.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"-.".contains(&b))
            || labels
                .iter()
                .any(|label| label.is_empty() || label.len() > 63 || label.starts_with('-') || label.ends_with('-'))
        {
            return Err(format!("application host `{name}` is not a plain lowercase DNS name"));
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
    let mut observations = Vec::new();
    for observation in document.observations {
        validate(&observation, node)?;
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
    fn hosts_attribute_accepts_plain_names_and_rejects_wildcards() {
        assert!(validate_hosts("files.myc").is_ok());
        assert!(validate_hosts("pulse.myc, worklog.myc").is_ok());
        assert!(validate_hosts("home.myc.fpl.dev").is_ok());
        assert!(validate_hosts("").is_err());
        assert!(validate_hosts("*.myc").is_err());
        assert!(validate_hosts("Files.myc").is_err());
        assert!(validate_hosts("myc").is_err());
        assert!(validate_hosts("-bad.myc").is_err());
        assert!(validate_hosts(&["a.myc"; 9].join(",")).is_err());
    }

    #[test]
    fn a_lease_claiming_a_name_is_rejected_when_the_name_is_not_plain() {
        let mut document = document();
        document["observations"][0]["value"]["attributes"]["hosts"] =
            serde_json::json!("*.myc");
        let bytes = serde_json::to_vec(&document).unwrap();
        assert!(observe(&bytes, "peer", 100).is_err());

        document["observations"][0]["value"]["attributes"]["hosts"] =
            serde_json::json!("files.myc");
        let bytes = serde_json::to_vec(&document).unwrap();
        let mut observations = observe(&bytes, "peer", 100).unwrap();
        let Observation::ServiceAdvertisement { advertisement, .. } = observations.remove(0)
        else {
            panic!()
        };
        let result = project(&advertisement).unwrap().unwrap();
        assert_eq!(
            result.value.attributes.get("hosts").map(String::as_str),
            Some("files.myc")
        );
    }
}
