//! Application-owned Iroh leases projected through existing topology gossip.
//! Endpoint keys identify transport peers, never people or permission grants.
use fpl_resource_observation::{
    Confidence, Provenance, Service, ServiceId, ServiceObservation, SCHEMA_VERSION,
};
use mycelium_core::{Observation, Origin, ServiceAdvertisement};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    io::Read,
    net::SocketAddr,
    path::Path,
};

pub const MAX_DOCUMENT_BYTES: usize = 65536;
pub const MAX_LEASE_SECONDS: u64 = 300;
pub const SERVICE_TYPE: &str = "_iroh._udp";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Endpoint {
    pub id: String,
    /// Lowercase hexadecimal encoding of the Iroh endpoint's public key.
    pub endpoint_id: String,
    /// UTF-8 ALPN names; arbitrary binary ALPNs are outside this v1 contract.
    pub alpns: BTreeSet<String>,
    #[serde(default)]
    pub direct_addresses: BTreeSet<SocketAddr>,
    #[serde(default)]
    pub relay_urls: BTreeSet<String>,
    pub observed_at: u64,
    pub expires_at: u64,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Document {
    pub schema_version: u16,
    pub endpoints: Vec<Endpoint>,
}

fn slug(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b))
}

impl Endpoint {
    pub fn validate(&self) -> Result<(), String> {
        if !slug(&self.id)
            || self.endpoint_id.len() != 64
            || !self
                .endpoint_id
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || self.endpoint_id.bytes().all(|b| b == b'0')
        {
            return Err("invalid Iroh endpoint identity".into());
        }
        if self.alpns.is_empty()
            || self.alpns.len() > 16
            || self
                .alpns
                .iter()
                .any(|a| a.is_empty() || a.len() > 128 || a.chars().any(char::is_control))
        {
            return Err("invalid bounded Iroh ALPNs".into());
        }
        if self.direct_addresses.len() > 16
            || self.relay_urls.len() > 4
            || (self.direct_addresses.is_empty() && self.relay_urls.is_empty())
            || self
                .direct_addresses
                .iter()
                .any(|a| a.port() == 0 || a.ip().is_unspecified() || a.ip().is_multicast())
        {
            return Err("invalid Iroh connection hints".into());
        }
        for relay in &self.relay_urls {
            let url = url::Url::parse(relay).map_err(|_| "invalid Iroh relay URL")?;
            if relay.len() > 512
                || url.scheme() != "https"
                || url.host_str().is_none()
                || !url.username().is_empty()
                || url.password().is_some()
                || url.query().is_some()
                || url.fragment().is_some()
            {
                return Err("Iroh relay hints must be credential-free HTTPS URLs".into());
            }
        }
        if self.observed_at == 0
            || self.expires_at <= self.observed_at
            || self.expires_at - self.observed_at > MAX_LEASE_SECONDS
        {
            return Err("invalid Iroh observation lease".into());
        }
        Ok(())
    }
}

pub fn parse(bytes: &[u8]) -> Result<Document, String> {
    if bytes.len() > MAX_DOCUMENT_BYTES {
        return Err("Iroh observation document exceeds bound".into());
    }
    let doc: Document =
        serde_json::from_slice(bytes).map_err(|_| "invalid Iroh observation document")?;
    if doc.schema_version != 1 || doc.endpoints.len() > 32 {
        return Err("unsupported or oversized Iroh document".into());
    }
    let mut ids = BTreeSet::new();
    let mut keys = BTreeSet::new();
    for endpoint in &doc.endpoints {
        endpoint.validate()?;
        if !ids.insert(&endpoint.id) || !keys.insert(&endpoint.endpoint_id) {
            return Err("duplicate Iroh endpoint identity".into());
        }
    }
    Ok(doc)
}

/// Absent file disables discovery. Invalid files fail visibly, never invent hints.
pub fn observe_file(path: &Path, node: &str, now: u64) -> Result<Vec<Observation>, String> {
    let file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(_) => return Err("cannot read Iroh observations".into()),
    };
    let mut bytes = Vec::new();
    file.take(MAX_DOCUMENT_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "cannot read Iroh observations")?;
    let doc = parse(&bytes)?;
    if doc.endpoints.iter().any(|e| e.observed_at > now) {
        return Err("Iroh observation is future dated".into());
    }
    Ok(doc
        .endpoints
        .into_iter()
        .filter(|e| now < e.expires_at)
        .map(|e| {
            let mut txt = BTreeSet::from([
                format!("endpoint_id={}", e.endpoint_id),
                format!("node_id={node}"),
                format!("observed_at={}", e.observed_at),
                format!("expires_at={}", e.expires_at),
            ]);
            txt.extend(e.alpns.iter().map(|a| format!("alpn={a}")));
            txt.extend(e.direct_addresses.iter().map(|a| format!("direct={a}")));
            txt.extend(e.relay_urls.iter().map(|r| format!("relay={r}")));
            Observation::ServiceAdvertisement {
                advertisement: ServiceAdvertisement {
                    instance: e.id,
                    service_type: SERVICE_TYPE.into(),
                    domain: format!("{node}.mycelium"),
                    target: Some(node.into()),
                    addresses: BTreeSet::new(),
                    port: None,
                    txt,
                    interface: None,
                    ttl: Some((e.expires_at - e.observed_at) as u32),
                    first_seen: e.observed_at,
                    last_seen: e.observed_at,
                    origins: BTreeSet::from([node.into()]),
                },
                origin: Origin::new(node, "iroh-owner-lease"),
            }
        })
        .collect())
}

/// Project only our explicit owner leases, not guessed UDP listeners or mDNS names.
pub fn project(ad: &ServiceAdvertisement) -> Result<Option<ServiceObservation>, String> {
    if ad.service_type != SERVICE_TYPE || !ad.domain.ends_with(".mycelium") {
        return Ok(None);
    }
    let one = |prefix: &str| -> Result<String, String> {
        let values: Vec<_> = ad
            .txt
            .iter()
            .filter_map(|v| v.strip_prefix(prefix))
            .collect();
        if values.len() != 1 {
            return Err("missing or ambiguous Iroh lease field".into());
        }
        Ok(values[0].into())
    };
    let many = |prefix: &str| {
        ad.txt
            .iter()
            .filter_map(|v| v.strip_prefix(prefix).map(str::to_owned))
            .collect::<BTreeSet<_>>()
    };
    let node = one("node_id=")?;
    if !slug(&node)
        || ad.domain != format!("{node}.mycelium")
        || ad.target.as_deref() != Some(&node)
        || !ad.origins.contains(&node)
    {
        return Err("Iroh owner provenance mismatch".into());
    }
    let endpoint = Endpoint {
        id: ad.instance.clone(),
        endpoint_id: one("endpoint_id=")?,
        alpns: many("alpn="),
        direct_addresses: many("direct=")
            .iter()
            .map(|v| v.parse().map_err(|_| "invalid Iroh address".into()))
            .collect::<Result<_, String>>()?,
        relay_urls: many("relay="),
        observed_at: one("observed_at=")?
            .parse()
            .map_err(|_| "invalid observation time")?,
        expires_at: one("expires_at=")?
            .parse()
            .map_err(|_| "invalid expiry time")?,
    };
    endpoint.validate()?;
    let mut attributes = BTreeMap::from([
        ("node_id".into(), node.clone()),
        ("endpoint_id".into(), endpoint.endpoint_id.clone()),
        ("authentication".into(), "application-owned".into()),
        (
            "relay_urls".into(),
            serde_json::to_string(&endpoint.relay_urls).unwrap(),
        ),
        (
            "direct_addresses".into(),
            serde_json::to_string(&endpoint.direct_addresses).unwrap(),
        ),
    ]);
    attributes.insert(
        "alpns".into(),
        serde_json::to_string(&endpoint.alpns).unwrap(),
    );
    Ok(Some(ServiceObservation {
        schema_version: SCHEMA_VERSION,
        service_id: ServiceId(format!("service/{node}/iroh/{}", endpoint.id)),
        observed_at: endpoint.observed_at,
        expires_at: endpoint.expires_at,
        provenance: Provenance {
            provider: "mycelium-iroh-owner-lease".into(),
            observer: node,
            source_id: Some(ad.key()),
        },
        confidence: Confidence::Derived,
        value: Service {
            kind: "iroh".into(),
            names: Vec::new(),
            endpoints: BTreeSet::from([format!("iroh://{}", endpoint.endpoint_id)]),
            protocols: BTreeSet::from(["iroh".into(), "quic".into()]),
            formats: BTreeSet::new(),
            attributes,
        },
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn endpoint() -> Endpoint {
        Endpoint {
            id: "worker".into(),
            endpoint_id: "a".repeat(64),
            alpns: BTreeSet::from(["fpl/compute/1".into()]),
            direct_addresses: BTreeSet::from(["192.168.1.2:4000".parse().unwrap()]),
            relay_urls: BTreeSet::new(),
            observed_at: 100,
            expires_at: 130,
        }
    }
    #[test]
    fn rejects_credentials_bad_keys_and_unbounded_leases() {
        assert!(endpoint().validate().is_ok());
        let mut e = endpoint();
        e.relay_urls
            .insert("https://user:secret@relay.example/".into());
        assert!(e.validate().is_err());
        let mut e = endpoint();
        e.endpoint_id = "0".repeat(64);
        assert!(e.validate().is_err());
        let mut e = endpoint();
        e.expires_at = 401;
        assert!(e.validate().is_err());
    }
    #[test]
    fn document_is_strict_bounded_and_deduplicated() {
        assert!(parse(
            &serde_json::to_vec(&Document {
                schema_version: 1,
                endpoints: vec![endpoint()]
            })
            .unwrap()
        )
        .is_ok());
        assert!(parse(
            &serde_json::to_vec(&Document {
                schema_version: 1,
                endpoints: vec![endpoint(), endpoint()]
            })
            .unwrap()
        )
        .is_err());
        assert!(parse(&vec![b' '; MAX_DOCUMENT_BYTES + 1]).is_err());
        assert!(parse(br#"{"schema_version":1,"endpoints":[],"secret":"x"}"#).is_err());
    }
    #[test]
    fn observations_expire_without_refresh_from_scan_or_projection() {
        let path =
            std::env::temp_dir().join(format!("mycelium-iroh-test-{}.json", std::process::id()));
        std::fs::write(
            &path,
            serde_json::to_vec(&Document {
                schema_version: 1,
                endpoints: vec![endpoint()],
            })
            .unwrap(),
        )
        .unwrap();
        let observations = observe_file(&path, "owner", 120).unwrap();
        let Observation::ServiceAdvertisement { advertisement, .. } = &observations[0] else {
            panic!()
        };
        let projected = project(advertisement).unwrap().unwrap();
        assert_eq!(projected.expires_at, 130);
        assert!(projected.is_fresh_at(129));
        assert!(!projected.is_fresh_at(130));
        assert!(observe_file(&path, "owner", 130).unwrap().is_empty());
        assert!(observe_file(&path, "owner", 99).is_err());
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn gossip_and_scan_replace_leases_and_ignore_older_replays() {
        let path =
            std::env::temp_dir().join(format!("mycelium-iroh-refresh-{}.json", std::process::id()));
        let observations = |observed_at, expires_at| {
            let mut e = endpoint();
            e.observed_at = observed_at;
            e.expires_at = expires_at;
            std::fs::write(
                &path,
                serde_json::to_vec(&Document {
                    schema_version: 1,
                    endpoints: vec![e],
                })
                .unwrap(),
            )
            .unwrap();
            observe_file(&path, "owner", observed_at).unwrap()
        };
        let old = observations(100, 130);
        let mut local = mycelium_core::Topology::empty();
        local.observe_all(old.clone());
        local.observe_all(observations(120, 180));
        assert_eq!(
            project(local.advertisements.values().next().unwrap())
                .unwrap()
                .unwrap()
                .expires_at,
            180
        );
        let mut remote = mycelium_core::Topology::empty();
        remote.observe_all(old.clone());
        remote.merge_snapshot(local);
        let mut replay = mycelium_core::Topology::empty();
        replay.observe_all(old);
        remote.merge_snapshot(replay);
        let ad = remote.advertisements.values().next().unwrap();
        assert_eq!(project(ad).unwrap().unwrap().expires_at, 180);
        assert_eq!(
            ad.txt
                .iter()
                .filter(|v| v.starts_with("expires_at="))
                .count(),
            1
        );
        let roundtrip: mycelium_core::Topology =
            serde_json::from_slice(&serde_json::to_vec(&remote).unwrap()).unwrap();
        assert_eq!(
            project(roundtrip.advertisements.values().next().unwrap())
                .unwrap()
                .unwrap()
                .observed_at,
            120
        );
        std::fs::remove_file(path).unwrap();
    }
}
