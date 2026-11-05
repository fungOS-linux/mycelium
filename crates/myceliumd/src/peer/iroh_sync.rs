//! Optional QUIC carriage for the existing authenticated gossip stream.
//! Iroh keys identify transports, not users or access grants. Inner mTLS
//! retains the fleet CA, certificate binding, and signed-envelope checks.
use super::*;
use iroh::{Endpoint, EndpointAddr, SecretKey};
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};

const ALPN: &[u8] = b"mycelium/sync/1";
const LIMIT: usize = 32;
const DISCOVERED_LINK_LIMIT: usize = 2;
const HANDSHAKE: Duration = Duration::from_secs(15);

fn rendezvous_from_hints(hints: &mycelium_peer_protocol::SyncHints) -> SyncRendezvous {
    SyncRendezvous {
        server_name: hints.server_name.clone(),
        endpoint: mycelium_iroh_discovery::Endpoint {
            id: "mycelium-sync".into(),
            endpoint_id: hints.endpoint_id.clone(),
            alpns: BTreeSet::from([String::from_utf8_lossy(ALPN).into_owned()]),
            direct_addresses: hints.direct_addresses.clone(),
            relay_urls: hints.relay_urls.clone(),
            observed_at: hints.observed_at,
            expires_at: hints.expires_at,
        },
    }
}

fn fallback_needed(mesh: &Mesh, owner: Option<&str>) -> bool {
    !owner.is_some_and(|peer| {
        mesh.active_tcp
            .lock()
            .expect("TCP path lock poisoned")
            .contains_key(peer)
    })
}

pub(super) fn validate_hints(
    hints: &mycelium_peer_protocol::SyncHints,
    origin: &str,
) -> Result<(), String> {
    if hints.node_id != origin {
        return Err("sync hints owner mismatch".into());
    }
    // Freshness is checked at selection, not merge: expired observations may
    // transit retained gossip without acquiring a new lease.
    rendezvous_from_hints(hints).validate(None)
}

async fn candidates(
    mesh: &Mesh,
    seeds: &[SyncRendezvous],
    at: u64,
) -> BTreeMap<String, (Option<String>, SyncRendezvous)> {
    let observations = mesh.observations.lock().await;
    let mut result: BTreeMap<_, _> = seeds
        .iter()
        .map(|seed| {
            let owner = observations
                .values()
                .find_map(|envelope| match &envelope.event {
                    PeerEvent::Transport(binding)
                        if binding.kind == TransportKind::Iroh
                            && binding.public_key == seed.endpoint.endpoint_id
                            && binding.valid_until.is_none_or(|expiry| expiry > at) =>
                    {
                        Some(envelope.origin.clone())
                    }
                    _ => None,
                });
            (seed.endpoint.endpoint_id.clone(), (owner, seed.clone()))
        })
        .collect();
    for envelope in observations.values() {
        let PeerEvent::SyncHints(hints) = &envelope.event else {
            continue;
        };
        if envelope.origin == mesh.node_id() || validate_hints(hints, &envelope.origin).is_err() {
            continue;
        }
        let rendezvous = rendezvous_from_hints(hints);
        if rendezvous.validate(Some(at)).is_err() {
            continue;
        }
        // A signed hint alone is not an endpoint-key binding.
        let bound = observations.values().any(|binding| {
            binding.origin == envelope.origin
                && matches!(&binding.event, PeerEvent::Transport(value)
                if value.kind == TransportKind::Iroh && value.public_key == hints.endpoint_id
                    && value.valid_until.is_none_or(|expiry| expiry > at))
        });
        if bound {
            result.insert(
                hints.endpoint_id.clone(),
                (Some(envelope.origin.clone()), rendezvous),
            );
        }
    }
    result
}

async fn dial_once(
    mesh: Arc<Mesh>,
    endpoint: Endpoint,
    connector: TlsConnector,
    seed: SyncRendezvous,
) -> Result<(), AnyError> {
    let connection =
        tokio::time::timeout(HANDSHAKE, endpoint.connect(seed.address()?, ALPN)).await??;
    let (send, recv) = tokio::time::timeout(HANDSHAKE, connection.open_bi()).await??;
    let stream = tokio::time::timeout(
        HANDSHAKE,
        connector.connect(
            ServerName::try_from(seed.server_name)?,
            tokio::io::join(recv, send),
        ),
    )
    .await??;
    let fingerprint = tls_peer_fingerprint(stream.get_ref().1.peer_certificates());
    mesh.run_bound_stream(
        stream,
        fingerprint,
        None,
        Some(connection.remote_id().to_string()),
    )
    .await
}

/// Explicit persistent seed configuration; changes take effect on restart.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SyncConfig {
    /// Public relays are opt-in. No public DNS address publication is enabled.
    #[serde(default)]
    pub public_relays: bool,
    #[serde(default)]
    pub seeds: Vec<SyncRendezvous>,
}

/// Public, expiring connection hints. This is NOT an enrollment claim.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SyncRendezvous {
    pub endpoint: mycelium_iroh_discovery::Endpoint,
    /// Must match an existing peer certificate SAN; never disable verification.
    pub server_name: String,
}

impl SyncRendezvous {
    pub fn validate(&self, at: Option<u64>) -> Result<(), String> {
        self.endpoint.validate()?;
        if !self
            .endpoint
            .alpns
            .contains(std::str::from_utf8(ALPN).unwrap())
        {
            return Err("rendezvous does not support Mycelium sync".into());
        }
        if self.endpoint.direct_addresses.is_empty() && self.endpoint.relay_urls.is_empty() {
            return Err("rendezvous has no reachable address hints".into());
        }
        if self.server_name.len() > 253 || ServerName::try_from(self.server_name.clone()).is_err() {
            return Err("invalid TLS server name".into());
        }
        if let Some(at) = at {
            if self.endpoint.observed_at > at || self.endpoint.expires_at <= at {
                return Err(format!(
                    "rendezvous is not fresh (observed_at {}, expires_at {}, now {}); \
                     a fresh rendezvous is published every 30 seconds by a running Iroh sync \
                     runtime, and there is no manual export that regenerates one — if this is \
                     your own peer, check that myceliumd is running with Iroh sync enabled \
                     and MYCELIUM_IROH_SERVER_NAME set in its environment, and see \
                     'Iroh rendezvous refresh' errors in daemon.log",
                    self.endpoint.observed_at, self.endpoint.expires_at, at
                ));
            }
        }
        Ok(())
    }

    fn address(&self) -> Result<EndpointAddr, AnyError> {
        let mut addr = EndpointAddr::new(self.endpoint.endpoint_id.parse()?);
        for ip in &self.endpoint.direct_addresses {
            addr = addr.with_ip_addr(*ip);
        }
        for relay in &self.endpoint.relay_urls {
            addr = addr.with_relay_url(relay.parse()?);
        }
        Ok(addr)
    }
}

impl SyncConfig {
    pub fn validate(&self) -> Result<(), String> {
        if self.seeds.len() > LIMIT {
            return Err("at most 32 Iroh seeds are allowed".into());
        }
        let mut ids = BTreeSet::new();
        for seed in &self.seeds {
            seed.validate(None)?;
            if !ids.insert(&seed.endpoint.endpoint_id) {
                return Err("duplicate Iroh endpoint".into());
            }
        }
        Ok(())
    }
}

fn read_bounded(path: &std::path::Path) -> Result<Vec<u8>, AnyError> {
    let mut data = Vec::new();
    std::fs::File::open(path)?
        .take(65537)
        .read_to_end(&mut data)?;
    if data.len() > 65536 {
        return Err("Iroh configuration exceeds 64 KiB".into());
    }
    Ok(data)
}

pub(crate) fn transport_key(path: &std::path::Path) -> Result<SecretKey, AnyError> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
    {
        Ok(mut file) => {
            let key = SecretKey::generate();
            file.write_all(&key.to_bytes())?;
            file.sync_all()?;
            Ok(key)
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            if std::fs::symlink_metadata(path)?.file_type().is_symlink()
                || std::fs::metadata(path)?.permissions().mode() & 0o077 != 0
            {
                return Err("Iroh transport key must be a private regular file (0600)".into());
            }
            let bytes: [u8; 32] = read_bounded(path)?
                .try_into()
                .map_err(|_| "Iroh transport key must contain exactly 32 bytes")?;
            Ok(SecretKey::from_bytes(&bytes))
        }
        Err(error) => Err(error.into()),
    }
}

fn portable_addresses(
    addresses: impl Iterator<Item = std::net::SocketAddr>,
    preferred: &BTreeSet<std::net::IpAddr>,
) -> BTreeSet<std::net::SocketAddr> {
    let mut addresses: BTreeSet<_> = addresses
        .filter(|address| match address.ip() {
            std::net::IpAddr::V4(ip) => !ip.is_link_local(),
            std::net::IpAddr::V6(ip) => !ip.is_unicast_link_local(),
        })
        .collect();
    if addresses.len() > 16 {
        eprintln!(
            "myceliumd: Iroh connection hints bounded to 16 of {} portable addresses",
            addresses.len()
        );
        let mut ranked: Vec<_> = addresses.into_iter().collect();
        ranked.sort_by_key(|address| (!preferred.contains(&address.ip()), *address));
        addresses = ranked.into_iter().take(16).collect();
    }
    addresses
}

pub(super) async fn start(mesh: Arc<Mesh>, tls: &TlsSettings) -> Result<(), AnyError> {
    let home = crate::home_dir();
    let path = home.join("iroh-sync.json");
    if !path.exists() {
        return Ok(());
    }
    let config: SyncConfig = serde_json::from_slice(&read_bounded(&path)?)?;
    config.validate()?;
    let server_name = std::env::var("MYCELIUM_IROH_SERVER_NAME").map_err(|_| {
        "MYCELIUM_IROH_SERVER_NAME is unset: it must name this node's certificate SAN (for \
         example mac-studio.wagar-house.myc). Run 'mycelium setup --repair' to recover it from \
         the certificate, then restart myceliumd"
    })?;
    ServerName::try_from(server_name.clone())?;
    let port: u16 = match std::env::var("MYCELIUM_IROH_PORT") {
        Ok(value) => value.parse()?,
        Err(std::env::VarError::NotPresent) => 7444,
        Err(error) => return Err(error.into()),
    };
    if port == 0 {
        return Err("Iroh sync requires a stable nonzero UDP port".into());
    }
    let preferred: BTreeSet<_> = mesh
        .hello
        .interfaces
        .iter()
        .filter(|interface| {
            !["veth", "docker", "br-", "sh-"]
                .iter()
                .any(|prefix| interface.name.starts_with(prefix))
        })
        .flat_map(|interface| interface.addresses.iter().copied())
        .collect();
    let builder = Endpoint::builder(iroh::endpoint::presets::N0)
        .secret_key(transport_key(&home.join("iroh-secret.key"))?)
        .clear_ip_transports()
        .bind_addr(format!("0.0.0.0:{port}"))?
        .bind_addr_with_opts(
            format!("[::]:{port}"),
            iroh::endpoint::BindOpts::default().set_is_required(false),
        )?
        .clear_address_lookup()
        .portmapper_config(iroh::endpoint::PortmapperConfig::Disabled)
        .transport_config(
            iroh::endpoint::QuicTransportConfig::builder()
                .max_concurrent_bidi_streams(1u8.into())
                .max_concurrent_uni_streams(0u8.into())
                .build(),
        )
        .alpns(vec![ALPN.to_vec()]);
    let builder = if config.public_relays {
        builder
    } else {
        builder.relay_mode(iroh::RelayMode::Disabled)
    };
    let endpoint = builder.bind().await?;
    let mut hello = mesh.local_hello().await;
    hello.capabilities.push("transport.iroh-key-binding".into());
    mesh.publish(PeerEvent::Hello(hello)).await?;
    mesh.publish(PeerEvent::Transport(TransportCredentialBinding {
        node_id: mesh.hello.node_id.clone(),
        kind: TransportKind::Iroh,
        public_key: endpoint.id().to_string(),
        generation: now(),
        valid_until: None,
    }))
    .await?;
    let acceptor = TlsAcceptor::from(Arc::new(tls.server_config()?));
    let connector = TlsConnector::from(Arc::new(tls.client_config()?));
    let permits = Arc::new(tokio::sync::Semaphore::new(LIMIT));
    let listener = endpoint.clone();
    let incoming_mesh = mesh.clone();
    tokio::spawn(async move {
        while let Some(incoming) = listener.accept().await {
            let Ok(permit) = permits.clone().try_acquire_owned() else {
                incoming.refuse();
                continue;
            };
            let mesh = incoming_mesh.clone();
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let _permit = permit;
                let result: Result<(), AnyError> = async {
                    let connection = tokio::time::timeout(HANDSHAKE, incoming).await??;
                    let (send, recv) =
                        tokio::time::timeout(HANDSHAKE, connection.accept_bi()).await??;
                    let stream = tokio::time::timeout(
                        HANDSHAKE,
                        acceptor.accept(tokio::io::join(recv, send)),
                    )
                    .await??;
                    let fingerprint = tls_peer_fingerprint(stream.get_ref().1.peer_certificates());
                    mesh.run_bound_stream(
                        stream,
                        fingerprint,
                        None,
                        Some(connection.remote_id().to_string()),
                    )
                    .await
                }
                .await;
                if let Err(error) = result {
                    eprintln!("myceliumd: Iroh incoming sync: {error}");
                }
            });
        }
    });
    let outgoing_mesh = mesh.clone();
    let outgoing_endpoint = endpoint.clone();
    tokio::spawn(async move {
        let mut running = BTreeMap::<String, tokio::task::JoinHandle<Result<(), AnyError>>>::new();
        let mut retries = BTreeMap::<String, (u64, u64)>::new();
        let configured: BTreeSet<_> = config
            .seeds
            .iter()
            .map(|seed| seed.endpoint.endpoint_id.clone())
            .collect();
        // Give the concurrently starting TCP connector first opportunity.
        tokio::time::sleep(Duration::from_secs(5)).await;
        loop {
            let at = now();
            let finished: Vec<_> = running
                .iter()
                .filter(|(_, task)| task.is_finished())
                .map(|(id, _)| id.clone())
                .collect();
            for id in finished {
                let task = running.remove(&id).unwrap();
                match task.await {
                    Ok(Ok(())) => {
                        retries.insert(id, (at + 5, 5));
                    }
                    result => {
                        eprintln!("myceliumd: Iroh fallback {id}: {result:?}");
                        let delay = retries.get(&id).map_or(5, |(_, delay)| (delay * 2).min(60));
                        retries.insert(id, (at + delay, delay));
                    }
                }
            }
            let candidates = candidates(&outgoing_mesh, &config.seeds, at).await;
            retries.retain(|id, _| candidates.contains_key(id) || running.contains_key(id));
            for (id, (owner, mut seed)) in candidates {
                if running.len() >= LIMIT {
                    break;
                }
                if running.contains_key(&id) || retries.get(&id).is_some_and(|(next, _)| *next > at)
                {
                    continue;
                }
                // Discovery adds sparse repair edges, not an all-to-all mesh.
                if !configured.contains(&id)
                    && running
                        .keys()
                        .filter(|key| !configured.contains(*key))
                        .count()
                        >= DISCOVERED_LINK_LIMIT
                {
                    continue;
                }
                if !fallback_needed(&outgoing_mesh, owner.as_deref()) {
                    continue;
                }
                if !config.public_relays {
                    seed.endpoint.relay_urls.clear();
                }
                if seed.validate(None).is_err() {
                    continue;
                }
                let mesh = outgoing_mesh.clone();
                let endpoint = outgoing_endpoint.clone();
                let connector = connector.clone();
                running.insert(id, tokio::spawn(dial_once(mesh, endpoint, connector, seed)));
            }
            tokio::time::sleep(Duration::from_secs(5)).await;
        }
    });
    tokio::spawn(async move {
        loop {
            let addr = endpoint.addr();
            let at = now();
            let rendezvous = SyncRendezvous {
                server_name: server_name.clone(),
                endpoint: mycelium_iroh_discovery::Endpoint {
                    id: "mycelium-sync".into(),
                    endpoint_id: addr.id.to_string(),
                    alpns: BTreeSet::from([String::from_utf8_lossy(ALPN).into_owned()]),
                    // Scoped link-local addresses cannot be dialed from a portable
                    // rendezvous. Container hosts can otherwise overflow the
                    // bounded discovery contract with per-veth IPv6 addresses.
                    direct_addresses: portable_addresses(addr.ip_addrs().copied(), &preferred),
                    relay_urls: addr.relay_urls().map(ToString::to_string).collect(),
                    observed_at: at,
                    expires_at: at + 120,
                },
            };
            let result: Result<(), AnyError> = (|| {
                rendezvous.validate(Some(at))?;
                let temp = home.join("iroh-rendezvous.json.tmp");
                std::fs::write(&temp, serde_json::to_vec(&rendezvous)?)?;
                std::fs::rename(temp, home.join("iroh-rendezvous.json"))?;
                let document = mycelium_iroh_discovery::Document {
                    schema_version: 1,
                    endpoints: vec![rendezvous.endpoint.clone()],
                };
                let temp = home.join("iroh-sync-endpoints.json.tmp");
                std::fs::write(&temp, serde_json::to_vec(&document)?)?;
                std::fs::rename(temp, home.join("iroh-sync-endpoints.json"))?;
                Ok(())
            })();
            if let Err(error) = result {
                eprintln!("myceliumd: Iroh rendezvous refresh: {error}");
            } else if let Err(error) = mesh
                .publish(PeerEvent::SyncHints(mycelium_peer_protocol::SyncHints {
                    node_id: mesh.node_id().into(),
                    endpoint_id: rendezvous.endpoint.endpoint_id.clone(),
                    server_name: rendezvous.server_name.clone(),
                    direct_addresses: rendezvous.endpoint.direct_addresses.clone(),
                    relay_urls: rendezvous.endpoint.relay_urls.clone(),
                    observed_at: at,
                    expires_at: rendezvous.endpoint.expires_at,
                }))
                .await
            {
                eprintln!("myceliumd: Iroh hint gossip: {error}");
            }
            tokio::time::sleep(Duration::from_secs(30)).await;
        }
    });
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tcp_path_lifetime_controls_fallback() {
        let mesh = Mesh::ephemeral_for_test();
        assert!(fallback_needed(&mesh, Some("peer")));
        let first = TcpRegistration::new(&mesh.active_tcp, "peer".into());
        let second = TcpRegistration::new(&mesh.active_tcp, "peer".into());
        assert!(!fallback_needed(&mesh, Some("peer")));
        drop(first);
        assert!(!fallback_needed(&mesh, Some("peer")));
        drop(second);
        assert!(fallback_needed(&mesh, Some("peer")));
        assert!(fallback_needed(&mesh, None));
        assert!(mesh.active_tcp.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn stalled_write_releases_tcp_path_for_fallback() {
        let mesh = Mesh::ephemeral_for_test();
        let (mut writer, _unread_receiver) = tokio::io::duplex(1);
        let result: Result<(), AnyError> = async {
            let _registration = TcpRegistration::new(&mesh.active_tcp, "peer".into());
            assert!(!fallback_needed(&mesh, Some("peer")));
            send_with_timeout(
                &mut writer,
                &PeerMessage::Ping { sent_at: 1 },
                Duration::from_millis(5),
            )
            .await
        }
        .await;
        assert!(result.unwrap_err().to_string().contains("write timed out"));
        assert!(fallback_needed(&mesh, Some("peer")));
    }

    #[tokio::test]
    async fn discovery_requires_fresh_owner_hints_and_matching_binding() {
        let mesh = Mesh::ephemeral_for_test();
        let key = SigningKey::from_bytes(&[7; 32]);
        let owner = encode_hex(key.verifying_key().as_bytes());
        let r = rendezvous();
        let mut hints = mycelium_peer_protocol::SyncHints {
            node_id: owner.clone(),
            endpoint_id: r.endpoint.endpoint_id.clone(),
            server_name: r.server_name.clone(),
            direct_addresses: r.endpoint.direct_addresses.clone(),
            relay_urls: r.endpoint.relay_urls.clone(),
            observed_at: 100,
            expires_at: 130,
        };
        assert!(validate_hints(&hints, "another-owner").is_err());
        let envelope =
            SignedEnvelope::sign(&key, 1, 100, PeerEvent::SyncHints(hints.clone())).unwrap();
        envelope.verify().unwrap();
        mesh.observations
            .lock()
            .await
            .insert(event_key(&envelope), envelope);
        assert!(candidates(&mesh, &[], 110).await.is_empty());
        let binding = SignedEnvelope::sign(
            &key,
            2,
            100,
            PeerEvent::Transport(TransportCredentialBinding {
                node_id: owner.clone(),
                kind: TransportKind::Iroh,
                public_key: hints.endpoint_id.clone(),
                generation: 1,
                valid_until: None,
            }),
        )
        .unwrap();
        mesh.observations
            .lock()
            .await
            .insert(event_key(&binding), binding);
        let selected = candidates(&mesh, &[], 110).await;
        assert_eq!(selected.len(), 1);
        assert_eq!(
            selected.values().next().unwrap().0.as_deref(),
            Some(owner.as_str())
        );
        assert!(candidates(&mesh, &[], 99).await.is_empty());
        assert!(candidates(&mesh, &[], 130).await.is_empty());
        hints.endpoint_id = SecretKey::generate().public().to_string();
        let changed = SignedEnvelope::sign(&key, 3, 110, PeerEvent::SyncHints(hints)).unwrap();
        mesh.observations
            .lock()
            .await
            .insert(event_key(&changed), changed);
        assert!(candidates(&mesh, &[], 110).await.is_empty());
        // Saved bootstrap seeds remain dialable, but never get a new lease.
        assert_eq!(candidates(&mesh, &[r], 1000).await.len(), 1);
    }

    #[tokio::test]
    async fn signed_endpoint_binding_rejects_substitution() {
        let mesh = Mesh::ephemeral_for_test();
        let endpoint = SecretKey::generate().public().to_string();
        mesh.publish(PeerEvent::Transport(TransportCredentialBinding {
            node_id: mesh.node_id().to_owned(),
            kind: TransportKind::Iroh,
            public_key: endpoint.clone(),
            generation: 1,
            valid_until: None,
        }))
        .await
        .unwrap();
        let binding = PeerEvent::Transport(TransportCredentialBinding {
            node_id: mesh.node_id().to_owned(),
            kind: TransportKind::Iroh,
            public_key: endpoint.clone(),
            generation: 1,
            valid_until: None,
        });
        assert!(!transport_event_supported(&binding, false));
        assert!(transport_event_supported(&binding, true));
        assert!(mesh
            .local_hello()
            .await
            .capabilities
            .iter()
            .any(|capability| capability == "transport.iroh-key-binding"));
        assert!(
            mesh.has_transport_binding(mesh.node_id(), TransportKind::Iroh, &endpoint)
                .await
        );
        assert!(
            !mesh
                .has_transport_binding(
                    mesh.node_id(),
                    TransportKind::Iroh,
                    &SecretKey::generate().public().to_string()
                )
                .await
        );
        assert!(
            !mesh
                .has_transport_binding("another-peer", TransportKind::Iroh, &endpoint)
                .await
        );
        assert!(
            !mesh
                .has_transport_binding(mesh.node_id(), TransportKind::Mtls, &endpoint)
                .await
        );
    }

    #[test]
    fn portable_hints_drop_scoped_addresses_and_stay_bounded() {
        let mut input: Vec<std::net::SocketAddr> = (1..=20)
            .map(|n| format!("192.168.1.{n}:7443").parse().unwrap())
            .collect();
        input.push("[fe80::1]:7443".parse().unwrap());
        input.push("169.254.1.1:7443".parse().unwrap());
        let preferred = BTreeSet::from(["192.168.1.20".parse().unwrap()]);
        let result = portable_addresses(input.into_iter(), &preferred);
        assert_eq!(result.len(), 16);
        assert!(result.contains(&"192.168.1.20:7443".parse().unwrap()));
        assert!(result.iter().all(|address| address.ip().is_ipv4()));
        assert!(!result.contains(&"169.254.1.1:7443".parse().unwrap()));
        assert_eq!(
            portable_addresses(
                ["127.0.0.1:7443".parse().unwrap()].into_iter(),
                &BTreeSet::new()
            )
            .len(),
            1
        );
    }

    fn rendezvous() -> SyncRendezvous {
        SyncRendezvous {
            server_name: "peer.test".into(),
            endpoint: mycelium_iroh_discovery::Endpoint {
                id: "sync".into(),
                endpoint_id: SecretKey::generate().public().to_string(),
                alpns: BTreeSet::from(["mycelium/sync/1".into()]),
                direct_addresses: BTreeSet::from(["127.0.0.1:12345".parse().unwrap()]),
                relay_urls: BTreeSet::new(),
                observed_at: 100,
                expires_at: 220,
            },
        }
    }

    #[test]
    fn import_bounds_and_freshness() {
        let mut r = rendezvous();
        assert!(r.validate(Some(150)).is_ok());
        assert!(r.validate(Some(220)).is_err());
        assert!(r.validate(Some(99)).is_err());
        // Explicit saved connection hints do not claim continuing observation freshness.
        assert!(r.validate(None).is_ok());
        r.server_name = "bad name".into();
        assert!(r.validate(None).is_err());
        let r = rendezvous();
        assert!(SyncConfig {
            public_relays: false,
            seeds: vec![r.clone(), r]
        }
        .validate()
        .is_err());
        assert!(serde_json::from_str::<SyncConfig>(r#"{"ssh_access":true}"#).is_err());
    }

    #[test]
    fn stable_private_transport_key() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!(
            "mycelium-iroh-key-{}-{}",
            std::process::id(),
            SecretKey::generate().public()
        ));
        std::fs::create_dir(&dir).unwrap();
        let path = dir.join("secret");
        let key = transport_key(&path).unwrap();
        assert_eq!(key.public(), transport_key(&path).unwrap().public());
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(transport_key(&path).is_err());
        std::fs::remove_dir_all(dir).unwrap();
    }

    fn tls_pair() -> (TlsAcceptor, TlsConnector) {
        use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair};
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let mut params = CertificateParams::new(vec!["ca.test".into()]).unwrap();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let ca_key = KeyPair::generate().unwrap();
        let ca = params.self_signed(&ca_key).unwrap();
        let leaf_key = KeyPair::generate().unwrap();
        let leaf = CertificateParams::new(vec!["peer.test".into()])
            .unwrap()
            .signed_by(&leaf_key, &ca, &ca_key)
            .unwrap();
        let mut roots = RootCertStore::empty();
        roots.add(ca.der().clone()).unwrap();
        let key = || PrivateKeyDer::Pkcs8(leaf_key.serialize_der().into());
        let server = ServerConfig::builder()
            .with_client_cert_verifier(
                WebPkiClientVerifier::builder(Arc::new(roots.clone()))
                    .build()
                    .unwrap(),
            )
            .with_single_cert(vec![leaf.der().clone()], key())
            .unwrap();
        let client = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_client_auth_cert(vec![leaf.der().clone()], key())
            .unwrap();
        (
            TlsAcceptor::from(Arc::new(server)),
            TlsConnector::from(Arc::new(client)),
        )
    }

    async fn local_endpoint() -> Endpoint {
        Endpoint::builder(iroh::endpoint::presets::N0)
            .clear_address_lookup()
            .relay_mode(iroh::RelayMode::Disabled)
            .portmapper_config(iroh::endpoint::PortmapperConfig::Disabled)
            .clear_ip_transports()
            .bind_addr("127.0.0.1:0")
            .unwrap()
            .alpns(vec![ALPN.to_vec()])
            .bind()
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn signed_gossip_over_mutually_authenticated_iroh() {
        let server = local_endpoint().await;
        let client = local_endpoint().await;
        let (acceptor, connector) = tls_pair();
        let receiver = server.clone();
        let task = tokio::spawn(async move {
            let connection = receiver.accept().await.unwrap().await.unwrap();
            let (send_stream, recv) = connection.accept_bi().await.unwrap();
            let stream = acceptor
                .accept(tokio::io::join(recv, send_stream))
                .await
                .unwrap();
            assert!(tls_peer_fingerprint(stream.get_ref().1.peer_certificates()).is_some());
            let mut reader = BufReader::new(stream);
            let line = next_peer_line(&mut reader, &mut Vec::new())
                .await
                .unwrap()
                .unwrap();
            let PeerMessage::Observations(values) = serde_json::from_str(&line).unwrap() else {
                panic!("wrong frame")
            };
            assert_eq!(values.len(), 1);
            values[0].verify().unwrap();
            send(reader.get_mut(), &PeerMessage::Ping { sent_at: 1 })
                .await
                .unwrap();
            // Keep the connection alive until delivery is acknowledged.
            assert!(next_peer_line(&mut reader, &mut Vec::new())
                .await
                .unwrap()
                .is_some());
        });
        let connection = client.connect(server.addr(), ALPN).await.unwrap();
        let (send_stream, recv) = connection.open_bi().await.unwrap();
        let mut stream = connector
            .connect(
                ServerName::try_from("peer.test").unwrap(),
                tokio::io::join(recv, send_stream),
            )
            .await
            .unwrap();
        assert!(tls_peer_fingerprint(stream.get_ref().1.peer_certificates()).is_some());
        let mesh = Mesh::ephemeral_for_test();
        let envelope =
            SignedEnvelope::sign(&mesh.key, 1, 1, PeerEvent::Hello(mesh.hello.clone())).unwrap();
        send(&mut stream, &PeerMessage::Observations(vec![envelope]))
            .await
            .unwrap();
        let mut reader = BufReader::new(stream);
        assert!(next_peer_line(&mut reader, &mut Vec::new())
            .await
            .unwrap()
            .unwrap()
            .contains("ping"));
        send(reader.get_mut(), &PeerMessage::Ping { sent_at: 2 })
            .await
            .unwrap();
        tokio::time::timeout(HANDSHAKE, task)
            .await
            .unwrap()
            .unwrap();
        client.close().await;
        server.close().await;
    }

    #[tokio::test]
    async fn wrong_tls_name_rejected_inside_iroh() {
        let server = local_endpoint().await;
        let client = local_endpoint().await;
        let (acceptor, connector) = tls_pair();
        let receiver = server.clone();
        let task = tokio::spawn(async move {
            let connection = receiver.accept().await.unwrap().await.unwrap();
            let (send, recv) = connection.accept_bi().await.unwrap();
            let _ = acceptor.accept(tokio::io::join(recv, send)).await;
        });
        let connection = client.connect(server.addr(), ALPN).await.unwrap();
        let (send, recv) = connection.open_bi().await.unwrap();
        assert!(connector
            .connect(
                ServerName::try_from("impostor.test").unwrap(),
                tokio::io::join(recv, send)
            )
            .await
            .is_err());
        task.abort();
        client.close().await;
        server.close().await;
    }
}
