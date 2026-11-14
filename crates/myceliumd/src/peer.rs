use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::io::BufReader as StdBufReader;
use std::io::{Read, Seek, SeekFrom, Write};
use std::net::IpAddr;
use std::path::Path;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ed25519_dalek::SigningKey;
use mycelium_peer_protocol::{
    decode_hex, encode_hex, local_build_target, local_compatible_targets, sha256_hex, AccessRecord,
    AccessStatement, AuthorityRecord, AuthorityStatement, EgressObservation, FilesystemHealth,
    HardwareSnapshot, HostHealth, PackageManifest, PeerEndpointObservation, PeerEvent, PeerHello,
    PeerInterface, PeerMessage, Platform, ProcessHealth, ReleaseManifest, SecurityEventBatch,
    SecurityPosture, SignedEnvelope, TopologySnapshot, TransportCredentialBinding, TransportKind,
    WireGuardBinding, MAX_SECURITY_EVENTS, MAX_SECURITY_FINDINGS, PROTOCOL_VERSION,
};
use rand_core::OsRng;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::server::WebPkiClientVerifier;
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use tokio_rustls::{TlsAcceptor, TlsConnector};

const HEALTH_INTERVAL: Duration = Duration::from_secs(60);
const SECURITY_INTERVAL: Duration = Duration::from_secs(15 * 60);
const HARDWARE_INTERVAL: Duration = Duration::from_secs(5 * 60);
const DIGEST_INTERVAL: Duration = Duration::from_secs(15);
const DEFAULT_ARTIFACT_REQUEST_INTERVAL: Duration = Duration::from_secs(5);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
/// A seed session must last this long before it resets the reconnect backoff.
const BACKOFF_RESET_SESSION: Duration = Duration::from_secs(30);
const PEER_IDLE_TIMEOUT: Duration = Duration::from_secs(45);
const MAX_OBSERVATIONS_PER_MESSAGE: usize = 64;
const MAX_OBSERVATION_MESSAGE_BYTES: usize = 900 * 1024;

type AnyError = Box<dyn Error + Send + Sync>;

#[cfg(feature = "iroh-sync")]
mod iroh_sync;
#[cfg(feature = "iroh-sync")]
pub(crate) use iroh_sync::transport_key;
#[cfg(feature = "iroh-sync")]
pub use iroh_sync::{SyncConfig, SyncRendezvous};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PeerView {
    pub origin: String,
    pub hello: Option<PeerHello>,
    pub health: Option<HostHealth>,
    pub hardware: Option<HardwareSnapshot>,
    pub transports: Vec<TransportCredentialBinding>,
    pub observed_endpoints: Vec<PeerEndpointObservation>,
    pub last_seen: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct AccessGrantView {
    pub record: AccessRecord,
    pub active: bool,
    pub revoked_by: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct AccessStateView {
    pub grants: Vec<AccessGrantView>,
    pub revocations: Vec<AccessRecord>,
}

#[derive(Clone, Debug, Serialize)]
pub struct SeededArtifact {
    pub artifact_digest: String,
    pub artifact_size: u64,
    pub already_present: bool,
    pub releases: Vec<ReleaseManifest>,
    pub packages: Vec<PackageManifest>,
}

#[derive(Debug, Deserialize)]
struct ReleaseSetFile {
    version: String,
    channel: String,
    artifacts: Vec<ReleaseSetArtifact>,
}

#[derive(Debug, Deserialize)]
struct ReleaseSetArtifact {
    target: String,
    binary: String,
}

pub struct Mesh {
    active_tcp: std::sync::Mutex<BTreeMap<String, usize>>,
    key: SigningKey,
    hello: PeerHello,
    sequence: AtomicU64,
    observations: Mutex<BTreeMap<String, SignedEnvelope>>,
    allowed_origins: Option<BTreeSet<String>>,
    authority_roots: BTreeSet<String>,
    trusted_release_keys: BTreeSet<String>,
    trusted_access_keys: BTreeSet<String>,
    require_transport_binding: bool,
}

impl Mesh {
    pub fn node_id(&self) -> &str {
        &self.hello.node_id
    }

    pub fn hostname(&self) -> &str {
        &self.hello.hostname
    }

    pub async fn local_hello(&self) -> PeerHello {
        let observations = self.observations.lock().await;
        let mut hello = observations
            .values()
            .find_map(|envelope| {
                if envelope.origin == self.node_id() {
                    if let PeerEvent::Hello(hello) = &envelope.event {
                        return Some(hello.clone());
                    }
                }
                None
            })
            .unwrap_or_else(|| self.hello.clone());
        // Negotiation follows the actual local binding, even when a bounded
        // inventory projection cannot retain the full Hello observation.
        if observations.values().any(|envelope| envelope.origin == self.node_id()
            && matches!(&envelope.event, PeerEvent::Transport(binding) if binding.kind == TransportKind::Iroh))
            && !hello.capabilities.iter().any(|capability| capability == "transport.iroh-key-binding")
        {
            hello.capabilities.push("transport.iroh-key-binding".into());
        }
        hello
    }

    /// Refresh public observations after a locally authorized rename/profile
    /// change. Neither the peer signing key nor transport credentials change.
    pub async fn refresh_local_hello(&self) -> Result<PeerHello, AnyError> {
        let mut hello = self.local_hello().await;
        let previous = hello.clone();
        let intent = crate::node_profile::read()?;
        if intent
            .as_ref()
            .is_some_and(|intent| intent.node_id != self.node_id())
        {
            return Err("local profile belongs to another peer".into());
        }
        hello.hostname = tokio::task::spawn_blocking(|| output("hostname", &["-s"]))
            .await??
            .trim()
            .to_owned();
        hello
            .capabilities
            .retain(|fact| !fact.starts_with("profile."));
        if let Some(intent) = intent {
            hello
                .capabilities
                .push(format!("profile.{}", intent.profile));
        }
        if hello != previous {
            self.publish(PeerEvent::Hello(hello.clone())).await?;
        }
        Ok(hello)
    }

    #[cfg(test)]
    pub fn ephemeral_for_test() -> Arc<Self> {
        let key = SigningKey::from_bytes(&[3; 32]);
        let node_id = encode_hex(key.verifying_key().as_bytes());
        Arc::new(Self {
            active_tcp: std::sync::Mutex::new(BTreeMap::new()),
            key,
            hello: PeerHello {
                node_id,
                protocol_version: PROTOCOL_VERSION,
                site: "test".into(),
                hostname: "test".into(),
                platform: Platform::Linux,
                architecture: "test".into(),
                daemon_version: crate::VERSION.into(),
                capabilities: vec![
                    "system.health".into(),
                    "security.posture".into(),
                    "transport.identity-binding".into(),
                ],
                interfaces: Vec::new(),
            },
            sequence: AtomicU64::new(0),
            observations: Mutex::new(BTreeMap::new()),
            allowed_origins: None,
            authority_roots: BTreeSet::new(),
            trusted_release_keys: BTreeSet::new(),
            trusted_access_keys: BTreeSet::new(),
            require_transport_binding: false,
        })
    }

    #[cfg(test)]
    pub async fn publish_ssh_peer_for_test(&self, hostname: &str, ssh_listening: bool) {
        let mut hello = self.hello.clone();
        hello.hostname = hostname.into();
        self.publish(PeerEvent::Hello(hello)).await.unwrap();
        self.publish(PeerEvent::Health(HostHealth {
            observed_at: now(),
            uptime_seconds: 1,
            load_average: [0.0; 3],
            logical_cpus: 1,
            memory_total_bytes: 1,
            memory_available_bytes: 1,
            swap_total_bytes: 0,
            swap_free_bytes: 0,
            filesystems: Vec::new(),
            process_leaders: Vec::new(),
            ssh_listening,
            established_ssh_sessions: 0,
            power: mycelium_peer_protocol::PowerSource::Unknown,
            link: mycelium_peer_protocol::LinkKind::Unknown,
            platform_metrics: BTreeMap::new(),
        }))
        .await
        .unwrap();
    }

    pub fn boot() -> Result<Arc<Self>, AnyError> {
        let key = load_or_create_key(&crate::peer_key_path())?;
        let node_id = encode_hex(key.verifying_key().as_bytes());
        let hostname = output("hostname", &["-s"])?.trim().to_owned();
        let site = std::env::var("MYCELIUM_SITE").unwrap_or_else(|_| hostname.clone());
        let capabilities = vec![
            "system.health".into(),
            "security.posture".into(),
            "transport.identity-binding".into(),
        ]
        .into_iter()
        .chain(raspberry_pi_capability())
        .chain(configured_node_facts())
        .collect();
        let hello = PeerHello {
            node_id,
            protocol_version: PROTOCOL_VERSION,
            site,
            hostname,
            platform: platform(),
            architecture: std::env::consts::ARCH.into(),
            daemon_version: crate::VERSION.into(),
            capabilities,
            interfaces: collect_interfaces(),
        };
        let allowed_origins = std::env::var("MYCELIUM_PEER_ALLOW").ok().map(|value| {
            value
                .split(',')
                .map(str::trim)
                .filter(|entry| !entry.is_empty())
                .map(str::to_owned)
                .collect::<BTreeSet<_>>()
        });
        let authority_roots = csv_set("MYCELIUM_AUTHORITY_KEYS");
        let trusted_release_keys = csv_set("MYCELIUM_RELEASE_KEYS");
        let trusted_access_keys = csv_set("MYCELIUM_ACCESS_KEYS");
        let require_transport_binding = std::env::var("MYCELIUM_REQUIRE_TRANSPORT_BINDING")
            .is_ok_and(|value| matches!(value.as_str(), "1" | "true" | "yes"));
        let observations = match std::fs::read_to_string(crate::peer_observations_path()) {
            Ok(text) => match serde_json::from_str::<Vec<SignedEnvelope>>(&text) {
                Ok(values) => validated_observations(
                    values,
                    &hello.node_id,
                    allowed_origins.as_ref(),
                    &authority_roots,
                    &trusted_access_keys,
                    &trusted_release_keys,
                ),
                Err(error) => {
                    // Peer observations are a cache: every entry is recoverable
                    // from its owner. Quarantine the unreadable file instead of
                    // refusing to boot, which would take every local service
                    // down with it and hide the real error behind a restart loop.
                    let path = crate::peer_observations_path();
                    let quarantine = path.with_extension(format!("json.corrupt-{}", now()));
                    std::fs::rename(&path, &quarantine)?;
                    eprintln!(
                        "myceliumd: quarantined unreadable peer observations at {}: {error}",
                        quarantine.display()
                    );
                    BTreeMap::new()
                }
            },
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => BTreeMap::new(),
            Err(error) => return Err(error.into()),
        };
        let sequence = observations
            .values()
            .filter(|envelope| envelope.origin == hello.node_id)
            .map(|envelope| envelope.sequence)
            .max()
            .unwrap_or(0);
        Ok(Arc::new(Self {
            active_tcp: std::sync::Mutex::new(BTreeMap::new()),
            key,
            hello,
            sequence: AtomicU64::new(sequence),
            observations: Mutex::new(observations),
            allowed_origins,
            authority_roots,
            trusted_release_keys,
            trusted_access_keys,
            require_transport_binding,
        }))
    }

    pub async fn start(self: &Arc<Self>) -> Result<(), AnyError> {
        self.publish(PeerEvent::Hello(self.hello.clone())).await?;
        self.refresh_local_hello().await?;
        let pulse_mesh = self.clone();
        tokio::spawn(async move {
            crate::pulse::run_system(pulse_mesh).await;
        });
        let collector = self.clone();
        tokio::spawn(async move {
            loop {
                match tokio::task::spawn_blocking(collect_health).await {
                    Ok(Ok(mut health)) => {
                        if let Some(release) = collector.preferred_release().await {
                            let ready = artifact_path(&release.artifact_digest)
                                .map(|path| path.is_file())
                                .unwrap_or(false);
                            health.platform_metrics.insert(
                                "mycelium_update.staged_digest".into(),
                                release.artifact_digest,
                            );
                            health
                                .platform_metrics
                                .insert("mycelium_update.staged_version".into(), release.version);
                            health.platform_metrics.insert(
                                "mycelium_update.staged_state".into(),
                                if ready { "ready" } else { "downloading" }.into(),
                            );
                        }
                        if let Err(error) = collector.publish(PeerEvent::Health(health)).await {
                            eprintln!("myceliumd: publish local health: {error}");
                        }
                    }
                    Ok(Err(error)) => eprintln!("myceliumd: collect local health: {error}"),
                    Err(error) => eprintln!("myceliumd: health task: {error}"),
                }
                tokio::time::sleep(HEALTH_INTERVAL).await;
            }
        });

        let security_collector = self.clone();
        tokio::spawn(async move {
            loop {
                if let Err(error) = security_collector
                    .collect_and_publish_security(None, None, false)
                    .await
                {
                    eprintln!("myceliumd: collect security posture: {error}");
                } else {
                    let events = security_collector.security_events().await;
                    if let Err(error) = crate::siem::export(&events, None, false, true).await {
                        eprintln!("myceliumd: export security events: {error}");
                    }
                }
                tokio::time::sleep(SECURITY_INTERVAL).await;
            }
        });

        let hardware_collector = self.clone();
        tokio::spawn(async move {
            loop {
                let hello = hardware_collector.local_hello().await;
                match tokio::task::spawn_blocking(move || crate::hardware::collect(&hello)).await {
                    Ok(Ok(snapshot)) => {
                        if let Err(error) = hardware_collector
                            .publish(PeerEvent::Hardware(snapshot))
                            .await
                        {
                            eprintln!("myceliumd: publish hardware inventory: {error}");
                        }
                    }
                    Ok(Err(error)) => eprintln!("myceliumd: collect hardware inventory: {error}"),
                    Err(error) => eprintln!("myceliumd: hardware inventory task: {error}"),
                }
                tokio::time::sleep(HARDWARE_INTERVAL).await;
            }
        });

        if let Some(tls) = TlsSettings::from_env()? {
            self.publish(PeerEvent::Transport(
                tls.identity_binding(&self.hello.node_id)?,
            ))
            .await?;
            let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
            #[cfg(feature = "iroh-sync")]
            if let Err(error) = iroh_sync::start(self.clone(), &tls).await {
                // Iroh sync is a fallback/repair transport. A sync runtime
                // that cannot start (for example because
                // MYCELIUM_IROH_SERVER_NAME is missing from the daemon
                // environment) must not take the peer itself down: TCP
                // gossip and the peer listener still run. The failure stays
                // visible in the daemon log instead of aborting startup.
                eprintln!("myceliumd: Iroh sync unavailable; continuing without it: {error}");
            }
            if let Some(address) = tls.listen.clone() {
                let mesh = self.clone();
                let acceptor = TlsAcceptor::from(Arc::new(tls.server_config()?));
                tokio::spawn(async move {
                    if let Err(error) = mesh.listen(&address, acceptor).await {
                        eprintln!("myceliumd: peer listener failed: {error}");
                    }
                });
            }
            for seed in &tls.seeds {
                let mesh = self.clone();
                let seed = seed.clone();
                let connector = TlsConnector::from(Arc::new(tls.client_config()?));
                tokio::spawn(async move { mesh.dial_forever(seed, connector).await });
            }
        }
        Ok(())
    }

    pub async fn views(&self) -> Vec<PeerView> {
        let observations = self.observations.lock().await;
        let mut views = BTreeMap::<String, PeerView>::new();
        let mut endpoints = Vec::new();
        for envelope in observations.values() {
            let view = views.entry(envelope.origin.clone()).or_insert(PeerView {
                origin: envelope.origin.clone(),
                hello: None,
                health: None,
                hardware: None,
                transports: Vec::new(),
                observed_endpoints: Vec::new(),
                last_seen: 0,
            });
            view.last_seen = view.last_seen.max(envelope.emitted_at);
            match &envelope.event {
                PeerEvent::Hello(hello) => view.hello = Some(hello.clone()),
                PeerEvent::Health(health) => view.health = Some(health.clone()),
                PeerEvent::Topology(_) => {}
                PeerEvent::Release(_) => {}
                PeerEvent::Package(_) => {}
                PeerEvent::Authority(_) => {}
                PeerEvent::Endpoint(endpoint) => endpoints.push(endpoint.clone()),
                PeerEvent::Egress(_) => {}
                PeerEvent::Access(_) => {}
                PeerEvent::SshCredentialRequest(_) | PeerEvent::SshCredentialResponses(_) => {}
                PeerEvent::Transport(binding) => view.transports.push(binding.clone()),
                PeerEvent::WireGuard(binding) => view.transports.push(binding.credential.clone()),
                PeerEvent::Hardware(snapshot) => view.hardware = Some(snapshot.clone()),
                PeerEvent::SecurityPosture(_) => {}
                PeerEvent::SecurityEvents(_) => {}
                PeerEvent::Unknown => {}
                PeerEvent::SyncHints(_) => {}
            }
        }
        for endpoint in endpoints {
            if let Some(view) = views.get_mut(&endpoint.peer) {
                view.observed_endpoints.push(endpoint);
            }
        }
        views.into_values().collect()
    }

    pub async fn releases(&self) -> Vec<ReleaseManifest> {
        let observations = self.observations.lock().await;
        let records = authority_records_from(&observations);
        let resolver = crate::authority::AuthorityResolver::new(
            &self.authority_roots,
            &self.trusted_access_keys,
            &self.trusted_release_keys,
            records.iter(),
            now(),
        );
        observations
            .values()
            .filter_map(|envelope| match &envelope.event {
                PeerEvent::Release(release) if resolver.release(&release.signer).authorized => {
                    Some(release.clone())
                }
                _ => None,
            })
            .collect()
    }

    pub async fn packages(&self) -> Vec<PackageManifest> {
        let observations = self.observations.lock().await;
        let records = authority_records_from(&observations);
        let resolver = crate::authority::AuthorityResolver::new(
            &self.authority_roots,
            &self.trusted_access_keys,
            &self.trusted_release_keys,
            records.iter(),
            now(),
        );
        observations
            .values()
            .filter_map(|envelope| match &envelope.event {
                PeerEvent::Package(package) if resolver.package(package).authorized => {
                    Some(package.clone())
                }
                _ => None,
            })
            .collect()
    }

    pub async fn wireguard_bindings(&self) -> Vec<WireGuardBinding> {
        self.observations
            .lock()
            .await
            .values()
            .filter_map(|envelope| match &envelope.event {
                PeerEvent::WireGuard(binding) => Some(binding.clone()),
                _ => None,
            })
            .collect()
    }

    /// Expiring iroh connection hints per owning peer, for the service proxy's
    /// resolver. Hints nominate a path only; they never grant access.
    pub async fn sync_hints(&self) -> Vec<mycelium_peer_protocol::SyncHints> {
        self.observations
            .lock()
            .await
            .values()
            .filter_map(|envelope| match &envelope.event {
                PeerEvent::SyncHints(hints) => Some(hints.clone()),
                _ => None,
            })
            .collect()
    }

    pub async fn egress_observations(&self) -> Vec<EgressObservation> {
        self.observations
            .lock()
            .await
            .values()
            .filter_map(|envelope| match &envelope.event {
                PeerEvent::Egress(value) => Some(value.clone()),
                _ => None,
            })
            .collect()
    }

    pub async fn publish_egress(&self, value: EgressObservation) -> Result<(), AnyError> {
        if value.node_id != self.hello.node_id {
            return Err("egress observation must describe the local peer".into());
        }
        self.publish(PeerEvent::Egress(value)).await
    }

    pub async fn hardware_snapshots(&self) -> Vec<HardwareSnapshot> {
        self.observations
            .lock()
            .await
            .values()
            .filter_map(|envelope| match &envelope.event {
                PeerEvent::Hardware(snapshot) => Some(snapshot.clone()),
                _ => None,
            })
            .collect()
    }

    async fn has_transport_binding(
        &self,
        node_id: &str,
        kind: TransportKind,
        public_key: &str,
    ) -> bool {
        self.observations.lock().await.values().any(|envelope| {
            envelope.origin == node_id
                && matches!(
                    &envelope.event,
                    PeerEvent::Transport(binding)
                        if binding.kind == kind && binding.public_key == public_key
                )
        })
    }

    pub async fn security_postures(&self) -> Vec<SecurityPosture> {
        self.observations
            .lock()
            .await
            .values()
            .filter_map(|envelope| match &envelope.event {
                PeerEvent::SecurityPosture(posture) => Some(posture.clone()),
                _ => None,
            })
            .collect()
    }

    pub async fn security_events(&self) -> Vec<SecurityEventBatch> {
        self.observations
            .lock()
            .await
            .values()
            .filter_map(|envelope| match &envelope.event {
                PeerEvent::SecurityEvents(events) => Some(events.clone()),
                _ => None,
            })
            .collect()
    }

    pub async fn collect_and_publish_security(
        &self,
        stig_content: Option<String>,
        stig_profile: Option<String>,
        remediation_plan: bool,
    ) -> Result<SecurityPosture, AnyError> {
        let hello = self.local_hello().await;
        let (posture, events) = tokio::task::spawn_blocking(move || {
            let stig = match (stig_content.as_deref(), stig_profile.as_deref()) {
                (Some(content), Some(profile)) => Some(crate::security::StigScan {
                    content,
                    profile,
                    remediation_plan,
                }),
                (None, None) => None,
                _ => return Err("STIG scanning requires both content and profile".into()),
            };
            crate::security::collect(&hello, stig)
        })
        .await??;
        self.publish(PeerEvent::SecurityPosture(posture.clone()))
            .await?;
        self.publish(PeerEvent::SecurityEvents(events)).await?;
        Ok(posture)
    }

    pub async fn publish_wireguard_binding(
        &self,
        public_key: String,
        endpoint: Option<String>,
        advertised_prefixes: Vec<String>,
    ) -> Result<WireGuardBinding, AnyError> {
        let binding = WireGuardBinding {
            credential: TransportCredentialBinding {
                node_id: self.hello.node_id.clone(),
                kind: TransportKind::WireGuard,
                public_key,
                generation: now(),
                valid_until: None,
            },
            hostname: self.hello.hostname.clone(),
            site: self.hello.site.clone(),
            endpoint,
            advertised_prefixes,
        };
        self.publish(PeerEvent::WireGuard(binding.clone())).await?;
        Ok(binding)
    }

    pub async fn topology_snapshots(&self) -> Vec<TopologySnapshot> {
        self.observations
            .lock()
            .await
            .values()
            .filter(|envelope| envelope.origin != self.hello.node_id)
            .filter_map(|envelope| match &envelope.event {
                PeerEvent::Topology(snapshot) => Some(snapshot.clone()),
                _ => None,
            })
            .collect()
    }

    pub async fn publish_topology(
        &self,
        topology: &mycelium_core::Topology,
    ) -> Result<(), AnyError> {
        self.publish(PeerEvent::Topology(TopologySnapshot {
            schema_version: 1,
            topology: serde_json::to_value(topology)?,
        }))
        .await
    }

    /// First byte of the node key, used to derive a stable startup offset for
    /// system pulses. The scheduler must not read the key for any other reason.
    pub(crate) fn pulse_seed(&self) -> u64 {
        self.key.to_bytes()[0] as u64
    }

    /// A single worker owns renewal state. Requests are one retained slot per
    /// peer; responses are one bounded batch per issuer, independent of the
    /// current direct/relay transport and connection count.
    pub async fn renew_ssh_credentials(&self) -> Result<(), AnyError> {
        let at = now();
        let key = self.key.clone();
        let pending =
            tokio::task::spawn_blocking(move || crate::ssh_renewal::renewal_request(&key, at))
                .await??;
        if let Some(request) = &pending {
            let already_published = self.observations.lock().await.values().any(|e| matches!(&e.event,PeerEvent::SshCredentialRequest(old) if e.origin == self.hello.node_id && old == request));
            if !already_published {
                self.publish(PeerEvent::SshCredentialRequest(request.clone()))
                    .await?;
            }
        }
        // Catch-up for a response that arrived before this process started: the
        // live path is `merge`, which installs on arrival.
        self.install_pending_ssh_renewal(at).await?;
        let snapshot: Vec<_> = self
            .observations
            .lock()
            .await
            .values()
            .filter(|e| {
                matches!(
                    e.event,
                    PeerEvent::SshCredentialRequest(_) | PeerEvent::SshCredentialResponses(_)
                )
            })
            .cloned()
            .collect();
        self.issue_ssh_responses(at, &snapshot).await
    }

    /// Install the response to the request this node is waiting on, if a
    /// gossiped response answers it. Returns whether a certificate was
    /// installed.
    ///
    /// This runs when a response is merged, not only on the renewal pulse: the
    /// pulse is half an hour apart, and the request it answers is only accepted
    /// for five minutes.
    async fn install_pending_ssh_renewal(&self, at: u64) -> Result<bool, AnyError> {
        let key = self.key.clone();
        let Some(request) =
            tokio::task::spawn_blocking(move || crate::ssh_renewal::pending(&key, at)).await??
        else {
            return Ok(false);
        };
        let snapshot: Vec<_> = self
            .observations
            .lock()
            .await
            .values()
            .filter(|e| matches!(e.event, PeerEvent::SshCredentialResponses(_)))
            .cloned()
            .collect();
        for envelope in &snapshot {
            let PeerEvent::SshCredentialResponses(deliveries) = &envelope.event else {
                continue;
            };
            for delivery in deliveries.iter().filter(|d| {
                d.node_id == self.hello.node_id
                    && d.response.request_id == request.request_id
                    && d.response.certificate.is_some()
            }) {
                let response = delivery.response.clone();
                match tokio::task::spawn_blocking(move || {
                    crate::ssh_renewal::install(&response, at)
                })
                .await?
                {
                    Ok(()) => {
                        eprintln!(
                            "myceliumd: installed CA-verified renewed SSH certificate from {}",
                            envelope.origin
                        );
                        return Ok(true);
                    }
                    Err(error) => {
                        eprintln!("myceliumd: reject gossiped SSH credential: {error}")
                    }
                }
            }
        }
        Ok(false)
    }

    /// The issuer half of SSH renewal. This must run inside the five-minute
    /// request acceptance window, so it is a fast system pulse of its own; the
    /// certificate check that creates a new request runs much less often.
    pub async fn serve_ssh_renewal(&self) -> Result<(), AnyError> {
        let at = now();
        let snapshot: Vec<_> = self
            .observations
            .lock()
            .await
            .values()
            .filter(|e| {
                matches!(
                    e.event,
                    PeerEvent::SshCredentialRequest(_) | PeerEvent::SshCredentialResponses(_)
                )
            })
            .cloned()
            .collect();
        self.issue_ssh_responses(at, &snapshot).await
    }

    async fn issue_ssh_responses(
        &self,
        at: u64,
        snapshot: &[SignedEnvelope],
    ) -> Result<(), AnyError> {
        if !crate::home_dir().join("ssh/user_ca").is_file() {
            return Ok(());
        }
        let mut requests: Vec<_> = snapshot
            .iter()
            .filter_map(|e| match &e.event {
                PeerEvent::SshCredentialRequest(r) if r.requested_at.abs_diff(at) <= 300 => {
                    Some(r.clone())
                }
                _ => None,
            })
            .collect();
        requests.sort_by_key(|r| (r.requested_at, r.node_id.clone()));
        let old = snapshot
            .iter()
            .find_map(|e| match &e.event {
                PeerEvent::SshCredentialResponses(d) if e.origin == self.hello.node_id => {
                    Some(d.clone())
                }
                _ => None,
            })
            .unwrap_or_default();
        let mut deliveries = Vec::new();
        let access = self.access_view(at).await;
        for request in requests
            .into_iter()
            .take(mycelium_peer_protocol::MAX_SSH_RENEWAL_DELIVERIES)
        {
            if let Some(existing) = old.iter().find(|d| {
                d.node_id == request.node_id
                    && d.response.request_id == request.request_id
                    && d.response.certificate.is_some()
                    && d.response.expires_at.is_some_and(|expiry| expiry > at)
            }) {
                deliveries.push(existing.clone());
                continue;
            }
            let state = access.clone();
            let node_id = request.node_id.clone();
            if let Some(response) =
                tokio::task::spawn_blocking(move || crate::ssh_renewal::issue(&request, at, &state))
                    .await?
            {
                deliveries.push(mycelium_peer_protocol::SshRenewalDelivery { node_id, response });
            }
        }
        deliveries.sort_by(|a, b| a.node_id.cmp(&b.node_id));
        let mut sorted_old = old;
        sorted_old.sort_by(|a, b| a.node_id.cmp(&b.node_id));
        if deliveries != sorted_old {
            self.publish(PeerEvent::SshCredentialResponses(deliveries))
                .await?;
        }
        Ok(())
    }

    pub async fn access_records(&self) -> Vec<AccessRecord> {
        self.observations
            .lock()
            .await
            .values()
            .filter_map(|envelope| match &envelope.event {
                PeerEvent::Access(record) => Some(record.clone()),
                _ => None,
            })
            .collect()
    }

    pub async fn access_view(&self, at: u64) -> AccessStateView {
        let authority_records = self.authority_records().await;
        let resolver = crate::authority::AuthorityResolver::new(
            &self.authority_roots,
            &self.trusted_access_keys,
            &self.trusted_release_keys,
            authority_records.iter(),
            at,
        );
        let records = self
            .access_records()
            .await
            .into_iter()
            .filter(|record| resolver.access(&record.signer).authorized)
            .collect::<Vec<_>>();
        let revocations = records
            .iter()
            .filter(|record| matches!(record.statement, AccessStatement::Revoke { .. }))
            .cloned()
            .collect::<Vec<_>>();
        let grants = records
            .into_iter()
            .filter(|record| matches!(record.statement, AccessStatement::Grant { .. }))
            .map(|record| {
                let revoked_by = revocations
                    .iter()
                    .filter(|revocation| revocation.statement.revokes(&record.statement))
                    .filter(|revocation| matches!(&revocation.statement, AccessStatement::Revoke {revoked_at,..} if *revoked_at <= at))
                    .filter_map(|revocation| match &revocation.statement {
                        AccessStatement::Revoke { revocation_id, .. } => {
                            Some(revocation_id.clone())
                        }
                        _ => None,
                    })
                    .collect::<Vec<_>>();
                let in_window = match &record.statement {
                    AccessStatement::Grant {
                        not_before,
                        not_after,
                        ..
                    } => *not_before <= at && at < *not_after,
                    _ => false,
                };
                AccessGrantView {
                    active: in_window && revoked_by.is_empty(),
                    record,
                    revoked_by,
                }
            })
            .collect();
        AccessStateView {
            grants,
            revocations,
        }
    }

    pub async fn publish_access(
        &self,
        statement_path: &Path,
        signing_key: &Path,
    ) -> Result<AccessRecord, AnyError> {
        let statement: AccessStatement = serde_json::from_slice(&std::fs::read(statement_path)?)?;
        validate_access_statement(&statement)?;
        let key_bytes = std::fs::read(signing_key)?;
        let key = SigningKey::from_bytes(
            key_bytes
                .as_slice()
                .try_into()
                .map_err(|_| "access signing key must be exactly 32 bytes")?,
        );
        let record = AccessRecord::sign(&key, statement)?;
        let decision = self.authorize_access(&record.signer).await;
        if !decision.authorized {
            return Err(format!("access signer is unauthorized: {}", decision.reason).into());
        }
        self.publish(PeerEvent::Access(record.clone())).await?;
        Ok(record)
    }

    pub async fn publish_release(&self, release: ReleaseManifest) -> Result<(), AnyError> {
        let decision = self.authorize_release(&release.signer).await;
        if !decision.authorized {
            return Err(format!("release signer is unauthorized: {}", decision.reason).into());
        }
        release
            .verify()
            .map_err(|error| format!("release signature: {error}"))?;
        self.publish(PeerEvent::Release(release)).await
    }

    pub async fn publish_package_artifact(
        &self,
        binary: &Path,
        signing_key: &Path,
        name: String,
        version: String,
        channel: String,
        target: Option<String>,
    ) -> Result<PackageManifest, AnyError> {
        for (label, value) in [
            ("name", &name),
            ("version", &version),
            ("channel", &channel),
        ] {
            validate_release_label(label, value)?;
        }
        let target = target.unwrap_or_else(local_build_target);
        validate_release_label("target", &target)?;
        let bytes = std::fs::read(binary)?;
        let key_bytes = std::fs::read(signing_key)?;
        let key = SigningKey::from_bytes(
            key_bytes
                .as_slice()
                .try_into()
                .map_err(|_| "release signing key must be exactly 32 bytes")?,
        );
        let package = PackageManifest::sign(&key, name, version, channel, target, &bytes)?;
        let decision = self.authorize_package(&package).await;
        if !decision.authorized {
            return Err(format!("package signer is unauthorized: {}", decision.reason).into());
        }
        std::fs::create_dir_all(crate::artifacts_dir())?;
        let final_path = artifact_path(&package.artifact_digest)?;
        if !final_path.is_file() {
            let temp = final_path.with_extension(format!("tmp-{}", std::process::id()));
            std::fs::write(&temp, &bytes)?;
            std::fs::rename(temp, &final_path)?;
        }
        self.publish(PeerEvent::Package(package.clone())).await?;
        Ok(package)
    }

    pub async fn authority_records(&self) -> Vec<AuthorityRecord> {
        self.observations
            .lock()
            .await
            .values()
            .filter_map(|envelope| match &envelope.event {
                PeerEvent::Authority(record) => Some(record.clone()),
                _ => None,
            })
            .collect()
    }

    pub async fn publish_authority(
        &self,
        statement_path: &Path,
        signing_key: &Path,
    ) -> Result<AuthorityRecord, AnyError> {
        let statement: AuthorityStatement =
            serde_json::from_slice(&std::fs::read(statement_path)?)?;
        validate_authority_statement(&statement)?;
        let key_bytes = std::fs::read(signing_key)?;
        let key = SigningKey::from_bytes(
            key_bytes
                .as_slice()
                .try_into()
                .map_err(|_| "authority signing key must be exactly 32 bytes")?,
        );
        let record = AuthorityRecord::sign(&key, statement)?;
        if !self.authority_roots.contains(&record.signer) {
            return Err("authority signer is not in MYCELIUM_AUTHORITY_KEYS".into());
        }
        self.publish(PeerEvent::Authority(record.clone())).await?;
        Ok(record)
    }

    pub async fn authorize_access(&self, signer: &str) -> crate::authority::AuthorityDecision {
        let records = self.authority_records().await;
        crate::authority::AuthorityResolver::new(
            &self.authority_roots,
            &self.trusted_access_keys,
            &self.trusted_release_keys,
            records.iter(),
            now(),
        )
        .access(signer)
    }

    pub async fn authorize_release(&self, signer: &str) -> crate::authority::AuthorityDecision {
        let records = self.authority_records().await;
        crate::authority::AuthorityResolver::new(
            &self.authority_roots,
            &self.trusted_access_keys,
            &self.trusted_release_keys,
            records.iter(),
            now(),
        )
        .release(signer)
    }

    pub async fn authorize_package(
        &self,
        package: &PackageManifest,
    ) -> crate::authority::AuthorityDecision {
        let records = self.authority_records().await;
        crate::authority::AuthorityResolver::new(
            &self.authority_roots,
            &self.trusted_access_keys,
            &self.trusted_release_keys,
            records.iter(),
            now(),
        )
        .package(package)
    }

    pub async fn authorize_package_fields(
        &self,
        signer: &str,
        name: &str,
        channel: &str,
        target: &str,
    ) -> crate::authority::AuthorityDecision {
        let records = self.authority_records().await;
        crate::authority::AuthorityResolver::new(
            &self.authority_roots,
            &self.trusted_access_keys,
            &self.trusted_release_keys,
            records.iter(),
            now(),
        )
        .package_fields(signer, name, channel, target)
    }

    pub async fn publish_artifact(
        &self,
        binary: &Path,
        signing_key: &Path,
        version: String,
        channel: String,
        target: Option<String>,
    ) -> Result<ReleaseManifest, AnyError> {
        validate_release_label("version", &version)?;
        validate_release_label("channel", &channel)?;
        let target = target.unwrap_or_else(local_build_target);
        validate_release_label("target", &target)?;
        let bytes = std::fs::read(binary)?;
        let key_bytes = std::fs::read(signing_key)?;
        let key = SigningKey::from_bytes(
            key_bytes
                .as_slice()
                .try_into()
                .map_err(|_| "release signing key must be exactly 32 bytes")?,
        );
        let release = ReleaseManifest::sign(&key, version, channel, target, &bytes)?;
        std::fs::create_dir_all(crate::artifacts_dir())?;
        let final_path = artifact_path(&release.artifact_digest)?;
        if !final_path.is_file() {
            let temp = final_path.with_extension("tmp");
            std::fs::write(&temp, &bytes)?;
            std::fs::rename(temp, &final_path)?;
        }
        self.publish_release(release.clone()).await?;
        Ok(release)
    }

    pub async fn publish_artifact_set(
        &self,
        manifest: &Path,
        signing_key: &Path,
    ) -> Result<Vec<ReleaseManifest>, AnyError> {
        let definition: ReleaseSetFile = serde_json::from_slice(&std::fs::read(manifest)?)?;
        validate_release_label("version", &definition.version)?;
        validate_release_label("channel", &definition.channel)?;
        if definition.artifacts.is_empty() {
            return Err("release set must contain at least one artifact".into());
        }
        let key_bytes = std::fs::read(signing_key)?;
        let key = SigningKey::from_bytes(
            key_bytes
                .as_slice()
                .try_into()
                .map_err(|_| "release signing key must be exactly 32 bytes")?,
        );
        let base = manifest.parent().unwrap_or_else(|| Path::new("."));
        let mut targets = BTreeSet::new();
        let mut prepared = Vec::with_capacity(definition.artifacts.len());
        for artifact in definition.artifacts {
            validate_release_label("target", &artifact.target)?;
            if !targets.insert(artifact.target.clone()) {
                return Err(format!("duplicate release target `{}`", artifact.target).into());
            }
            let path = {
                let path = Path::new(&artifact.binary);
                if path.is_absolute() {
                    path.to_owned()
                } else {
                    base.join(path)
                }
            };
            let bytes = std::fs::read(&path)
                .map_err(|error| format!("cannot read {}: {error}", path.display()))?;
            let release = ReleaseManifest::sign(
                &key,
                definition.version.clone(),
                definition.channel.clone(),
                artifact.target,
                &bytes,
            )?;
            prepared.push((release, bytes));
        }

        // No release becomes visible until every input has been read, validated,
        // hashed, and signed successfully.
        std::fs::create_dir_all(crate::artifacts_dir())?;
        for (release, bytes) in &prepared {
            let final_path = artifact_path(&release.artifact_digest)?;
            if !final_path.is_file() {
                let temp = final_path.with_extension(format!("tmp-{}", std::process::id()));
                std::fs::write(&temp, bytes)?;
                std::fs::rename(temp, final_path)?;
            }
        }
        let releases = prepared
            .into_iter()
            .map(|(release, _)| release)
            .collect::<Vec<_>>();
        for release in &releases {
            self.publish_release(release.clone()).await?;
        }
        Ok(releases)
    }

    /// Add authorized artifact bytes to the local content-addressed cache.
    /// The converged, verified release manifest is the authority; seeding does
    /// not create metadata and does not require possession of a signing key.
    pub async fn seed_artifact(
        &self,
        binary: &Path,
        digest: &str,
    ) -> Result<SeededArtifact, AnyError> {
        validate_digest(digest)?;
        let releases = self
            .releases()
            .await
            .into_iter()
            .filter(|release| release.artifact_digest == digest)
            .collect::<Vec<_>>();
        let packages = self
            .packages()
            .await
            .into_iter()
            .filter(|package| package.artifact_digest == digest)
            .collect::<Vec<_>>();
        if releases.is_empty() && packages.is_empty() {
            return Err("artifact has no trusted release or package manifest".into());
        }
        for release in &releases {
            release
                .verify()
                .map_err(|error| format!("release signature: {error}"))?;
        }
        for package in &packages {
            package
                .verify()
                .map_err(|error| format!("package signature: {error}"))?;
        }
        let expected_size = releases
            .first()
            .map(|item| item.artifact_size)
            .or_else(|| packages.first().map(|item| item.artifact_size))
            .expect("manifest checked above");
        if releases
            .iter()
            .any(|release| release.artifact_size != expected_size)
            || packages
                .iter()
                .any(|package| package.artifact_size != expected_size)
        {
            return Err("trusted manifests disagree on artifact size".into());
        }
        let already_present =
            seed_artifact_file(binary, &artifact_path(digest)?, digest, expected_size)?;
        Ok(SeededArtifact {
            artifact_digest: digest.to_owned(),
            artifact_size: expected_size,
            already_present,
            releases,
            packages,
        })
    }

    pub fn generate_release_key(path: &Path) -> Result<String, AnyError> {
        if path.exists() {
            return Err("release signing key already exists".into());
        }
        let key = SigningKey::generate(&mut OsRng);
        std::fs::write(path, key.to_bytes())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        }
        Ok(encode_hex(key.verifying_key().as_bytes()))
    }

    async fn publish(&self, event: PeerEvent) -> Result<(), AnyError> {
        let sequence = self.sequence.fetch_add(1, Ordering::SeqCst) + 1;
        let envelope = SignedEnvelope::sign(&self.key, sequence, now(), event)?;
        self.merge(vec![envelope]).await
    }

    async fn merge(&self, incoming: Vec<SignedEnvelope>) -> Result<(), AnyError> {
        let mut changed = false;
        let mut credential_response = false;
        let mut observations = self.observations.lock().await;
        let mut incoming = incoming;
        incoming.sort_by_key(|envelope| !matches!(envelope.event, PeerEvent::Authority(_)));
        for envelope in incoming {
            if matches!(envelope.event, PeerEvent::Unknown) {
                continue;
            }
            let authorized = envelope.origin == self.hello.node_id
                || self
                    .allowed_origins
                    .as_ref()
                    .is_none_or(|allowed| allowed.contains(&envelope.origin));
            let records = authority_records_from(&observations);
            let resolver = crate::authority::AuthorityResolver::new(
                &self.authority_roots,
                &self.trusted_access_keys,
                &self.trusted_release_keys,
                records.iter(),
                now(),
            );
            let event_authorized = event_is_authorized(&envelope, &self.authority_roots, &resolver);
            if !authorized
                || !event_authorized
                || envelope.verify().is_err()
                || !event_origin_matches(&envelope)
            {
                continue;
            }
            let key = event_key(&envelope);
            let replace = observations
                .get(&key)
                .map(|current| envelope.sequence > current.sequence)
                .unwrap_or(true);
            if replace {
                credential_response |=
                    matches!(envelope.event, PeerEvent::SshCredentialResponses(_));
                observations.insert(key, envelope);
                changed = true;
            }
        }
        let values = changed.then(|| observations.values().cloned().collect::<Vec<_>>());
        drop(observations);
        if let Some(values) = values {
            tokio::task::spawn_blocking(move || persist_observations(&values)).await??;
        }
        // A renewal response is installed when it arrives. Waiting for the
        // half-hourly check would let it age out of the five-minute window it
        // was signed inside.
        if credential_response {
            self.install_pending_ssh_renewal(now()).await?;
        }
        Ok(())
    }

    async fn listen(self: Arc<Self>, address: &str, acceptor: TlsAcceptor) -> Result<(), AnyError> {
        let listener = TcpListener::bind(address).await?;
        eprintln!("myceliumd: peer mesh listening on {address}");
        loop {
            let (tcp, peer) = listener.accept().await?;
            let mesh = self.clone();
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                match acceptor.accept(tcp).await {
                    Ok(stream) => {
                        let fingerprint =
                            tls_peer_fingerprint(stream.get_ref().1.peer_certificates());
                        if let Err(error) =
                            mesh.run_stream(stream, fingerprint, Some(peer.ip())).await
                        {
                            eprintln!("myceliumd: peer {peer}: {error}");
                        }
                    }
                    Err(error) => eprintln!("myceliumd: peer TLS {peer}: {error}"),
                }
            });
        }
    }

    async fn dial_forever(self: Arc<Self>, seed: String, connector: TlsConnector) {
        let mut delay = Duration::from_secs(1);
        let mut reported: Option<String> = None;
        loop {
            let started = std::time::Instant::now();
            match self.dial(&seed, connector.clone()).await {
                // A session that closes immediately is not evidence of health:
                // reset the backoff only after a connection was actually useful.
                Ok(()) if started.elapsed() >= BACKOFF_RESET_SESSION => {
                    delay = Duration::from_secs(1);
                    reported = None;
                }
                Ok(()) => {}
                Err(error) => {
                    // One line per distinct failure, not one per retry.
                    let message = format!("myceliumd: peer seed {seed}: {error}");
                    if reported.as_deref() != Some(message.as_str()) {
                        eprintln!("{message}");
                        reported = Some(message);
                    }
                }
            }
            tokio::time::sleep(delay).await;
            delay = (delay * 2).min(Duration::from_secs(60));
        }
    }

    async fn dial(&self, seed: &str, connector: TlsConnector) -> Result<(), AnyError> {
        let (expected_name, address) = split_seed(seed)?;
        let tcp = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(address))
            .await
            .map_err(|_| "TCP connection timed out")??;
        let observed_address = tcp.peer_addr().ok().map(|address| address.ip());
        let host = address
            .rsplit_once(':')
            .map_or(address, |(host, _)| host)
            .trim_matches(&['[', ']'][..]);
        let name = server_name(expected_name.unwrap_or(host))?;
        let stream = tokio::time::timeout(CONNECT_TIMEOUT, connector.connect(name, tcp))
            .await
            .map_err(|_| "TLS handshake timed out")??;
        let fingerprint = tls_peer_fingerprint(stream.get_ref().1.peer_certificates());
        self.run_stream(stream, fingerprint, observed_address).await
    }

    async fn run_stream<S>(
        &self,
        stream: S,
        peer_certificate: Option<String>,
        observed_address: Option<IpAddr>,
    ) -> Result<(), AnyError>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    {
        self.run_bound_stream(stream, peer_certificate, observed_address, None)
            .await
    }

    async fn run_bound_stream<S>(
        &self,
        stream: S,
        peer_certificate: Option<String>,
        observed_address: Option<IpAddr>,
        iroh_endpoint: Option<String>,
    ) -> Result<(), AnyError>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    {
        let (reader, mut writer) = tokio::io::split(stream);
        send(&mut writer, &PeerMessage::Hello(self.local_hello().await)).await?;
        let mut reader = BufReader::new(reader);
        let mut pending_line = Vec::new();
        let mut digest_interval = tokio::time::interval(DIGEST_INTERVAL);
        digest_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let artifact_request_interval = std::env::var("MYCELIUM_ARTIFACT_REQUEST_SECS")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .filter(|seconds| *seconds > 0)
            .map(Duration::from_secs)
            .unwrap_or(DEFAULT_ARTIFACT_REQUEST_INTERVAL);
        let mut artifact_interval = tokio::time::interval(artifact_request_interval);
        artifact_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut remote_identity = None::<String>;
        let mut binding_required = self.require_transport_binding || iroh_endpoint.is_some();
        let mut transport_authenticated = false;
        let mut endpoint_published = false;
        let mut remote_supports_iroh = false;
        let mut tcp_registration = None;
        let mut read_deadline = tokio::time::Instant::now() + PEER_IDLE_TIMEOUT;
        loop {
            tokio::select! {
                _ = tokio::time::sleep_until(read_deadline) => {
                    return Err("peer sync read timed out".into());
                }
                result = next_peer_line(&mut reader, &mut pending_line) => {
                    let Some(line) = result? else { return Ok(()); };
                    read_deadline = tokio::time::Instant::now() + PEER_IDLE_TIMEOUT;
                    if line.len() > 1_048_576 { return Err("peer message exceeds 1 MiB".into()); }
                    match serde_json::from_str::<PeerMessage>(line.trim())? {
                        PeerMessage::Observations(values) => {
                            self.merge(values).await?;
                            if let (Some(node_id), Some(fingerprint)) =
                                (remote_identity.as_deref(), peer_certificate.as_deref())
                            {
                                let was_authenticated = transport_authenticated;
                                transport_authenticated = self
                                    .has_transport_binding(node_id, TransportKind::Mtls, fingerprint)
                                    .await;
                                if let Some(endpoint) = iroh_endpoint.as_deref() {
                                    transport_authenticated &= self.has_transport_binding(node_id, TransportKind::Iroh, endpoint).await;
                                    if transport_authenticated && !was_authenticated {
                                        eprintln!("myceliumd: authenticated Iroh peer {node_id} endpoint {endpoint}");
                                    }
                                }
                            }
                            if !transport_authenticated {
                                tcp_registration = None;
                            }
                            if transport_authenticated && iroh_endpoint.is_none() && tcp_registration.is_none() {
                                if let Some(peer) = remote_identity.as_ref() {
                                    tcp_registration = Some(TcpRegistration::new(&self.active_tcp, peer.clone()));
                                }
                            }
                            if transport_authenticated && !endpoint_published {
                                if let (Some(peer), Some(address)) =
                                    (remote_identity.clone(), observed_address)
                                {
                                    if is_publishable_address(&address) {
                                        self.publish(PeerEvent::Endpoint(PeerEndpointObservation {
                                            observer: self.hello.node_id.clone(),
                                            peer,
                                            address,
                                            observed_at: now(),
                                        })).await?;
                                        endpoint_published = true;
                                    }
                                }
                            }
                        }
                        PeerMessage::Digest(remote) => {
                            let newer = self
                                .observations
                                .lock()
                                .await
                                .iter()
                                .filter(|(_, envelope)| transport_event_supported(&envelope.event, remote_supports_iroh))
                                .filter(|(key, envelope)| {
                                    remote.get(*key).copied().unwrap_or(0) < envelope.sequence
                                })
                                .map(|(_, envelope)| envelope.clone())
                                .collect::<Vec<_>>();
                            if !newer.is_empty() {
                                let batches = tokio::task::spawn_blocking(move || {
                                    observation_batches(newer)
                                })
                                .await??;
                                for chunk in batches {
                                    send(
                                        &mut writer,
                                        &PeerMessage::Observations(chunk),
                                    )
                                    .await?;
                                }
                            }
                        }
                        PeerMessage::Hello(hello) if hello.protocol_version != PROTOCOL_VERSION => {
                            return Err(format!("protocol {} is unsupported", hello.protocol_version).into());
                        }
                        PeerMessage::ArtifactRequest { digest, offset, length } => {
                            if binding_required && !transport_authenticated {
                                continue;
                            }
                            if let Some(chunk) = artifact_chunk(&digest, offset, length)? {
                                send(&mut writer, &chunk).await?;
                            }
                        }
                        PeerMessage::ArtifactChunk { digest, offset, data, complete } => {
                            if binding_required && !transport_authenticated {
                                continue;
                            }
                            accept_artifact_chunk(
                                &digest,
                                offset,
                                &data,
                                complete,
                                &self.releases().await,
                                &self.packages().await,
                            )?;
                            if !complete {
                                if let Some(request) = self.next_artifact_request().await? {
                                    send(&mut writer, &request).await?;
                                }
                            }
                        }
                        PeerMessage::SshRenewalRequest(request) => {
                            if binding_required && !transport_authenticated {
                                continue;
                            }
                            if let Some(response) = crate::ssh_renewal::issue(&request, now(), &self.access_view(now()).await) {
                                send(&mut writer, &PeerMessage::SshRenewalResponse(response)).await?;
                            }
                        }
                        // New clients use retained gossip deliveries; keep the
                        // direct response variant decodable for older peers.
                        PeerMessage::SshRenewalResponse(_) => {}
                        PeerMessage::Hello(hello) => {
                            if remote_identity.as_ref().is_some_and(|identity| identity != &hello.node_id) {
                                return Err("peer identity changed within authenticated stream".into());
                            }
                            remote_supports_iroh = hello.capabilities.iter().any(|capability| capability == "transport.iroh-key-binding");
                            remote_identity = Some(hello.node_id.clone());
                            binding_required = self.require_transport_binding
                                || iroh_endpoint.is_some()
                                || hello.capabilities.iter().any(|capability| {
                                    capability == "transport.identity-binding"
                                });
                            if binding_required && peer_certificate.is_none() {
                                return Err("peer advertised transport binding without a TLS certificate".into());
                            }
                        }
                        PeerMessage::Ping { .. } => {}
                    }
                }
                _ = digest_interval.tick() => {
                    let digest = self
                        .observations
                        .lock()
                        .await
                        .iter()
                        .map(|(key, envelope)| (key.clone(), envelope.sequence))
                        .collect();
                    send(&mut writer, &PeerMessage::Digest(digest)).await?;
                }
                _ = artifact_interval.tick() => {
                    if !binding_required || transport_authenticated {
                        if let Some(request) = self.next_artifact_request().await? {
                            send(&mut writer, &request).await?;
                        }
                    }
                }
            }
        }
    }

    async fn next_artifact_request(&self) -> Result<Option<PeerMessage>, AnyError> {
        let targets = local_compatible_targets();
        let desired_packages = match crate::software::read_policy(&crate::software_policy_path()) {
            Ok(policy) => crate::software::plan(&policy, &self.views().await)?
                .into_iter()
                .filter(|assignment| assignment.node_id == self.hello.node_id)
                .map(|assignment| (assignment.package, assignment.channel))
                .collect::<BTreeSet<_>>(),
            Err(error)
                if error
                    .downcast_ref::<std::io::Error>()
                    .is_some_and(|error| error.kind() == std::io::ErrorKind::NotFound) =>
            {
                BTreeSet::new()
            }
            Err(error) => return Err(format!("software policy: {error}").into()),
        };
        let packages = self.packages().await;
        for (name, channel) in desired_packages {
            let Some(package) = crate::software::select(&packages, &name, &channel, &targets)
            else {
                continue;
            };
            if artifact_path(&package.artifact_digest)?.is_file() {
                continue;
            }
            let partial = partial_artifact_path(&package.artifact_digest)?;
            let offset = std::fs::metadata(partial)
                .map(|metadata| metadata.len())
                .unwrap_or(0);
            if offset > package.artifact_size {
                return Err("partial package artifact exceeds signed size".into());
            }
            return Ok(Some(PeerMessage::ArtifactRequest {
                digest: package.artifact_digest.clone(),
                offset,
                length: 65_536,
            }));
        }
        let release = self.preferred_release().await;
        let Some(release) = release else {
            return Ok(None);
        };
        if artifact_path(&release.artifact_digest)?.is_file() {
            return Ok(None);
        }
        let partial = partial_artifact_path(&release.artifact_digest)?;
        let offset = std::fs::metadata(partial)
            .map(|metadata| metadata.len())
            .unwrap_or(0);
        if offset > release.artifact_size {
            return Err("partial artifact exceeds signed size".into());
        }
        Ok(Some(PeerMessage::ArtifactRequest {
            digest: release.artifact_digest,
            offset,
            length: 65_536,
        }))
    }

    async fn preferred_release(&self) -> Option<ReleaseManifest> {
        let targets = local_compatible_targets();
        let channel = std::env::var("MYCELIUM_UPDATE_CHANNEL").unwrap_or_else(|_| "canary".into());
        self.releases()
            .await
            .into_iter()
            .filter(|release| targets.contains(&release.target) && release.channel == channel)
            .max_by_key(|release| {
                let preference = targets
                    .iter()
                    .position(|target| target == &release.target)
                    .map(|index| targets.len() - index)
                    .unwrap_or_default();
                (release.version.clone(), preference)
            })
    }
}

fn transport_event_supported(event: &PeerEvent, iroh: bool) -> bool {
    iroh || !matches!(event, PeerEvent::Transport(binding) if binding.kind == TransportKind::Iroh)
}

/// Drop removes live path state on EOF, errors, and task cancellation alike.
struct TcpRegistration<'a> {
    peers: &'a std::sync::Mutex<BTreeMap<String, usize>>,
    peer: String,
}
impl<'a> TcpRegistration<'a> {
    fn new(peers: &'a std::sync::Mutex<BTreeMap<String, usize>>, peer: String) -> Self {
        *peers
            .lock()
            .expect("TCP path lock poisoned")
            .entry(peer.clone())
            .or_default() += 1;
        Self { peers, peer }
    }
}
impl Drop for TcpRegistration<'_> {
    fn drop(&mut self) {
        let mut peers = self.peers.lock().expect("TCP path lock poisoned");
        if let Some(count) = peers.get_mut(&self.peer) {
            *count -= 1;
            if *count == 0 {
                peers.remove(&self.peer);
            }
        }
    }
}

fn observation_batches(
    observations: Vec<SignedEnvelope>,
) -> Result<Vec<Vec<SignedEnvelope>>, AnyError> {
    let mut batches = Vec::new();
    let mut current = Vec::new();
    let mut current_bytes = 32usize;
    for observation in observations {
        let bytes = serde_json::to_vec(&observation)?.len() + 1;
        if bytes > MAX_OBSERVATION_MESSAGE_BYTES {
            eprintln!(
                "myceliumd: skipping oversized {} byte observation from {}",
                bytes, observation.origin
            );
            continue;
        }
        if !current.is_empty()
            && (current.len() == MAX_OBSERVATIONS_PER_MESSAGE
                || current_bytes + bytes > MAX_OBSERVATION_MESSAGE_BYTES)
        {
            batches.push(std::mem::take(&mut current));
            current_bytes = 32;
        }
        current_bytes += bytes;
        current.push(observation);
    }
    if !current.is_empty() {
        batches.push(current);
    }
    Ok(batches)
}

#[derive(Clone)]
struct TlsSettings {
    listen: Option<String>,
    seeds: Vec<String>,
    ca: String,
    cert: String,
    key: String,
}

impl TlsSettings {
    fn identity_binding(&self, node_id: &str) -> Result<TransportCredentialBinding, AnyError> {
        let certificate = certs(&self.cert)?
            .into_iter()
            .next()
            .ok_or("peer certificate chain is empty")?;
        Ok(TransportCredentialBinding {
            node_id: node_id.to_owned(),
            kind: TransportKind::Mtls,
            public_key: mycelium_peer_protocol::sha256_hex(certificate.as_ref()),
            generation: now(),
            valid_until: None,
        })
    }

    fn from_env() -> Result<Option<Self>, AnyError> {
        let listen = std::env::var("MYCELIUM_PEER_LISTEN").ok();
        let seeds = std::env::var("MYCELIUM_PEERS")
            .unwrap_or_default()
            .split(',')
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_owned)
            .collect::<Vec<_>>();
        let iroh_enabled = crate::home_dir().join("iroh-sync.json").exists();
        if iroh_enabled && !cfg!(feature = "iroh-sync") {
            return Err("iroh-sync.json exists but this binary lacks the iroh-sync feature".into());
        }
        if listen.is_none() && seeds.is_empty() && !iroh_enabled {
            return Ok(None);
        }
        let required = |name| -> Result<String, AnyError> {
            std::env::var(name).map_err(|_| format!("{name} is required").into())
        };
        Ok(Some(Self {
            listen,
            seeds,
            ca: required("MYCELIUM_PEER_CA")?,
            cert: required("MYCELIUM_PEER_CERT")?,
            key: required("MYCELIUM_PEER_KEY")?,
        }))
    }

    fn roots(&self) -> Result<RootCertStore, AnyError> {
        let mut roots = RootCertStore::empty();
        for cert in certs(&self.ca)? {
            roots.add(cert)?;
        }
        Ok(roots)
    }

    fn client_config(&self) -> Result<ClientConfig, AnyError> {
        Ok(ClientConfig::builder()
            .with_root_certificates(self.roots()?)
            .with_client_auth_cert(certs(&self.cert)?, private_key(&self.key)?)?)
    }

    fn server_config(&self) -> Result<ServerConfig, AnyError> {
        let verifier = WebPkiClientVerifier::builder(Arc::new(self.roots()?)).build()?;
        Ok(ServerConfig::builder()
            .with_client_cert_verifier(verifier)
            .with_single_cert(certs(&self.cert)?, private_key(&self.key)?)?)
    }
}

async fn send<W: tokio::io::AsyncWrite + Unpin>(
    writer: &mut W,
    message: &PeerMessage,
) -> Result<(), AnyError> {
    send_with_timeout(writer, message, CONNECT_TIMEOUT).await
}

async fn send_with_timeout<W: tokio::io::AsyncWrite + Unpin>(
    writer: &mut W,
    message: &PeerMessage,
    deadline: Duration,
) -> Result<(), AnyError> {
    let bytes = serde_json::to_vec(message)?;
    // A timed-out partial frame is fatal: callers must close the stream,
    // never resume writing a different frame onto these partial bytes.
    tokio::time::timeout(deadline, async {
        writer.write_all(&bytes).await?;
        writer.write_all(b"\n").await?;
        writer.flush().await
    })
    .await
    .map_err(|_| "peer sync write timed out")??;
    Ok(())
}

/// Cancellation-safe framing: retained partial bytes survive select! ticks,
/// and the size bound is enforced before extending the buffer.
async fn next_peer_line<R: tokio::io::AsyncRead + Unpin>(
    reader: &mut BufReader<R>,
    pending: &mut Vec<u8>,
) -> std::io::Result<Option<String>> {
    loop {
        let available = reader.fill_buf().await?;
        if available.is_empty() {
            if pending.is_empty() {
                return Ok(None);
            }
            break;
        }
        let end = available.iter().position(|byte| *byte == b'\n');
        let count = end.map_or(available.len(), |i| i + 1);
        if pending.len() + count > 1_048_577 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "peer message exceeds 1 MiB",
            ));
        }
        pending.extend_from_slice(&available[..count]);
        reader.consume(count);
        if end.is_some() {
            break;
        }
    }
    let mut bytes = std::mem::take(pending);
    if bytes.last() == Some(&b'\n') {
        bytes.pop();
    }
    String::from_utf8(bytes)
        .map(Some)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))
}

fn validated_observations(
    envelopes: Vec<SignedEnvelope>,
    local_node_id: &str,
    allowed_origins: Option<&BTreeSet<String>>,
    authority_roots: &BTreeSet<String>,
    legacy_access: &BTreeSet<String>,
    legacy_release: &BTreeSet<String>,
) -> BTreeMap<String, SignedEnvelope> {
    let mut candidates = envelopes
        .into_iter()
        .filter(|envelope| {
            !matches!(envelope.event, PeerEvent::Unknown)
                && envelope.verify().is_ok()
                && event_origin_matches(envelope)
                && (envelope.origin == local_node_id
                    || allowed_origins.is_none_or(|allowed| allowed.contains(&envelope.origin)))
        })
        .collect::<Vec<_>>();
    candidates.sort_by_key(|envelope| !matches!(envelope.event, PeerEvent::Authority(_)));
    let mut accepted = BTreeMap::new();
    for envelope in candidates {
        let records = authority_records_from(&accepted);
        let resolver = crate::authority::AuthorityResolver::new(
            authority_roots,
            legacy_access,
            legacy_release,
            records.iter(),
            now(),
        );
        if event_is_authorized(&envelope, authority_roots, &resolver) {
            accepted.insert(event_key(&envelope), envelope);
        }
    }
    accepted
}

fn authority_records_from(observations: &BTreeMap<String, SignedEnvelope>) -> Vec<AuthorityRecord> {
    observations
        .values()
        .filter_map(|envelope| match &envelope.event {
            PeerEvent::Authority(record) => Some(record.clone()),
            _ => None,
        })
        .collect()
}

fn event_is_authorized(
    envelope: &SignedEnvelope,
    authority_roots: &BTreeSet<String>,
    resolver: &crate::authority::AuthorityResolver<'_>,
) -> bool {
    match &envelope.event {
        PeerEvent::SyncHints(hints) => {
            #[cfg(feature = "iroh-sync")]
            {
                iroh_sync::validate_hints(hints, &envelope.origin).is_ok()
            }
            #[cfg(not(feature = "iroh-sync"))]
            {
                let _ = hints;
                false
            }
        }
        PeerEvent::Hello(hello) => {
            hello.interfaces.len() <= 64
                && hello.interfaces.iter().all(|interface| {
                    !interface.name.is_empty()
                        && interface.name.len() <= 64
                        && interface.addresses.len() <= 32
                        && interface.addresses.iter().all(is_publishable_address)
                        && interface.mac.as_deref().is_none_or(is_public_mac)
                })
        }
        PeerEvent::Release(release) => {
            release.verify().is_ok() && resolver.release(&release.signer).authorized
        }
        PeerEvent::Package(package) => {
            package.verify().is_ok() && resolver.package(package).authorized
        }
        PeerEvent::Authority(record) => {
            authority_roots.contains(&record.signer) && record.verify().is_ok()
        }
        PeerEvent::Endpoint(endpoint) => {
            endpoint.observer == envelope.origin
                && decode_hex(&endpoint.peer).is_ok_and(|value| value.len() == 32)
                && is_publishable_address(&endpoint.address)
        }
        PeerEvent::Egress(value) => {
            value.node_id == envelope.origin && value.mapped_endpoints.len() <= 16
        }
        PeerEvent::Access(record) => {
            record.verify().is_ok() && resolver.access(&record.signer).authorized
        }
        PeerEvent::SshCredentialRequest(request) => {
            request.node_id == envelope.origin
                && request.request_id.len() <= 64
                && request.public_key.len() <= 16384
                && request.requested_at.abs_diff(envelope.emitted_at) <= 300
                && request.verify().is_ok()
        }
        PeerEvent::SshCredentialResponses(deliveries) => {
            deliveries.len() <= mycelium_peer_protocol::MAX_SSH_RENEWAL_DELIVERIES
                && deliveries.iter().all(|d| {
                    d.node_id.len() == 64
                        && d.node_id.bytes().all(|b| b.is_ascii_hexdigit())
                        && d.response.request_id.len() <= 64
                        && d.response
                            .certificate
                            .as_ref()
                            .is_none_or(|c| c.len() <= 16384)
                        && d.response.error.as_ref().is_none_or(|e| e.len() <= 512)
                })
        }
        PeerEvent::Transport(binding) => binding.validate_for(&envelope.origin).is_ok(),
        PeerEvent::WireGuard(binding) => binding.validate_for(&envelope.origin).is_ok(),
        PeerEvent::Hardware(snapshot) => snapshot.validate_for(&envelope.origin).is_ok(),
        PeerEvent::SecurityPosture(posture) => {
            posture.node_id == envelope.origin && posture.findings.len() <= MAX_SECURITY_FINDINGS
        }
        PeerEvent::SecurityEvents(events) => {
            events.node_id == envelope.origin && events.events.len() <= MAX_SECURITY_EVENTS
        }
        _ => true,
    }
}

fn event_key(envelope: &SignedEnvelope) -> String {
    match &envelope.event {
        PeerEvent::SyncHints(_) => format!("{}:sync-hints", envelope.origin),
        PeerEvent::Hello(_) => format!("{}:hello", envelope.origin),
        PeerEvent::Health(_) => format!("{}:health", envelope.origin),
        PeerEvent::Topology(_) => format!("{}:topology", envelope.origin),
        PeerEvent::Release(release) => format!(
            "{}:release:{}:{}",
            envelope.origin, release.channel, release.target
        ),
        PeerEvent::Package(package) => format!(
            "{}:package:{}:{}:{}",
            envelope.origin, package.name, package.channel, package.target
        ),
        PeerEvent::Authority(record) => match &record.statement {
            AuthorityStatement::Delegate { delegation_id, .. } => {
                format!("authority:{}:delegate:{delegation_id}", record.signer)
            }
            AuthorityStatement::Revoke { revocation_id, .. } => {
                format!("authority:{}:revoke:{revocation_id}", record.signer)
            }
        },
        PeerEvent::Endpoint(endpoint) => format!(
            "{}:endpoint:{}:{}",
            envelope.origin, endpoint.peer, endpoint.address
        ),
        PeerEvent::Egress(_) => format!("{}:egress", envelope.origin),
        PeerEvent::Access(record) => match &record.statement {
            AccessStatement::Grant { grant_id, .. } => {
                format!("access:{}:grant:{grant_id}", record.signer)
            }
            AccessStatement::Revoke { revocation_id, .. } => {
                format!("access:{}:revoke:{revocation_id}", record.signer)
            }
        },
        PeerEvent::SshCredentialRequest(_) => format!("{}:ssh-credential-request", envelope.origin),
        PeerEvent::SshCredentialResponses(_) => {
            format!("{}:ssh-credential-responses", envelope.origin)
        }
        PeerEvent::Transport(binding) => {
            format!("{}:transport:{:?}", envelope.origin, binding.kind)
        }
        PeerEvent::WireGuard(_) => format!("{}:wireguard", envelope.origin),
        PeerEvent::Hardware(_) => format!("{}:hardware", envelope.origin),
        PeerEvent::SecurityPosture(_) => format!("{}:security-posture", envelope.origin),
        PeerEvent::SecurityEvents(_) => format!("{}:security-events", envelope.origin),
        PeerEvent::Unknown => format!("{}:unknown", envelope.origin),
    }
}

fn event_origin_matches(envelope: &SignedEnvelope) -> bool {
    match &envelope.event {
        PeerEvent::SyncHints(hints) => hints.node_id == envelope.origin,
        PeerEvent::Hello(hello) => hello.node_id == envelope.origin,
        PeerEvent::SshCredentialRequest(request) => request.node_id == envelope.origin,
        PeerEvent::SshCredentialResponses(_) => true,
        PeerEvent::Health(_)
        | PeerEvent::Topology(_)
        | PeerEvent::Release(_)
        | PeerEvent::Package(_)
        | PeerEvent::Authority(_)
        | PeerEvent::Access(_) => true,
        PeerEvent::Endpoint(endpoint) => endpoint.observer == envelope.origin,
        PeerEvent::Egress(value) => value.node_id == envelope.origin,
        PeerEvent::Transport(binding) => binding.validate_for(&envelope.origin).is_ok(),
        PeerEvent::WireGuard(binding) => binding.validate_for(&envelope.origin).is_ok(),
        PeerEvent::Hardware(snapshot) => snapshot.validate_for(&envelope.origin).is_ok(),
        PeerEvent::SecurityPosture(posture) => posture.node_id == envelope.origin,
        PeerEvent::SecurityEvents(events) => events.node_id == envelope.origin,
        PeerEvent::Unknown => false,
    }
}

fn csv_set(name: &str) -> BTreeSet<String> {
    std::env::var(name)
        .unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .collect()
}

fn raspberry_pi_capability() -> Option<String> {
    #[cfg(target_os = "linux")]
    {
        return std::fs::read_to_string("/proc/device-tree/model")
            .ok()
            .filter(|model| model.to_ascii_lowercase().contains("raspberry pi"))
            .map(|_| "node.raspberry-pi".into());
    }
    #[cfg(not(target_os = "linux"))]
    None
}

fn configured_node_facts() -> impl Iterator<Item = String> {
    std::env::var("MYCELIUM_NODE_FACTS")
        .unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|fact| {
            !fact.is_empty()
                && fact.len() <= 128
                && fact
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
        })
        .map(str::to_owned)
        .collect::<Vec<_>>()
        .into_iter()
}

fn collect_interfaces() -> Vec<PeerInterface> {
    #[cfg(target_os = "linux")]
    {
        let Ok(text) = output("ip", &["-j", "address", "show"]) else {
            return Vec::new();
        };
        let Ok(rows) = serde_json::from_str::<Vec<serde_json::Value>>(&text) else {
            return Vec::new();
        };
        return rows
            .into_iter()
            .filter_map(|row| {
                let name = row["ifname"].as_str()?.to_owned();
                if !is_advertisable_interface(&name) {
                    return None;
                }
                let mac = row["address"]
                    .as_str()
                    .filter(|value| is_public_mac(value))
                    .map(str::to_lowercase);
                let addresses = row["addr_info"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(|address| address["local"].as_str()?.parse().ok())
                    .filter(is_publishable_address)
                    .collect::<Vec<_>>();
                (!addresses.is_empty() || mac.is_some()).then_some(PeerInterface {
                    name,
                    mac,
                    addresses,
                })
            })
            .collect();
    }
    #[cfg(target_os = "macos")]
    {
        let Ok(text) = output("ifconfig", &[]) else {
            return Vec::new();
        };
        let mut interfaces = Vec::new();
        let mut current = None::<PeerInterface>;
        for line in text.lines() {
            if !line.starts_with(char::is_whitespace) {
                if let Some(interface) = current
                    .take()
                    .filter(|interface| !interface.addresses.is_empty() || interface.mac.is_some())
                {
                    interfaces.push(interface);
                }
                let name = line.split(':').next().unwrap_or_default();
                current = is_advertisable_interface(name).then(|| PeerInterface {
                    name: name.to_owned(),
                    mac: None,
                    addresses: Vec::new(),
                });
                continue;
            }
            let Some(interface) = current.as_mut() else {
                continue;
            };
            let fields = line.split_whitespace().collect::<Vec<_>>();
            match fields.as_slice() {
                ["ether", mac, ..] if is_public_mac(mac) => {
                    interface.mac = Some(mac.to_lowercase());
                }
                ["inet", address, ..] | ["inet6", address, ..] => {
                    let address = address.split('%').next().unwrap_or(address);
                    if let Ok(address) = address.parse::<IpAddr>() {
                        if is_publishable_address(&address) {
                            interface.addresses.push(address);
                        }
                    }
                }
                _ => {}
            }
        }
        if let Some(interface) =
            current.filter(|interface| !interface.addresses.is_empty() || interface.mac.is_some())
        {
            interfaces.push(interface);
        }
        return interfaces;
    }
    #[allow(unreachable_code)]
    Vec::new()
}

fn is_publishable_address(address: &IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => {
            !address.is_loopback() && !address.is_unspecified() && !address.is_link_local()
        }
        IpAddr::V6(address) => {
            !address.is_loopback() && !address.is_unspecified() && !address.is_unicast_link_local()
        }
    }
}

fn is_public_mac(value: &str) -> bool {
    value != "00:00:00:00:00:00" && value.split(':').count() == 6
}

/// Addresses this host actually holds on the overlay interface.
///
/// An overlay attachment is only real where the kernel holds an address for it.
/// Reporting nothing before the WireGuard configuration is applied is the honest
/// answer; inventing an address from the credential would publish a name no
/// packet can reach.
pub(crate) fn local_overlay_addresses(interface: &str) -> Vec<IpAddr> {
    overlay_addresses(&collect_interfaces(), interface)
}

fn overlay_addresses(observed: &[PeerInterface], interface: &str) -> Vec<IpAddr> {
    observed
        .iter()
        .filter(|candidate| candidate.name == interface)
        .flat_map(|candidate| candidate.addresses.iter().copied())
        .collect()
}

/// Interfaces whose addresses describe where a node can be reached.
///
/// Container, VM, and tunnel bridges can number in the hundreds on a busy
/// host, and a `PeerHello` accepts at most 64 interfaces. Advertising them
/// adds no address a peer can dial, and enough of them make every receiver
/// reject the whole hello.
fn is_advertisable_interface(name: &str) -> bool {
    name != "lo"
        && name != "lo0"
        && ![
            "veth", "docker", "br-", "bridge", "virbr", "vmenet", "vmnet", "cni", "flannel", "lxc",
            "lxd", "podman", "sh-", "tap", "tunl",
        ]
        .iter()
        .any(|prefix| name.starts_with(prefix))
}

fn validate_digest(digest: &str) -> Result<(), AnyError> {
    if digest.len() != 64 || !digest.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("artifact digest must be 64 hexadecimal characters".into());
    }
    Ok(())
}

fn validate_release_label(name: &str, value: &str) -> Result<(), AnyError> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._+-".contains(&byte))
    {
        return Err(format!("{name} must contain 1-128 safe ASCII characters").into());
    }
    Ok(())
}

fn validate_access_identity(name: &str, value: &str) -> Result<(), AnyError> {
    // Principals are opaque identity-provider identifiers, not local labels.
    // In particular, the OIDC adapter emits `oidc:<issuer>#<subject>` values.
    if value.is_empty() || value.len() > 512 || !value.bytes().all(|byte| byte.is_ascii_graphic()) {
        return Err(format!(
            "{name} must contain 1-512 printable ASCII characters without whitespace"
        )
        .into());
    }
    Ok(())
}

fn validate_access_selector(name: &str, value: &str) -> Result<(), AnyError> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._+:-/".contains(&byte))
    {
        return Err(format!("{name} must contain 1-128 safe ASCII selector characters").into());
    }
    Ok(())
}

fn validate_access_statement(statement: &AccessStatement) -> Result<(), AnyError> {
    match statement {
        AccessStatement::Grant {
            grant_id,
            principal,
            roles,
            scopes,
            unix_users,
            ssh_public_keys,
            oidc_audiences,
            not_before,
            not_after,
            ..
        } => {
            validate_release_label("grant_id", grant_id)?;
            validate_access_identity("principal", principal)?;
            for (name, values) in [("role", roles), ("scope", scopes)] {
                for value in values {
                    validate_access_selector(name, value)?;
                }
            }
            for value in unix_users {
                validate_release_label("unix_user", value)?;
            }
            for value in oidc_audiences {
                validate_access_identity("oidc_audience", value)?;
            }
            if ssh_public_keys.len() > 32
                || ssh_public_keys.iter().any(|key| {
                    key.len() > 16_384
                        || !(key.starts_with("ssh-ed25519 ")
                            || key.starts_with("ecdsa-sha2-")
                            || key.starts_with("sk-ssh-ed25519@openssh.com "))
                })
            {
                return Err("grant contains an invalid SSH public key".into());
            }
            if not_after <= not_before {
                return Err("grant not_after must be later than not_before".into());
            }
        }
        AccessStatement::Revoke {
            revocation_id,
            grant_id,
            principal,
            serial,
            reason,
            ..
        } => {
            validate_release_label("revocation_id", revocation_id)?;
            if grant_id.is_none() && principal.is_none() && serial.is_none() {
                return Err("revocation needs grant_id, principal, or serial".into());
            }
            if let Some(value) = grant_id {
                validate_release_label("grant_id", value)?;
            }
            if let Some(value) = principal {
                validate_access_identity("principal", value)?;
            }
            if reason.is_empty() || reason.len() > 512 || reason.contains(['\n', '\r']) {
                return Err("revocation reason must be 1-512 characters on one line".into());
            }
        }
    }
    Ok(())
}

fn validate_authority_statement(statement: &AuthorityStatement) -> Result<(), AnyError> {
    match statement {
        AuthorityStatement::Delegate {
            delegation_id,
            subject,
            capabilities,
            not_before,
            not_after,
        } => {
            validate_release_label("delegation_id", delegation_id)?;
            decode_hex(subject).map_err(|error| format!("invalid authority subject: {error}"))?;
            if capabilities.is_empty() {
                return Err("delegation must contain at least one capability".into());
            }
            if not_after <= not_before {
                return Err("delegation not_after must be later than not_before".into());
            }
        }
        AuthorityStatement::Revoke {
            revocation_id,
            delegation_id,
            reason,
            ..
        } => {
            validate_release_label("revocation_id", revocation_id)?;
            validate_release_label("delegation_id", delegation_id)?;
            if reason.is_empty() || reason.len() > 512 {
                return Err("revocation reason must contain 1-512 characters".into());
            }
        }
    }
    Ok(())
}

fn artifact_path(digest: &str) -> Result<std::path::PathBuf, AnyError> {
    validate_digest(digest)?;
    Ok(crate::artifacts_dir().join(digest))
}

fn seed_artifact_file(
    source: &Path,
    destination: &Path,
    digest: &str,
    expected_size: u64,
) -> Result<bool, AnyError> {
    let verify = |path: &Path| -> Result<(), AnyError> {
        let bytes = std::fs::read(path)?;
        if bytes.len() as u64 != expected_size || sha256_hex(&bytes) != digest {
            return Err(format!(
                "{} does not match signed artifact size and digest",
                path.display()
            )
            .into());
        }
        Ok(())
    };
    if destination.is_file() {
        verify(destination)?;
        return Ok(true);
    }
    verify(source)?;
    let parent = destination
        .parent()
        .ok_or("artifact cache path has no parent")?;
    std::fs::create_dir_all(parent)?;
    let temp = destination.with_extension(format!(
        "seed-{}-{}",
        std::process::id(),
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos()
    ));
    std::fs::copy(source, &temp)?;
    if let Err(error) = std::fs::rename(&temp, destination) {
        let _ = std::fs::remove_file(&temp);
        return Err(error.into());
    }
    Ok(false)
}

fn partial_artifact_path(digest: &str) -> Result<std::path::PathBuf, AnyError> {
    validate_digest(digest)?;
    Ok(crate::artifacts_dir().join(format!("{digest}.part")))
}

fn artifact_chunk(digest: &str, offset: u64, length: u32) -> Result<Option<PeerMessage>, AnyError> {
    if length == 0 || length > 65_536 {
        return Err("artifact request length must be 1 through 65536".into());
    }
    let path = artifact_path(digest)?;
    let Ok(mut file) = std::fs::File::open(path) else {
        return Ok(None);
    };
    let size = file.metadata()?.len();
    if offset > size {
        return Err("artifact request offset exceeds file size".into());
    }
    file.seek(SeekFrom::Start(offset))?;
    let mut data = vec![0; length as usize];
    let count = file.read(&mut data)?;
    data.truncate(count);
    Ok(Some(PeerMessage::ArtifactChunk {
        digest: digest.into(),
        offset,
        data: encode_hex(&data),
        complete: offset + count as u64 == size,
    }))
}

fn accept_artifact_chunk(
    digest: &str,
    offset: u64,
    encoded: &str,
    complete: bool,
    releases: &[ReleaseManifest],
    packages: &[PackageManifest],
) -> Result<(), AnyError> {
    let signed_bounds = releases
        .iter()
        .find(|release| release.artifact_digest == digest)
        .map(|release| release.artifact_size)
        .or_else(|| {
            packages
                .iter()
                .find(|package| package.artifact_digest == digest)
                .map(|package| package.artifact_size)
        })
        .ok_or("artifact has no trusted release or package manifest")?;
    let data = decode_hex(encoded).map_err(|error| format!("artifact chunk: {error}"))?;
    if data.len() > 65_536 || offset + data.len() as u64 > signed_bounds {
        return Err("artifact chunk exceeds signed bounds".into());
    }
    std::fs::create_dir_all(crate::artifacts_dir())?;
    let partial = partial_artifact_path(digest)?;
    let current = std::fs::metadata(&partial)
        .map(|metadata| metadata.len())
        .unwrap_or(0);
    if current != offset {
        return Ok(());
    }
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&partial)?;
    file.write_all(&data)?;
    file.sync_data()?;
    if complete {
        let bytes = std::fs::read(&partial)?;
        if bytes.len() as u64 != signed_bounds || sha256_hex(&bytes) != digest {
            return Err("completed artifact does not match signed size and digest".into());
        }
        std::fs::rename(partial, artifact_path(digest)?)?;
    }
    Ok(())
}

fn persist_observations(values: &[SignedEnvelope]) -> Result<(), AnyError> {
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let path = crate::peer_observations_path();
    // The rename is atomic, the write is not: a second writer must never land in
    // this one's temporary file, or the published document holds both.
    let temp = path.with_extension(format!(
        "json.{}.{}.tmp",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::write(&temp, serde_json::to_vec_pretty(values)?)?;
    std::fs::rename(temp, path)?;
    Ok(())
}

fn load_or_create_key(path: &Path) -> Result<SigningKey, AnyError> {
    match std::fs::read(path) {
        Ok(bytes) => Ok(SigningKey::from_bytes(
            bytes
                .as_slice()
                .try_into()
                .map_err(|_| "peer.key must be exactly 32 bytes")?,
        )),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let key = SigningKey::generate(&mut OsRng);
            std::fs::write(path, key.to_bytes())?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
            }
            Ok(key)
        }
        Err(error) => Err(error.into()),
    }
}

fn certs(path: &str) -> Result<Vec<CertificateDer<'static>>, AnyError> {
    rustls_pemfile::certs(&mut StdBufReader::new(std::fs::File::open(path)?))
        .collect::<Result<Vec<_>, _>>()
        .map_err(Into::into)
}

fn tls_peer_fingerprint(certificates: Option<&[CertificateDer<'_>]>) -> Option<String> {
    certificates
        .and_then(|chain| chain.first())
        .map(|certificate| mycelium_peer_protocol::sha256_hex(certificate.as_ref()))
}

fn private_key(path: &str) -> Result<PrivateKeyDer<'static>, AnyError> {
    rustls_pemfile::private_key(&mut StdBufReader::new(std::fs::File::open(path)?))?
        .ok_or_else(|| "PEM file contains no private key".into())
}

fn server_name(name: &str) -> Result<ServerName<'static>, AnyError> {
    if let Ok(ip) = name.parse::<IpAddr>() {
        Ok(ServerName::IpAddress(ip.into()))
    } else {
        Ok(ServerName::try_from(name.to_owned())?)
    }
}

/// Split a peer seed into its optional expected certificate name and its
/// `host:port` address.
///
/// A stable fleet name lets a seed survive a node changing networks:
/// `mac-studio.wagar-house.myc@192.168.2.3:7443` is verified against the
/// certificate name, so the address is only a rendezvous hint.
fn split_seed(seed: &str) -> Result<(Option<&str>, &str), AnyError> {
    match seed.split_once('@') {
        Some((name, address)) if name.is_empty() || address.is_empty() => {
            Err("seed must be name@host:port".into())
        }
        Some((name, address)) => Ok((Some(name), address)),
        None => Ok((None, seed)),
    }
}

fn platform() -> Platform {
    #[cfg(target_os = "macos")]
    return Platform::Darwin;
    #[cfg(not(target_os = "macos"))]
    Platform::Linux
}

pub(crate) fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn collect_health() -> Result<HostHealth, AnyError> {
    #[cfg(target_os = "linux")]
    let mut health = collect_linux()?;
    #[cfg(target_os = "macos")]
    let mut health = collect_darwin()?;
    add_update_health(&mut health);
    add_frontdoor_usage(&mut health);
    Ok(health)
}

/// Publish the token counters the local frontdoor persists so every peer can
/// roll them up. A snapshot that is not fresh is dropped instead of gossiped: a
/// frontdoor that stopped running must not look like a fleet that went quiet.
fn add_frontdoor_usage(health: &mut HostHealth) {
    let home = crate::home_dir();
    // The old directory stays readable until the frontdoor migration has run.
    let Some(path) = [
        home.join("frontdoor/usage.json"),
        home.join("gateway/usage.json"),
    ]
    .into_iter()
    .find(|path| path.is_file()) else {
        return;
    };
    let Ok(bytes) = std::fs::read(&path) else {
        return;
    };
    match frontdoor_usage_metrics(&bytes, now()) {
        Ok(Some(metrics)) => health.platform_metrics.extend(metrics),
        // A frontdoor that is not running (or has just started) publishes
        // nothing. Peers already drop metrics that are not fresh, so this is not
        // an error worth repeating on every health tick.
        Ok(None) => {}
        Err(error) => eprintln!("frontdoor usage: {}: {error}", path.display()),
    }
}

fn frontdoor_usage_metrics(
    bytes: &[u8],
    now: u64,
) -> Result<Option<BTreeMap<String, String>>, String> {
    use mycelium_peer_protocol::frontdoor_usage::{
        FrontdoorUsageMetrics, FrontdoorUsageSnapshot, FRONTDOOR_USAGE_SCHEMA_VERSION,
    };
    let snapshot: FrontdoorUsageSnapshot =
        serde_json::from_slice(bytes).map_err(|error| format!("unreadable usage: {error}"))?;
    if snapshot.schema_version != FRONTDOOR_USAGE_SCHEMA_VERSION {
        return Err(format!(
            "unsupported usage schema {}",
            snapshot.schema_version
        ));
    }
    let metrics = FrontdoorUsageMetrics::from_snapshot(&snapshot);
    if !metrics.is_fresh(now) {
        return Ok(None);
    }
    Ok(Some(metrics.to_platform_metrics()))
}

fn add_update_health(health: &mut HostHealth) {
    let state = crate::read_update_state();
    if let Ok(executable) = std::env::current_exe() {
        if let Ok(bytes) = std::fs::read(executable) {
            health.platform_metrics.insert(
                "mycelium_update.installed_digest".into(),
                mycelium_peer_protocol::sha256_hex(&bytes),
            );
        }
    }
    if let Some(value) = state.release_version {
        health
            .platform_metrics
            .insert("mycelium_update.release_version".into(), value);
    }
    if let Some(value) = state.release_target {
        health
            .platform_metrics
            .insert("mycelium_update.release_target".into(), value);
    }
    if !state.activation_state.is_empty() {
        health.platform_metrics.insert(
            "mycelium_update.activation_state".into(),
            state.activation_state,
        );
    }
    if let Some(value) = state.last_error {
        health
            .platform_metrics
            .insert("mycelium_update.last_error".into(), value);
    }
}

#[cfg(target_os = "linux")]
fn collect_linux() -> Result<HostHealth, AnyError> {
    let uptime_seconds = first_number(&std::fs::read_to_string("/proc/uptime")?)? as u64;
    let load_average = three_numbers(&std::fs::read_to_string("/proc/loadavg")?)?;
    let memory = parse_linux_memory(&std::fs::read_to_string("/proc/meminfo")?);
    let mut platform_metrics = BTreeMap::new();
    for kind in ["cpu", "memory", "io"] {
        if let Ok(value) = std::fs::read_to_string(format!("/proc/pressure/{kind}")) {
            platform_metrics.insert(format!("pressure_{kind}"), value.trim().into());
        }
    }
    if let Some((overflows, drops)) =
        linux_listen_drops(&std::fs::read_to_string("/proc/net/netstat").unwrap_or_default())
    {
        platform_metrics.insert("tcp_listen_overflows".into(), overflows.to_string());
        platform_metrics.insert("tcp_listen_drops".into(), drops.to_string());
    }
    let ssh = output("ss", &["-H", "-lnt"])?;
    let sessions = output("ss", &["-H", "-nt", "state", "established"])?;
    Ok(HostHealth {
        observed_at: now(),
        uptime_seconds,
        load_average,
        logical_cpus: std::thread::available_parallelism()?.get() as u32,
        memory_total_bytes: memory.get("MemTotal").copied().unwrap_or(0) * 1024,
        memory_available_bytes: memory.get("MemAvailable").copied().unwrap_or(0) * 1024,
        swap_total_bytes: memory.get("SwapTotal").copied().unwrap_or(0) * 1024,
        swap_free_bytes: memory.get("SwapFree").copied().unwrap_or(0) * 1024,
        filesystems: root_filesystem()?,
        process_leaders: process_leaders(&["-eo", "pid=,pcpu=,pmem=,comm=", "--sort=-pcpu"])?,
        ssh_listening: ssh.lines().any(|line| local_port(line, 22)),
        established_ssh_sessions: sessions.lines().filter(|line| local_port(line, 22)).count()
            as u32,
        power: linux_power(),
        link: linux_link(),
        platform_metrics,
    })
}

#[cfg(target_os = "macos")]
fn collect_darwin() -> Result<HostHealth, AnyError> {
    let boot = output("/usr/sbin/sysctl", &["-n", "kern.boottime"])?;
    let boot_seconds = boot
        .split("sec =")
        .nth(1)
        .and_then(|v| v.trim().split(',').next())
        .and_then(|v| v.parse().ok())
        .ok_or("cannot parse kern.boottime")?;
    let load_average = three_numbers(
        output("/usr/sbin/sysctl", &["-n", "vm.loadavg"])?.trim_matches(|c| c == '{' || c == '}'),
    )?;
    let page_size = output("/usr/sbin/sysctl", &["-n", "hw.pagesize"])?
        .trim()
        .parse::<u64>()?;
    let memory_total_bytes = output("/usr/sbin/sysctl", &["-n", "hw.memsize"])?
        .trim()
        .parse::<u64>()?;
    let vm = output("/usr/bin/vm_stat", &[])?;
    let memory_available_bytes = (darwin_pages(&vm, "Pages free")
        + darwin_pages(&vm, "Pages inactive")
        + darwin_pages(&vm, "Pages speculative")
        + darwin_pages(&vm, "Pages purgeable"))
        * page_size;
    let (swap_total_bytes, swap_free_bytes) =
        parse_darwin_swap(&output("/usr/sbin/sysctl", &["-n", "vm.swapusage"])?);
    let sockets = output("/usr/sbin/lsof", &["-nP", "-iTCP:22"]).unwrap_or_default();
    Ok(HostHealth {
        observed_at: now(),
        uptime_seconds: now().saturating_sub(boot_seconds),
        load_average,
        logical_cpus: std::thread::available_parallelism()?.get() as u32,
        memory_total_bytes,
        memory_available_bytes,
        swap_total_bytes,
        swap_free_bytes,
        filesystems: root_filesystem()?,
        process_leaders: process_leaders(&["-axo", "pid=,pcpu=,pmem=,comm=", "-r"])?,
        ssh_listening: sockets
            .lines()
            .any(|line| line.contains("(LISTEN)") && darwin_local_port(line, 22)),
        established_ssh_sessions: sockets
            .lines()
            .filter(|line| line.contains("(ESTABLISHED)") && darwin_local_port(line, 22))
            .count() as u32,
        power: darwin_power(),
        link: darwin_link(),
        platform_metrics: BTreeMap::new(),
    })
}

/// Power source from sysfs.
///
/// A machine with no battery is mains by construction. With a battery, mains is
/// only claimed when a supply reports itself online; anything ambiguous stays
/// `Unknown`, because `Unknown` does not exclude a host while `Battery` does.
#[cfg(target_os = "linux")]
fn linux_power() -> mycelium_peer_protocol::PowerSource {
    use mycelium_peer_protocol::PowerSource;
    let Ok(entries) = std::fs::read_dir("/sys/class/power_supply") else {
        return PowerSource::Unknown;
    };
    let mut seen = false;
    let mut has_battery = false;
    let mut on_mains = false;
    for entry in entries.flatten() {
        let kind = std::fs::read_to_string(entry.path().join("type")).unwrap_or_default();
        match kind.trim() {
            "Battery" => {
                seen = true;
                has_battery = true;
            }
            "Mains" | "USB" | "USB_C" => {
                seen = true;
                if let Ok(online) = std::fs::read_to_string(entry.path().join("online")) {
                    on_mains |= online.trim() == "1";
                }
            }
            _ => {}
        }
    }
    match (seen, has_battery, on_mains) {
        (false, _, _) => PowerSource::Unknown,
        (true, false, _) => PowerSource::Mains,
        (true, true, true) => PowerSource::Mains,
        (true, true, false) => PowerSource::Battery,
    }
}

/// Link kind of the interface carrying the default route.
#[cfg(target_os = "linux")]
fn linux_link() -> mycelium_peer_protocol::LinkKind {
    use mycelium_peer_protocol::LinkKind;
    let route = std::fs::read_to_string("/proc/net/route").unwrap_or_default();
    let Some(interface) = route.lines().skip(1).find_map(|line| {
        let mut fields = line.split_whitespace();
        let name = fields.next()?;
        let destination = fields.next()?;
        (destination == "00000000").then(|| name.to_owned())
    }) else {
        return LinkKind::Unknown;
    };
    let base = format!("/sys/class/net/{interface}");
    if std::path::Path::new(&format!("{base}/wireless")).exists() {
        LinkKind::Wireless
    } else if std::path::Path::new(&base).exists() {
        LinkKind::Wired
    } else {
        LinkKind::Unknown
    }
}

/// Power source as reported by the power management daemon.
#[cfg(target_os = "macos")]
fn darwin_power() -> mycelium_peer_protocol::PowerSource {
    use mycelium_peer_protocol::PowerSource;
    let Ok(battery) = output("/usr/bin/pmset", &["-g", "batt"]) else {
        return PowerSource::Unknown;
    };
    if battery.contains("AC Power") {
        PowerSource::Mains
    } else if battery.contains("Battery Power") {
        PowerSource::Battery
    } else {
        PowerSource::Unknown
    }
}

/// Link kind of the interface carrying the default route.
#[cfg(target_os = "macos")]
fn darwin_link() -> mycelium_peer_protocol::LinkKind {
    use mycelium_peer_protocol::LinkKind;
    let Ok(route) = output("/sbin/route", &["-n", "get", "default"]) else {
        return LinkKind::Unknown;
    };
    let Some(interface) = route
        .lines()
        .find_map(|line| line.trim().strip_prefix("interface:").map(str::trim))
    else {
        return LinkKind::Unknown;
    };
    // A Thunderbolt or USB adapter reports as "Ethernet" and is still wired.
    let ports = output("/usr/sbin/networksetup", &["-listallhardwareports"]).unwrap_or_default();
    let mut port = None;
    let mut lines = ports.lines();
    while let Some(line) = lines.next() {
        if let Some(name) = line.trim().strip_prefix("Hardware Port:") {
            let device = lines.next().unwrap_or_default().trim();
            if device == format!("Device: {interface}") {
                port = Some(name.trim().to_owned());
                break;
            }
        }
    }
    match port.as_deref() {
        Some("Wi-Fi") | Some("AirPort") => LinkKind::Wireless,
        Some(_) => LinkKind::Wired,
        None => LinkKind::Unknown,
    }
}

fn output(command: &str, args: &[&str]) -> Result<String, AnyError> {
    let result = Command::new(command).args(args).output()?;
    if !result.status.success() {
        return Err(format!("{command} exited {}", result.status).into());
    }
    Ok(String::from_utf8(result.stdout)?)
}
#[cfg(target_os = "linux")]
fn first_number(text: &str) -> Result<f64, AnyError> {
    Ok(text
        .split_whitespace()
        .next()
        .ok_or("missing number")?
        .parse()?)
}
fn three_numbers(text: &str) -> Result<[f64; 3], AnyError> {
    text.split_whitespace()
        .filter_map(|v| v.parse().ok())
        .take(3)
        .collect::<Vec<f64>>()
        .try_into()
        .map_err(|_| "expected three load averages".into())
}
#[cfg(target_os = "linux")]
fn parse_linux_memory(text: &str) -> BTreeMap<String, u64> {
    text.lines()
        .filter_map(|line| {
            let (name, value) = line.split_once(':')?;
            Some((name.into(), value.split_whitespace().next()?.parse().ok()?))
        })
        .collect()
}
#[cfg(any(target_os = "linux", test))]
fn linux_listen_drops(text: &str) -> Option<(u64, u64)> {
    for pair in text.lines().collect::<Vec<_>>().windows(2) {
        if pair[0].starts_with("TcpExt:") && pair[1].starts_with("TcpExt:") {
            let names = pair[0].split_whitespace().skip(1).collect::<Vec<_>>();
            let values = pair[1].split_whitespace().skip(1).collect::<Vec<_>>();
            let get = |name| {
                values
                    .get(names.iter().position(|item| *item == name)?)?
                    .parse()
                    .ok()
            };
            return Some((get("ListenOverflows")?, get("ListenDrops")?));
        }
    }
    None
}
fn root_filesystem() -> Result<Vec<FilesystemHealth>, AnyError> {
    let text = output("df", &["-Pk", "/"])?;
    let fields = text
        .lines()
        .last()
        .ok_or("df returned no filesystem")?
        .split_whitespace()
        .collect::<Vec<_>>();
    if fields.len() < 6 {
        return Err("unexpected df output".into());
    }
    Ok(vec![FilesystemHealth {
        mount: fields[5].into(),
        total_bytes: fields[1].parse::<u64>()? * 1024,
        available_bytes: fields[3].parse::<u64>()? * 1024,
    }])
}
fn process_leaders(args: &[&str]) -> Result<Vec<ProcessHealth>, AnyError> {
    Ok(output("ps", args)?
        .lines()
        .filter_map(|line| {
            let mut f = line.split_whitespace();
            Some(ProcessHealth {
                pid: f.next()?.parse().ok()?,
                cpu_percent: f.next()?.parse().ok()?,
                memory_percent: f.next()?.parse().ok()?,
                name: f.collect::<Vec<_>>().join(" "),
            })
        })
        .take(10)
        .collect())
}
#[cfg(target_os = "linux")]
fn local_port(line: &str, port: u16) -> bool {
    line.split_whitespace()
        .any(|field| field.ends_with(&format!(":{port}")) || field.ends_with(&format!(".{port}")))
}
#[cfg(target_os = "macos")]
fn darwin_local_port(line: &str, port: u16) -> bool {
    line.split_whitespace()
        .find(|field| field.contains(':'))
        .and_then(|field| field.split("->").next())
        .map(|local| local.ends_with(&format!(":{port}")))
        .unwrap_or(false)
}
#[cfg(target_os = "macos")]
fn darwin_pages(text: &str, name: &str) -> u64 {
    text.lines()
        .find(|line| line.starts_with(name))
        .and_then(|line| line.split(':').nth(1))
        .map(|v| v.trim().trim_end_matches('.'))
        .and_then(|v| v.parse().ok())
        .unwrap_or(0)
}
#[cfg(target_os = "macos")]
fn parse_darwin_swap(text: &str) -> (u64, u64) {
    let words = text.split_whitespace().collect::<Vec<_>>();
    let mib = |label| {
        words
            .iter()
            .position(|word| *word == label)
            .and_then(|i| words.get(i + 2))
            .and_then(|v| v.trim_end_matches('M').parse::<f64>().ok())
            .map(|v| (v * 1_048_576.0) as u64)
            .unwrap_or(0)
    };
    (mib("total"), mib("free"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn overlay_addresses_come_from_the_named_interface_only() {
        let observed = vec![
            PeerInterface {
                name: "en0".into(),
                mac: None,
                addresses: vec!["192.168.2.3".parse().unwrap()],
            },
            PeerInterface {
                name: "mycelium0".into(),
                mac: None,
                addresses: vec!["10.9.0.1".parse().unwrap(), "fd00:9::1".parse().unwrap()],
            },
        ];
        assert_eq!(
            overlay_addresses(&observed, "mycelium0"),
            vec![
                "10.9.0.1".parse::<IpAddr>().unwrap(),
                "fd00:9::1".parse().unwrap()
            ]
        );
        // No interface means no address; the attachment is not claimed yet.
        assert!(overlay_addresses(&observed, "utun9").is_empty());
    }

    #[test]
    fn container_and_tunnel_bridges_are_not_advertised() {
        for name in ["en0", "enp87s0", "eth0", "tailscale0", "wlan0"] {
            assert!(
                is_advertisable_interface(name),
                "{name} should be advertised"
            );
        }
        for name in [
            "lo",
            "lo0",
            "veth1234",
            "docker0",
            "br-2f4a",
            "bridge100",
            "vmenet0",
            "sh-mg0",
            "tap0",
        ] {
            assert!(!is_advertisable_interface(name), "{name} should be skipped");
        }
    }

    #[test]
    fn peer_seeds_split_into_an_optional_certificate_name() {
        assert_eq!(
            split_seed("mac-studio.wagar-house.myc@192.168.2.3:7443").unwrap(),
            (Some("mac-studio.wagar-house.myc"), "192.168.2.3:7443")
        );
        assert_eq!(
            split_seed("100.80.85.86:7443").unwrap(),
            (None, "100.80.85.86:7443")
        );
        assert!(split_seed("@100.80.85.86:7443").is_err());
        assert!(split_seed("neo@").is_err());
    }

    fn usage_document(generated_at: u64, schema_version: u16) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "schema_version": schema_version,
            "generated_at": generated_at,
            "window_seconds": 60,
            "totals": {"requests": 3, "metered_requests": 2,
                "prompt_tokens": 40, "completion_tokens": 12},
            "window": {"requests": 1, "completion_tokens": 4, "generation_millis": 1000}
        }))
        .unwrap()
    }

    #[test]
    fn fresh_frontdoor_usage_is_gossiped_and_stale_usage_is_dropped() {
        let metrics = frontdoor_usage_metrics(&usage_document(1_000, 1), 1_060)
            .unwrap()
            .unwrap();
        assert_eq!(
            metrics
                .get("mycelium_ai.completion_tokens")
                .map(String::as_str),
            Some("12")
        );
        assert_eq!(
            metrics
                .get("mycelium_ai.window_completion_tokens")
                .map(String::as_str),
            Some("4")
        );
        // A stopped gateway must not report yesterday's traffic as current, and
        // being stopped is a state rather than an error to log on every tick.
        assert!(frontdoor_usage_metrics(
            &usage_document(1_000, 1),
            1_000 + mycelium_peer_protocol::frontdoor_usage::FRONTDOOR_USAGE_MAX_AGE_SECONDS + 1
        )
        .unwrap()
        .is_none());
    }

    #[test]
    fn usage_from_another_schema_is_not_reinterpreted() {
        assert!(frontdoor_usage_metrics(&usage_document(1_000, 99), 1_060).is_err());
        assert!(frontdoor_usage_metrics(b"not json", 1_060).is_err());
    }

    #[test]
    fn renewal_gossip_is_origin_bound_and_slot_bounded() {
        let key = SigningKey::from_bytes(&[9; 32]);
        let request = mycelium_peer_protocol::SshRenewalRequest::sign(
            "request-1".into(),
            100,
            "ssh-ed25519 AAAA".into(),
            &key,
        )
        .unwrap();
        let first = SignedEnvelope::sign(
            &key,
            1,
            100,
            PeerEvent::SshCredentialRequest(request.clone()),
        )
        .unwrap();
        let second = SignedEnvelope::sign(
            &key,
            2,
            101,
            PeerEvent::SshCredentialRequest(request.clone()),
        )
        .unwrap();
        assert_eq!(event_key(&first), event_key(&second));
        assert!(event_origin_matches(&first));
        let forged = SignedEnvelope::sign(
            &SigningKey::from_bytes(&[8; 32]),
            1,
            100,
            PeerEvent::SshCredentialRequest(request),
        )
        .unwrap();
        assert!(!event_origin_matches(&forged));
        let empty = BTreeSet::new();
        let resolver = crate::authority::AuthorityResolver::new(&empty, &empty, &empty, [], 100);
        assert!(event_is_authorized(&first, &empty, &resolver));
        assert!(!event_is_authorized(&forged, &empty, &resolver));
        let delivery = mycelium_peer_protocol::SshRenewalDelivery {
            node_id: first.origin.clone(),
            response: mycelium_peer_protocol::SshRenewalResponse {
                request_id: "request-1".into(),
                certificate: None,
                expires_at: None,
                error: Some("denied".into()),
            },
        };
        for (count, allowed) in [(32, true), (33, false)] {
            let envelope = SignedEnvelope::sign(
                &key,
                1,
                100,
                PeerEvent::SshCredentialResponses(vec![delivery.clone(); count]),
            )
            .unwrap();
            assert_eq!(event_is_authorized(&envelope, &empty, &resolver), allowed);
        }
    }

    #[test]
    fn observation_batches_are_bounded_by_wire_size() {
        let key = SigningKey::from_bytes(&[31; 32]);
        let observations = (1..=3)
            .map(|sequence| {
                SignedEnvelope::sign(
                    &key,
                    sequence,
                    sequence,
                    PeerEvent::Topology(TopologySnapshot {
                        schema_version: 1,
                        topology: serde_json::json!({"payload": "x".repeat(480_000)}),
                    }),
                )
                .unwrap()
            })
            .collect();
        let batches = observation_batches(observations).unwrap();
        assert_eq!(batches.len(), 3);
        assert!(batches.iter().all(|batch| {
            serde_json::to_vec(&PeerMessage::Observations(batch.clone()))
                .unwrap()
                .len()
                < 1_048_576
        }));
    }

    #[test]
    fn oversized_observation_does_not_block_smaller_events() {
        let key = SigningKey::from_bytes(&[32; 32]);
        let oversized = SignedEnvelope::sign(
            &key,
            1,
            1,
            PeerEvent::Topology(TopologySnapshot {
                schema_version: 1,
                topology: serde_json::json!({"payload": "x".repeat(MAX_OBSERVATION_MESSAGE_BYTES)}),
            }),
        )
        .unwrap();
        let hello = SignedEnvelope::sign(&key, 2, 2, PeerEvent::Hello(test_hello(&key))).unwrap();
        let batches = observation_batches(vec![oversized, hello]).unwrap();
        assert_eq!(batches.len(), 1);
        assert_eq!(batches[0].len(), 1);
        assert!(matches!(batches[0][0].event, PeerEvent::Hello(_)));
    }

    fn test_hello(key: &SigningKey) -> PeerHello {
        PeerHello {
            node_id: encode_hex(key.verifying_key().as_bytes()),
            protocol_version: PROTOCOL_VERSION,
            site: "test".into(),
            hostname: "test".into(),
            platform: Platform::Linux,
            architecture: "x86_64".into(),
            daemon_version: "test".into(),
            capabilities: Vec::new(),
            interfaces: Vec::new(),
        }
    }

    #[tokio::test]
    async fn peer_framing_bounds_and_cancellation() {
        let (mut writer, stream) = tokio::io::duplex(64);
        let mut reader = BufReader::new(stream);
        let mut pending = Vec::new();
        writer.write_all(b"partial").await.unwrap();
        assert!(tokio::time::timeout(
            Duration::from_millis(10),
            next_peer_line(&mut reader, &mut pending)
        )
        .await
        .is_err());
        assert_eq!(pending, b"partial");
        writer.write_all(b" complete\nnext\n").await.unwrap();
        assert_eq!(
            next_peer_line(&mut reader, &mut pending)
                .await
                .unwrap()
                .unwrap(),
            "partial complete"
        );
        assert_eq!(
            next_peer_line(&mut reader, &mut pending)
                .await
                .unwrap()
                .unwrap(),
            "next"
        );
        let oversized = vec![b'x'; 1_048_578];
        let mut reader = BufReader::new(&oversized[..]);
        assert!(next_peer_line(&mut reader, &mut pending).await.is_err());
        assert!(pending.len() <= 1_048_577);
    }

    fn test_dir(name: &str) -> std::path::PathBuf {
        crate::test_dir(name)
    }

    fn oidc_grant(principal: &str) -> AccessStatement {
        AccessStatement::Grant {
            grant_id: "grant-1".into(),
            principal: principal.into(),
            serial: 1,
            roles: vec!["operator".into()],
            scopes: vec!["site:home".into()],
            unix_users: vec!["avery".into()],
            ssh_public_keys: vec![],
            oidc_audiences: vec!["mycelium".into()],
            oidc_ssh_key_exchange: true,
            not_before: 1,
            not_after: 2,
        }
    }

    #[test]
    fn access_validation_accepts_normalized_oidc_principal() {
        validate_access_statement(&oidc_grant("oidc:https://identity.example#subject-42")).unwrap();
    }

    #[test]
    fn access_validation_rejects_principal_with_whitespace() {
        assert!(validate_access_statement(&oidc_grant(
            "oidc:https://identity.example#bad\nsubject"
        ))
        .is_err());
    }

    #[test]
    fn listen_drop_parser_maps_header_to_values() {
        assert_eq!(
            linux_listen_drops("TcpExt: Foo ListenOverflows ListenDrops\nTcpExt: 1 7 9\n"),
            Some((7, 9))
        );
    }

    #[test]
    fn seeded_artifact_is_verified_and_idempotent() {
        let dir = test_dir("seed");
        let source = dir.join("binary");
        let destination = dir.join("cache").join("artifact");
        let bytes = b"same ARM64 release bytes";
        std::fs::write(&source, bytes).unwrap();
        let digest = sha256_hex(bytes);

        assert!(!seed_artifact_file(&source, &destination, &digest, bytes.len() as u64).unwrap());
        assert!(seed_artifact_file(&source, &destination, &digest, bytes.len() as u64).unwrap());
        assert_eq!(std::fs::read(&destination).unwrap(), bytes);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn seeded_artifact_rejects_unmatching_bytes() {
        let dir = test_dir("seed-mismatch");
        let source = dir.join("binary");
        let destination = dir.join("cache").join("artifact");
        std::fs::write(&source, b"wrong bytes").unwrap();
        let expected = b"authorized bytes";

        let error = seed_artifact_file(
            &source,
            &destination,
            &sha256_hex(expected),
            expected.len() as u64,
        )
        .unwrap_err();
        assert!(error.to_string().contains("does not match signed artifact"));
        assert!(!destination.exists());
        std::fs::remove_dir_all(dir).unwrap();
    }
    #[cfg(target_os = "macos")]
    #[test]
    fn darwin_ssh_count_uses_local_endpoint() {
        assert!(!darwin_local_port(
            "ssh 1 user 3u IPv4 x TCP 10.0.0.2:50000->10.0.0.3:22 (ESTABLISHED)",
            22
        ));
        assert!(darwin_local_port(
            "sshd 1 root 3u IPv4 x TCP 10.0.0.2:22->10.0.0.3:50000 (ESTABLISHED)",
            22
        ));
    }
}
