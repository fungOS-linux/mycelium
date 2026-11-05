//! Symmetric, transport-neutral messages exchanged by Mycelium peers.

pub mod identity;

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const PROTOCOL_VERSION: u16 = 1;

/// The Rust target of the currently running binary. Publication uses this
/// when the build pipeline does not provide an explicit target.
pub fn local_build_target() -> String {
    #[cfg(target_os = "macos")]
    let os = "apple-darwin";
    #[cfg(all(target_os = "linux", target_env = "musl"))]
    let os = "unknown-linux-musl";
    #[cfg(all(target_os = "linux", not(target_env = "musl")))]
    let os = "unknown-linux-gnu";
    format!("{}-{os}", std::env::consts::ARCH)
}

/// Release targets executable by this host, in preference order. Linux can
/// migrate from a dynamically linked GNU build to a portable static musl
/// build; Darwin remains ABI-specific.
pub fn local_compatible_targets() -> Vec<String> {
    compatible_targets(std::env::consts::ARCH, std::env::consts::OS)
}

fn compatible_targets(architecture: &str, os: &str) -> Vec<String> {
    match os {
        "linux" => vec![
            format!("{architecture}-unknown-linux-musl"),
            format!("{architecture}-unknown-linux-gnu"),
        ],
        "macos" => vec![format!("{architecture}-apple-darwin")],
        other => vec![format!("{architecture}-{other}")],
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Platform {
    Linux,
    Darwin,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerHello {
    /// Hex-encoded Ed25519 public key; also the stable node identity.
    pub node_id: String,
    pub protocol_version: u16,
    pub site: String,
    pub hostname: String,
    pub platform: Platform,
    pub architecture: String,
    pub daemon_version: String,
    pub capabilities: Vec<String>,
    /// Public attachment facts asserted by this signed peer identity.
    #[serde(default)]
    pub interfaces: Vec<PeerInterface>,
}

/// One local network interface claimed by its owning peer.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerInterface {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mac: Option<String>,
    #[serde(default)]
    pub addresses: Vec<IpAddr>,
}

/// A receiver's signed observation of an authenticated peer connection.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerEndpointObservation {
    pub observer: String,
    pub peer: String,
    pub address: IpAddr,
    pub observed_at: u64,
}

/// Expiring connection hints, separate from durable transport-key bindings.
/// These nominate a path; they never confer membership or authorization.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SyncHints {
    pub node_id: String,
    pub endpoint_id: String,
    pub server_name: String,
    pub direct_addresses: BTreeSet<std::net::SocketAddr>,
    pub relay_urls: BTreeSet<String>,
    pub observed_at: u64,
    pub expires_at: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EgressObservation {
    pub node_id: String,
    pub hostname: String,
    pub site: String,
    pub observed_at: u64,
    pub mapped_endpoints: Vec<String>,
    pub public_ip_stable: bool,
    pub mapping_varies_by_destination: bool,
    pub median_latency_ms: u64,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct FilesystemHealth {
    pub mount: String,
    pub total_bytes: u64,
    pub available_bytes: u64,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ProcessHealth {
    pub pid: u32,
    pub name: String,
    pub cpu_percent: f32,
    pub memory_percent: f32,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct HostHealth {
    pub observed_at: u64,
    pub uptime_seconds: u64,
    pub load_average: [f64; 3],
    pub logical_cpus: u32,
    pub memory_total_bytes: u64,
    pub memory_available_bytes: u64,
    pub swap_total_bytes: u64,
    pub swap_free_bytes: u64,
    pub filesystems: Vec<FilesystemHealth>,
    pub process_leaders: Vec<ProcessHealth>,
    pub ssh_listening: bool,
    pub established_ssh_sessions: u32,
    #[serde(default)]
    pub platform_metrics: BTreeMap<String, String>,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum PeerEvent {
    SyncHints(SyncHints),
    Hello(PeerHello),
    Health(HostHealth),
    Topology(TopologySnapshot),
    Release(ReleaseManifest),
    Package(PackageManifest),
    Authority(AuthorityRecord),
    Endpoint(PeerEndpointObservation),
    Egress(EgressObservation),
    Access(AccessRecord),
    Transport(TransportCredentialBinding),
    WireGuard(WireGuardBinding),
    Hardware(HardwareSnapshot),
    SecurityPosture(SecurityPosture),
    SecurityEvents(SecurityEventBatch),
    SshHealth(SshHealth),
    /// A future event kind this binary does not understand. Receivers discard
    /// it without rejecting the other independently signed observations.
    Unknown,
}

#[derive(Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
enum KnownPeerEvent {
    SyncHints(SyncHints),
    Hello(PeerHello),
    Health(HostHealth),
    Topology(TopologySnapshot),
    Release(ReleaseManifest),
    Package(PackageManifest),
    Authority(AuthorityRecord),
    Endpoint(PeerEndpointObservation),
    Egress(EgressObservation),
    Access(AccessRecord),
    Transport(TransportCredentialBinding),
    WireGuard(WireGuardBinding),
    Hardware(HardwareSnapshot),
    SecurityPosture(SecurityPosture),
    SecurityEvents(SecurityEventBatch),
    SshHealth(SshHealth),
}

impl<'de> Deserialize<'de> for PeerEvent {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = serde_json::Value::deserialize(deserializer)?;
        let known = matches!(
            value.get("kind").and_then(serde_json::Value::as_str),
            Some(
                "hello"
                    | "sync_hints"
                    | "health"
                    | "topology"
                    | "release"
                    | "package"
                    | "authority"
                    | "endpoint"
                    | "egress"
                    | "access"
                    | "transport"
                    | "wire_guard"
                    | "hardware"
                    | "security_posture"
                    | "security_events"
                    | "ssh_health"
            )
        );
        if !known {
            return Ok(Self::Unknown);
        }
        let event: KnownPeerEvent =
            serde_json::from_value(value).map_err(serde::de::Error::custom)?;
        Ok(match event {
            KnownPeerEvent::SyncHints(value) => Self::SyncHints(value),
            KnownPeerEvent::Hello(value) => Self::Hello(value),
            KnownPeerEvent::Health(value) => Self::Health(value),
            KnownPeerEvent::Topology(value) => Self::Topology(value),
            KnownPeerEvent::Release(value) => Self::Release(value),
            KnownPeerEvent::Package(value) => Self::Package(value),
            KnownPeerEvent::Authority(value) => Self::Authority(value),
            KnownPeerEvent::Endpoint(value) => Self::Endpoint(value),
            KnownPeerEvent::Egress(value) => Self::Egress(value),
            KnownPeerEvent::Access(value) => Self::Access(value),
            KnownPeerEvent::Transport(value) => Self::Transport(value),
            KnownPeerEvent::WireGuard(value) => Self::WireGuard(value),
            KnownPeerEvent::Hardware(value) => Self::Hardware(value),
            KnownPeerEvent::SecurityPosture(value) => Self::SecurityPosture(value),
            KnownPeerEvent::SecurityEvents(value) => Self::SecurityEvents(value),
            KnownPeerEvent::SshHealth(value) => Self::SshHealth(value),
        })
    }
}

pub const MAX_SECURITY_FINDINGS: usize = 256;
pub const MAX_SECURITY_EVENTS: usize = 128;
pub const MAX_HARDWARE_DEVICES: usize = 4096;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum HardwareKind {
    PciDevice,
    UsbDevice,
    StorageController,
    StorageDevice,
    StorageVolume,
    Accelerator,
    SecurityModule,
    /// A kind introduced by a newer peer. The original wire string is kept
    /// verbatim so a decoded envelope re-serializes to the same bytes and its
    /// signature still verifies when it is gossiped onward. Callers ignore it
    /// rather than failing the whole sync exchange.
    Unknown(String),
}

impl HardwareKind {
    pub fn as_str(&self) -> &str {
        match self {
            Self::PciDevice => "pci_device",
            Self::UsbDevice => "usb_device",
            Self::StorageController => "storage_controller",
            Self::StorageDevice => "storage_device",
            Self::StorageVolume => "storage_volume",
            Self::Accelerator => "accelerator",
            Self::SecurityModule => "security_module",
            Self::Unknown(value) => value,
        }
    }
}

impl Serialize for HardwareKind {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for HardwareKind {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        Ok(match value.as_str() {
            "pci_device" => Self::PciDevice,
            "usb_device" => Self::UsbDevice,
            "storage_controller" => Self::StorageController,
            "storage_device" => Self::StorageDevice,
            "storage_volume" => Self::StorageVolume,
            "accelerator" => Self::Accelerator,
            "security_module" => Self::SecurityModule,
            _ => Self::Unknown(value),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HardwareBus {
    Pci,
    Usb,
    Nvme,
    Sata,
    Scsi,
    Virtio,
    Thunderbolt,
    Integrated,
    Unknown,
}

/// One node in a peer-local physical/logical hardware graph.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HardwareDevice {
    /// Stable within this peer, derived from a platform locator rather than a label.
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent: Option<String>,
    pub locator: String,
    pub kind: HardwareKind,
    pub bus: HardwareBus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vendor: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    /// SHA-256 of a hardware serial when one is available; raw serials are not gossiped.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub serial_hash: Option<String>,
    #[serde(default)]
    pub capabilities: BTreeSet<String>,
    #[serde(default)]
    pub properties: BTreeMap<String, String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HardwareSnapshot {
    pub schema_version: u16,
    pub node_id: String,
    pub hostname: String,
    pub observed_at: u64,
    pub devices: Vec<HardwareDevice>,
}

impl HardwareSnapshot {
    pub fn validate_for(&self, origin: &str) -> Result<(), String> {
        if self.schema_version != 1 {
            return Err(format!(
                "unsupported hardware schema {}",
                self.schema_version
            ));
        }
        if self.node_id != origin {
            return Err("hardware snapshot does not belong to its signed origin".into());
        }
        if self.devices.len() > MAX_HARDWARE_DEVICES {
            return Err("hardware snapshot exceeds the device limit".into());
        }
        let mut ids = BTreeSet::new();
        for device in &self.devices {
            if device.id.len() > 128
                || device.locator.is_empty()
                || device.locator.len() > 512
                || !ids.insert(device.id.as_str())
            {
                return Err("hardware snapshot contains an invalid or duplicate identity".into());
            }
            if device.capabilities.len() > 32 || device.properties.len() > 64 {
                return Err("hardware device metadata exceeds its field limit".into());
            }
            if device
                .capabilities
                .iter()
                .any(|value| value.is_empty() || value.len() > 128)
                || device
                    .properties
                    .iter()
                    .any(|(key, value)| key.is_empty() || key.len() > 128 || value.len() > 1024)
            {
                return Err("hardware device metadata contains an invalid field".into());
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecuritySeverity {
    Informational,
    Low,
    Medium,
    High,
    Critical,
    Unknown,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecurityFinding {
    pub id: String,
    pub source: String,
    pub category: String,
    pub severity: SecuritySeverity,
    pub title: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub component: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub installed_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fixed_version: Option<String>,
    #[serde(default)]
    pub references: BTreeSet<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComplianceSummary {
    pub profile: String,
    pub passed: u32,
    pub failed: u32,
    pub errors: u32,
    pub not_applicable: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_digest: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecurityPosture {
    pub schema_version: u16,
    pub node_id: String,
    pub hostname: String,
    pub site: String,
    pub observed_at: u64,
    pub platform: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub os_version: Option<String>,
    pub security_updates_available: u32,
    pub reboot_required: bool,
    #[serde(default)]
    pub scanners: BTreeMap<String, String>,
    #[serde(default)]
    pub findings: Vec<SecurityFinding>,
    #[serde(default)]
    pub compliance: Vec<ComplianceSummary>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecurityEvent {
    pub id: String,
    pub observed_at: u64,
    pub category: String,
    pub action: String,
    pub outcome: String,
    pub severity: SecuritySeverity,
    pub message: String,
    #[serde(default)]
    pub fields: BTreeMap<String, String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecurityEventBatch {
    pub schema_version: u16,
    pub node_id: String,
    pub hostname: String,
    pub site: String,
    pub observed_at: u64,
    pub events: Vec<SecurityEvent>,
}

/// A gossiped SSH access healthcheck. It is derived locally from installed
/// credentials and locally verified signed access/authority records; it never
/// asserts an access grant by itself. Peers merge it as a signed observation,
/// so the fleet can see an expired or unrenewed certificate before an operator
/// discovers it by failing to log in.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SshHealth {
    pub schema_version: u16,
    pub node_id: String,
    pub hostname: String,
    pub site: String,
    pub observed_at: u64,
    /// sshd is accepting connections on the local host.
    pub listening: bool,
    pub established_sessions: u32,
    /// `valid`, `due`, `expired`, `missing`, or `error`.
    pub certificate_state: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub certificate_not_before: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub certificate_not_after: Option<u64>,
    #[serde(default)]
    pub certificate_principals: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub renewal_after: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub renewal_error: Option<String>,
    /// Active signed access grants and trusted authority records observed via
    /// the fleet feed. These are counts, not an authorization assertion.
    pub access_grants: u32,
    pub access_authorities: u32,
    /// `ok`, `stale`, `unavailable`, or `unknown` for local host enforcement.
    pub access_enforcement: String,
    /// One-line operator verdict: `ok`, `warn`, or `fail`.
    pub verdict: String,
}

/// A narrowly scoped transport credential bound to a stable Mycelium peer.
///
/// This is deliberately not key derivation: every transport owns and rotates
/// its own private key. The peer's Ed25519 identity authorizes the public half
/// by signing the envelope that carries this binding.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportKind {
    Mtls,
    Iroh,
    WireGuard,
    Derp,
    Ssh,
}

fn wireguard_transport_kind() -> TransportKind {
    TransportKind::WireGuard
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransportCredentialBinding {
    pub node_id: String,
    #[serde(default = "wireguard_transport_kind")]
    pub kind: TransportKind,
    /// Transport-specific public key or certificate SHA-256 fingerprint.
    pub public_key: String,
    pub generation: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid_until: Option<u64>,
}

impl TransportCredentialBinding {
    pub fn validate_for(&self, origin: &str) -> Result<(), String> {
        if self.node_id != origin {
            return Err("transport binding does not belong to its signed origin".into());
        }
        if self.public_key.trim().is_empty() {
            return Err("transport binding public key is empty".into());
        }
        Ok(())
    }
}

/// A WireGuard transport key and the routes it may advertise, authorized by
/// the surrounding signed envelope from the node's Mycelium identity.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireGuardBinding {
    #[serde(flatten)]
    pub credential: TransportCredentialBinding,
    pub hostname: String,
    pub site: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    #[serde(default)]
    pub advertised_prefixes: Vec<String>,
}

impl WireGuardBinding {
    pub fn validate_for(&self, origin: &str) -> Result<(), String> {
        self.credential.validate_for(origin)?;
        if self.credential.kind != TransportKind::WireGuard {
            return Err("WireGuard binding carries a non-WireGuard credential".into());
        }
        Ok(())
    }
}

/// A signed, schema-versioned topology snapshot. The topology schema remains
/// owned by `mycelium-core`; the transport protocol only carries opaque JSON,
/// avoiding a dependency from the peer contract back into the control plane.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct TopologySnapshot {
    pub schema_version: u16,
    pub topology: serde_json::Value,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AccessStatement {
    Grant {
        grant_id: String,
        principal: String,
        serial: u64,
        #[serde(default)]
        roles: Vec<String>,
        #[serde(default)]
        scopes: Vec<String>,
        #[serde(default)]
        unix_users: Vec<String>,
        #[serde(default)]
        ssh_public_keys: Vec<String>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        oidc_audiences: Vec<String>,
        #[serde(default, skip_serializing_if = "is_false")]
        oidc_ssh_key_exchange: bool,
        not_before: u64,
        not_after: u64,
    },
    Revoke {
        revocation_id: String,
        #[serde(default)]
        grant_id: Option<String>,
        #[serde(default)]
        principal: Option<String>,
        #[serde(default)]
        serial: Option<u64>,
        revoked_at: u64,
        reason: String,
    },
}

fn is_false(value: &bool) -> bool {
    !*value
}

impl AccessStatement {
    pub fn revokes(&self, grant: &AccessStatement) -> bool {
        let Self::Revoke {
            grant_id,
            principal,
            serial,
            ..
        } = self
        else {
            return false;
        };
        let Self::Grant {
            grant_id: candidate_id,
            principal: candidate_principal,
            serial: candidate_serial,
            ..
        } = grant
        else {
            return false;
        };
        grant_id.as_ref().is_none_or(|value| value == candidate_id)
            && principal
                .as_ref()
                .is_none_or(|value| value == candidate_principal)
            && serial.is_none_or(|value| value == *candidate_serial)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccessRecord {
    pub protocol_version: u16,
    pub statement: AccessStatement,
    pub signer: String,
    pub signature: String,
}

#[derive(Serialize)]
struct UnsignedAccess<'a> {
    protocol_version: u16,
    statement: &'a AccessStatement,
    signer: &'a str,
}

impl AccessRecord {
    pub fn sign(key: &SigningKey, statement: AccessStatement) -> Result<Self, serde_json::Error> {
        let signer = encode_hex(key.verifying_key().as_bytes());
        let bytes = serde_json::to_vec(&UnsignedAccess {
            protocol_version: PROTOCOL_VERSION,
            statement: &statement,
            signer: &signer,
        })?;
        Ok(Self {
            protocol_version: PROTOCOL_VERSION,
            statement,
            signer,
            signature: encode_hex(&key.sign(&bytes).to_bytes()),
        })
    }

    pub fn verify(&self) -> Result<(), String> {
        if self.protocol_version != PROTOCOL_VERSION {
            return Err(format!("unsupported protocol {}", self.protocol_version));
        }
        let key = VerifyingKey::from_bytes(&decode_array::<32>(&self.signer)?)
            .map_err(|error| error.to_string())?;
        let signature = Signature::from_bytes(&decode_array::<64>(&self.signature)?);
        let bytes = serde_json::to_vec(&UnsignedAccess {
            protocol_version: self.protocol_version,
            statement: &self.statement,
            signer: &self.signer,
        })
        .map_err(|error| error.to_string())?;
        key.verify(&bytes, &signature)
            .map_err(|error| error.to_string())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReleaseManifest {
    pub version: String,
    pub channel: String,
    pub target: String,
    pub protocol_version: u16,
    pub artifact_digest: String,
    pub artifact_size: u64,
    pub signer: String,
    pub signature: String,
}

#[derive(Serialize)]
struct UnsignedRelease<'a> {
    version: &'a str,
    channel: &'a str,
    target: &'a str,
    protocol_version: u16,
    artifact_digest: &'a str,
    artifact_size: u64,
    signer: &'a str,
}

impl ReleaseManifest {
    pub fn sign(
        key: &SigningKey,
        version: String,
        channel: String,
        target: String,
        artifact: &[u8],
    ) -> Result<Self, serde_json::Error> {
        let signer = encode_hex(key.verifying_key().as_bytes());
        let artifact_digest = sha256_hex(artifact);
        let artifact_size = artifact.len() as u64;
        let bytes = serde_json::to_vec(&UnsignedRelease {
            version: &version,
            channel: &channel,
            target: &target,
            protocol_version: PROTOCOL_VERSION,
            artifact_digest: &artifact_digest,
            artifact_size,
            signer: &signer,
        })?;
        Ok(Self {
            version,
            channel,
            target,
            protocol_version: PROTOCOL_VERSION,
            artifact_digest,
            artifact_size,
            signer,
            signature: encode_hex(&key.sign(&bytes).to_bytes()),
        })
    }

    pub fn verify(&self) -> Result<(), String> {
        let key = VerifyingKey::from_bytes(&decode_array::<32>(&self.signer)?)
            .map_err(|error| error.to_string())?;
        let signature = Signature::from_bytes(&decode_array::<64>(&self.signature)?);
        let bytes = serde_json::to_vec(&UnsignedRelease {
            version: &self.version,
            channel: &self.channel,
            target: &self.target,
            protocol_version: self.protocol_version,
            artifact_digest: &self.artifact_digest,
            artifact_size: self.artifact_size,
            signer: &self.signer,
        })
        .map_err(|error| error.to_string())?;
        key.verify(&bytes, &signature)
            .map_err(|error| error.to_string())
    }
}

/// A signed, content-addressed executable distributed independently of the
/// Mycelium daemon. Placement policy is intentionally not part of this
/// manifest: publishers authorize bytes; each node's desired state decides
/// whether those bytes should run there.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackageManifest {
    pub name: String,
    pub version: String,
    pub channel: String,
    pub target: String,
    pub protocol_version: u16,
    pub artifact_digest: String,
    pub artifact_size: u64,
    pub signer: String,
    pub signature: String,
}

#[derive(Serialize)]
struct UnsignedPackage<'a> {
    name: &'a str,
    version: &'a str,
    channel: &'a str,
    target: &'a str,
    protocol_version: u16,
    artifact_digest: &'a str,
    artifact_size: u64,
    signer: &'a str,
}

impl PackageManifest {
    pub fn sign(
        key: &SigningKey,
        name: String,
        version: String,
        channel: String,
        target: String,
        artifact: &[u8],
    ) -> Result<Self, serde_json::Error> {
        let signer = encode_hex(key.verifying_key().as_bytes());
        let artifact_digest = sha256_hex(artifact);
        let artifact_size = artifact.len() as u64;
        let bytes = serde_json::to_vec(&UnsignedPackage {
            name: &name,
            version: &version,
            channel: &channel,
            target: &target,
            protocol_version: PROTOCOL_VERSION,
            artifact_digest: &artifact_digest,
            artifact_size,
            signer: &signer,
        })?;
        Ok(Self {
            name,
            version,
            channel,
            target,
            protocol_version: PROTOCOL_VERSION,
            artifact_digest,
            artifact_size,
            signer,
            signature: encode_hex(&key.sign(&bytes).to_bytes()),
        })
    }

    pub fn verify(&self) -> Result<(), String> {
        if self.protocol_version != PROTOCOL_VERSION {
            return Err(format!("unsupported protocol {}", self.protocol_version));
        }
        let key = VerifyingKey::from_bytes(&decode_array::<32>(&self.signer)?)
            .map_err(|error| error.to_string())?;
        let signature = Signature::from_bytes(&decode_array::<64>(&self.signature)?);
        let bytes = serde_json::to_vec(&UnsignedPackage {
            name: &self.name,
            version: &self.version,
            channel: &self.channel,
            target: &self.target,
            protocol_version: self.protocol_version,
            artifact_digest: &self.artifact_digest,
            artifact_size: self.artifact_size,
            signer: &self.signer,
        })
        .map_err(|error| error.to_string())?;
        key.verify(&bytes, &signature)
            .map_err(|error| error.to_string())
    }
}

/// A narrowly scoped operation that an authority root may delegate.
///
/// Empty package constraint sets are wildcards. For example, an empty
/// `targets` set permits the named packages on every target, while a non-empty
/// set permits only exact target-triple matches.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum AuthorityCapability {
    /// Publish signed access grants and access revocations.
    AccessPublish,
    /// Publish a signed Mycelium self-update release manifest.
    ReleasePublish,
    /// Promote a signed, named software package into the mesh.
    PackagePromote {
        /// Permitted package names; empty means all package names.
        #[serde(default)]
        packages: BTreeSet<String>,
        /// Permitted release channels; empty means all channels.
        #[serde(default)]
        channels: BTreeSet<String>,
        /// Permitted target triples; empty means all targets.
        #[serde(default)]
        targets: BTreeSet<String>,
    },
}

impl AuthorityCapability {
    /// Returns whether this capability permits the supplied signed package.
    pub fn permits_package(&self, package: &PackageManifest) -> bool {
        self.permits_package_fields(&package.name, &package.channel, &package.target)
    }

    /// Returns whether this capability permits an exact package tuple.
    ///
    /// This is the projection used by `authority explain`, where no manifest
    /// needs to be constructed merely to inspect a policy decision.
    pub fn permits_package_fields(&self, name: &str, channel: &str, target: &str) -> bool {
        match self {
            Self::PackagePromote {
                packages,
                channels,
                targets,
            } => {
                (packages.is_empty() || packages.contains(name))
                    && (channels.is_empty() || channels.contains(channel))
                    && (targets.is_empty() || targets.contains(target))
            }
            _ => false,
        }
    }
}

/// A root-issued change to the shared authority graph.
///
/// Authority v1 deliberately supports one delegation level: a configured root
/// may delegate capabilities to a workload signer, but a delegated signer may
/// not issue further authority statements.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AuthorityStatement {
    /// Grants bounded capabilities to one Ed25519 public-key identity.
    Delegate {
        /// Stable, globally unique identifier referenced by revocations.
        delegation_id: String,
        /// Hex-encoded Ed25519 public key receiving the capabilities.
        subject: String,
        /// Operations the subject may perform.
        capabilities: Vec<AuthorityCapability>,
        /// First valid Unix timestamp, inclusive.
        not_before: u64,
        /// Expiration Unix timestamp, exclusive.
        not_after: u64,
    },
    /// Permanently invalidates one delegation after `revoked_at`.
    Revoke {
        /// Stable identifier for this revocation observation.
        revocation_id: String,
        /// Identifier of the delegation being revoked.
        delegation_id: String,
        /// Unix timestamp at which the revocation takes effect.
        revoked_at: u64,
        /// Human-readable audit reason.
        reason: String,
    },
}

/// A signed, gossipable authority statement.
///
/// `signer` is the hex-encoded Ed25519 public key. Peers accept the record only
/// when that key is configured as an authority root; signature validity alone
/// never grants root authority.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorityRecord {
    /// Wire protocol version covered by the signature.
    pub protocol_version: u16,
    /// Delegation or revocation covered by the signature.
    pub statement: AuthorityStatement,
    /// Hex-encoded Ed25519 authority-root public key.
    pub signer: String,
    /// Hex-encoded Ed25519 signature over the canonical record fields.
    pub signature: String,
}

#[derive(Serialize)]
struct UnsignedAuthority<'a> {
    protocol_version: u16,
    statement: &'a AuthorityStatement,
    signer: &'a str,
}

impl AuthorityRecord {
    /// Creates a root-signed authority record.
    ///
    /// Callers must still verify that the resulting signer is a configured
    /// authority root before publishing the record.
    pub fn sign(
        key: &SigningKey,
        statement: AuthorityStatement,
    ) -> Result<Self, serde_json::Error> {
        let signer = encode_hex(key.verifying_key().as_bytes());
        let bytes = serde_json::to_vec(&UnsignedAuthority {
            protocol_version: PROTOCOL_VERSION,
            statement: &statement,
            signer: &signer,
        })?;
        Ok(Self {
            protocol_version: PROTOCOL_VERSION,
            statement,
            signer,
            signature: encode_hex(&key.sign(&bytes).to_bytes()),
        })
    }

    /// Verifies the record's protocol version and Ed25519 signature.
    ///
    /// This proves integrity and signer possession only. Root membership and
    /// delegation policy are evaluated by the daemon's authority resolver.
    pub fn verify(&self) -> Result<(), String> {
        if self.protocol_version != PROTOCOL_VERSION {
            return Err(format!("unsupported protocol {}", self.protocol_version));
        }
        let key = VerifyingKey::from_bytes(&decode_array::<32>(&self.signer)?)
            .map_err(|error| error.to_string())?;
        let signature = Signature::from_bytes(&decode_array::<64>(&self.signature)?);
        let bytes = serde_json::to_vec(&UnsignedAuthority {
            protocol_version: self.protocol_version,
            statement: &self.statement,
            signer: &self.signer,
        })
        .map_err(|error| error.to_string())?;
        key.verify(&bytes, &signature)
            .map_err(|error| error.to_string())
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SignedEnvelope {
    pub origin: String,
    pub sequence: u64,
    pub emitted_at: u64,
    pub event: PeerEvent,
    pub signature: String,
}

#[derive(Serialize)]
struct Signable<'a> {
    origin: &'a str,
    sequence: u64,
    emitted_at: u64,
    event: &'a PeerEvent,
}

impl SignedEnvelope {
    pub fn sign(
        key: &SigningKey,
        sequence: u64,
        emitted_at: u64,
        event: PeerEvent,
    ) -> Result<Self, serde_json::Error> {
        let origin = encode_hex(key.verifying_key().as_bytes());
        let bytes = serde_json::to_vec(&Signable {
            origin: &origin,
            sequence,
            emitted_at,
            event: &event,
        })?;
        let signature = encode_hex(&key.sign(&bytes).to_bytes());
        Ok(Self {
            origin,
            sequence,
            emitted_at,
            event,
            signature,
        })
    }

    pub fn verify(&self) -> Result<(), String> {
        let public = decode_array::<32>(&self.origin)?;
        let signature = Signature::from_bytes(&decode_array::<64>(&self.signature)?);
        let key = VerifyingKey::from_bytes(&public).map_err(|error| error.to_string())?;
        let bytes = serde_json::to_vec(&Signable {
            origin: &self.origin,
            sequence: self.sequence,
            emitted_at: self.emitted_at,
            event: &self.event,
        })
        .map_err(|error| error.to_string())?;
        key.verify(&bytes, &signature)
            .map_err(|error| error.to_string())
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", content = "payload", rename_all = "snake_case")]
pub enum PeerMessage {
    Hello(PeerHello),
    Digest(BTreeMap<String, u64>),
    Observations(Vec<SignedEnvelope>),
    Ping {
        sent_at: u64,
    },
    ArtifactRequest {
        digest: String,
        offset: u64,
        length: u32,
    },
    ArtifactChunk {
        digest: String,
        offset: u64,
        data: String,
        complete: bool,
    },
    SshRenewalRequest(SshRenewalRequest),
    SshRenewalResponse(SshRenewalResponse),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SshRenewalRequest {
    pub request_id: String,
    pub node_id: String,
    pub requested_at: u64,
    pub public_key: String,
    pub signature: String,
}

impl SshRenewalRequest {
    pub fn sign(
        request_id: String,
        requested_at: u64,
        public_key: String,
        key: &SigningKey,
    ) -> Result<Self, String> {
        let node_id = encode_hex(key.verifying_key().as_bytes());
        let bytes = renewal_signing_bytes(&request_id, &node_id, requested_at, &public_key)?;
        Ok(Self {
            request_id,
            node_id,
            requested_at,
            public_key,
            signature: encode_hex(&key.sign(&bytes).to_bytes()),
        })
    }

    pub fn verify(&self) -> Result<(), String> {
        let key = VerifyingKey::from_bytes(&decode_array::<32>(&self.node_id)?)
            .map_err(|error| error.to_string())?;
        let signature = Signature::from_bytes(&decode_array::<64>(&self.signature)?);
        let bytes = renewal_signing_bytes(
            &self.request_id,
            &self.node_id,
            self.requested_at,
            &self.public_key,
        )?;
        key.verify(&bytes, &signature)
            .map_err(|error| error.to_string())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SshRenewalResponse {
    pub request_id: String,
    pub certificate: Option<String>,
    pub expires_at: Option<u64>,
    pub error: Option<String>,
}

fn renewal_signing_bytes(
    request_id: &str,
    node_id: &str,
    requested_at: u64,
    public_key: &str,
) -> Result<Vec<u8>, String> {
    serde_json::to_vec(&(request_id, node_id, requested_at, public_key))
        .map_err(|error| error.to_string())
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    encode_hex(&Sha256::digest(bytes))
}

pub fn decode_hex(text: &str) -> Result<Vec<u8>, String> {
    if text.len() % 2 != 0 {
        return Err("hex value must contain pairs of characters".into());
    }
    (0..text.len())
        .step_by(2)
        .map(|index| {
            u8::from_str_radix(&text[index..index + 2], 16).map_err(|_| "invalid hex".to_owned())
        })
        .collect()
}

pub fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

fn decode_array<const N: usize>(text: &str) -> Result<[u8; N], String> {
    if text.len() != N * 2 {
        return Err(format!("expected {} hex characters", N * 2));
    }
    let mut output = [0_u8; N];
    for (index, slot) in output.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&text[index * 2..index * 2 + 2], 16)
            .map_err(|_| "invalid hex".to_owned())?;
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    #[test]
    fn security_module_kind_round_trips() {
        let encoded = serde_json::to_string(&super::HardwareKind::SecurityModule).unwrap();
        assert_eq!(encoded, "\"security_module\"");
        assert_eq!(
            serde_json::from_str::<super::HardwareKind>(&encoded).unwrap(),
            super::HardwareKind::SecurityModule
        );
    }

    #[test]
    fn unknown_hardware_kind_is_preserved_verbatim() {
        let encoded = "\"quantum_annealer\"";
        let kind: super::HardwareKind = serde_json::from_str(encoded).unwrap();
        assert_eq!(kind, super::HardwareKind::Unknown("quantum_annealer".into()));
        // Critical for gossip: re-serializing must reproduce the original
        // string, otherwise a forwarded envelope's signature no longer verifies.
        assert_eq!(serde_json::to_string(&kind).unwrap(), encoded);
    }
    use super::*;

    #[test]
    fn linux_hosts_prefer_portable_musl_but_accept_gnu() {
        assert_eq!(
            compatible_targets("x86_64", "linux"),
            ["x86_64-unknown-linux-musl", "x86_64-unknown-linux-gnu"]
        );
        assert_eq!(
            compatible_targets("aarch64", "linux"),
            ["aarch64-unknown-linux-musl", "aarch64-unknown-linux-gnu"]
        );
    }

    #[test]
    fn legacy_peer_hello_defaults_to_no_interface_claims() {
        let hello: PeerHello = serde_json::from_value(serde_json::json!({
            "node_id": "11".repeat(32),
            "protocol_version": 1,
            "site": "home",
            "hostname": "old-peer",
            "platform": "linux",
            "architecture": "aarch64",
            "daemon_version": "0.1.0",
            "capabilities": []
        }))
        .unwrap();
        assert!(hello.interfaces.is_empty());
    }

    #[test]
    fn forwarded_envelopes_remain_origin_authenticated() {
        let key = SigningKey::from_bytes(&[7; 32]);
        let event = PeerEvent::Hello(PeerHello {
            node_id: encode_hex(key.verifying_key().as_bytes()),
            protocol_version: PROTOCOL_VERSION,
            site: "home".into(),
            hostname: "node".into(),
            platform: Platform::Linux,
            architecture: "x86_64".into(),
            daemon_version: "0.1.0".into(),
            capabilities: vec!["system.health".into()],
            interfaces: Vec::new(),
        });
        let mut envelope = SignedEnvelope::sign(&key, 1, 2, event).unwrap();
        envelope.verify().unwrap();
        envelope.sequence = 3;
        assert!(envelope.verify().is_err());
    }

    #[test]
    fn release_signature_authorizes_exact_artifact() {
        let key = SigningKey::from_bytes(&[9; 32]);
        let mut release = ReleaseManifest::sign(
            &key,
            "1.2.3".into(),
            "canary".into(),
            "aarch64-apple-darwin".into(),
            b"binary",
        )
        .unwrap();
        release.verify().unwrap();
        release.artifact_size += 1;
        assert!(release.verify().is_err());
    }

    #[test]
    fn envelope_signature_covers_topology_snapshot() {
        let key = SigningKey::from_bytes(&[10; 32]);
        let mut envelope = SignedEnvelope::sign(
            &key,
            1,
            2,
            PeerEvent::Topology(TopologySnapshot {
                schema_version: 1,
                topology: serde_json::json!({"nodes": {}}),
            }),
        )
        .unwrap();
        envelope.verify().unwrap();
        if let PeerEvent::Topology(snapshot) = &mut envelope.event {
            snapshot.topology = serde_json::json!({"nodes": {"injected": {}}});
        }
        assert!(envelope.verify().is_err());
    }

    #[test]
    fn unknown_peer_events_are_parseable_for_forward_compatibility() {
        let event: PeerEvent = serde_json::from_value(serde_json::json!({
            "kind": "future_capability",
            "value": {"schema_version": 7, "payload": "opaque"}
        }))
        .unwrap();
        assert_eq!(event, PeerEvent::Unknown);
    }

    #[test]
    fn wireguard_binding_is_covered_by_node_identity_signature() {
        let key = SigningKey::from_bytes(&[19; 32]);
        let node_id = encode_hex(key.verifying_key().as_bytes());
        let mut envelope = SignedEnvelope::sign(
            &key,
            1,
            1,
            PeerEvent::WireGuard(WireGuardBinding {
                credential: TransportCredentialBinding {
                    node_id,
                    kind: TransportKind::WireGuard,
                    public_key: "wireguard-public-key".into(),
                    generation: 1,
                    valid_until: None,
                },
                hostname: "gateway".into(),
                site: "home".into(),
                endpoint: Some("198.51.100.10:51820".into()),
                advertised_prefixes: vec!["192.168.10.0/24".into()],
            }),
        )
        .unwrap();
        envelope.verify().unwrap();
        if let PeerEvent::WireGuard(binding) = &mut envelope.event {
            binding.advertised_prefixes.push("10.0.0.0/8".into());
        }
        assert!(envelope.verify().is_err());
    }

    #[test]
    fn transport_binding_rejects_wrong_origin_and_transport_kind() {
        let binding = TransportCredentialBinding {
            node_id: "peer-a".into(),
            kind: TransportKind::Mtls,
            public_key: "sha256:certificate".into(),
            generation: 1,
            valid_until: None,
        };
        assert!(binding.validate_for("peer-a").is_ok());
        assert!(binding.validate_for("peer-b").is_err());

        let wireguard = WireGuardBinding {
            credential: binding,
            hostname: "gateway".into(),
            site: "home".into(),
            endpoint: None,
            advertised_prefixes: Vec::new(),
        };
        assert!(wireguard.validate_for("peer-a").is_err());
    }

    #[test]
    fn legacy_wireguard_binding_defaults_to_wireguard_transport() {
        let binding: WireGuardBinding = serde_json::from_value(serde_json::json!({
            "node_id": "peer-a",
            "hostname": "gateway",
            "site": "home",
            "public_key": "wg-key",
            "advertised_prefixes": [],
            "generation": 7
        }))
        .unwrap();
        assert_eq!(binding.credential.kind, TransportKind::WireGuard);
        assert_eq!(binding.credential.public_key, "wg-key");
    }

    #[test]
    fn hardware_snapshot_is_peer_scoped_bounded_and_signed() {
        let key = SigningKey::from_bytes(&[29; 32]);
        let node_id = encode_hex(key.verifying_key().as_bytes());
        let snapshot = HardwareSnapshot {
            schema_version: 1,
            node_id: node_id.clone(),
            hostname: "worker".into(),
            observed_at: 1,
            devices: vec![HardwareDevice {
                id: "hw:accelerator".into(),
                parent: None,
                locator: "darwin:display:integrated".into(),
                kind: HardwareKind::Accelerator,
                bus: HardwareBus::Integrated,
                vendor: Some("Apple".into()),
                model: Some("Apple GPU".into()),
                serial_hash: None,
                capabilities: BTreeSet::from(["metal".into()]),
                properties: BTreeMap::new(),
            }],
        };
        snapshot.validate_for(&node_id).unwrap();
        assert!(snapshot.validate_for("another-peer").is_err());
        let mut envelope = SignedEnvelope::sign(&key, 1, 1, PeerEvent::Hardware(snapshot)).unwrap();
        envelope.verify().unwrap();
        if let PeerEvent::Hardware(snapshot) = &mut envelope.event {
            snapshot.devices[0].capabilities.insert("tampered".into());
        }
        assert!(envelope.verify().is_err());
    }

    #[test]
    fn ssh_health_round_trips_and_is_signature_covered() {
        let key = SigningKey::from_bytes(&[24; 32]);
        let node_id = encode_hex(key.verifying_key().as_bytes());
        let mut envelope = SignedEnvelope::sign(
            &key,
            1,
            1,
            PeerEvent::SshHealth(SshHealth {
                schema_version: 1,
                node_id,
                hostname: "gateway".into(),
                site: "home".into(),
                observed_at: 1,
                listening: true,
                established_sessions: 0,
                certificate_state: "valid".into(),
                certificate_not_before: None,
                certificate_not_after: Some(2),
                certificate_principals: vec!["mycelium-role-network-admin".into()],
                renewal_after: Some(1),
                renewal_error: None,
                access_grants: 1,
                access_authorities: 1,
                access_enforcement: "ok".into(),
                verdict: "ok".into(),
            }),
        )
        .unwrap();
        envelope.verify().unwrap();
        let encoded = serde_json::to_string(&envelope).unwrap();
        let decoded: SignedEnvelope = serde_json::from_str(&encoded).unwrap();
        assert!(matches!(decoded.event, PeerEvent::SshHealth(_)));
        if let PeerEvent::SshHealth(ssh) = &mut envelope.event {
            ssh.verdict = "fail".into();
        }
        assert!(envelope.verify().is_err());
    }

    #[test]
    fn security_posture_is_covered_by_node_identity_signature() {
        let key = SigningKey::from_bytes(&[23; 32]);
        let node_id = encode_hex(key.verifying_key().as_bytes());
        let mut envelope = SignedEnvelope::sign(
            &key,
            1,
            1,
            PeerEvent::SecurityPosture(SecurityPosture {
                schema_version: 1,
                node_id,
                hostname: "gateway".into(),
                site: "home".into(),
                observed_at: 1,
                platform: "linux".into(),
                os_version: Some("Test Linux".into()),
                security_updates_available: 0,
                reboot_required: false,
                scanners: BTreeMap::new(),
                findings: Vec::new(),
                compliance: Vec::new(),
            }),
        )
        .unwrap();
        envelope.verify().unwrap();
        if let PeerEvent::SecurityPosture(posture) = &mut envelope.event {
            posture.security_updates_available = 1;
        }
        assert!(envelope.verify().is_err());
    }

    #[test]
    fn package_signature_covers_identity_and_artifact() {
        let key = SigningKey::from_bytes(&[29; 32]);
        let mut package = PackageManifest::sign(
            &key,
            "unibus".into(),
            "1.2.3".into(),
            "stable".into(),
            "aarch64-unknown-linux-musl".into(),
            b"binary",
        )
        .unwrap();
        package.verify().unwrap();
        package.name = "other".into();
        assert!(package.verify().is_err());
    }

    #[test]
    fn access_signature_covers_authorization_and_revocation_fields() {
        let key = SigningKey::from_bytes(&[11; 32]);
        let mut record = AccessRecord::sign(
            &key,
            AccessStatement::Grant {
                grant_id: "avery-laptop".into(),
                principal: "avery".into(),
                serial: 42,
                roles: vec!["operator".into()],
                scopes: vec!["home".into()],
                unix_users: vec!["avery".into()],
                ssh_public_keys: vec!["ssh-ed25519 AAAA".into()],
                oidc_audiences: vec![],
                oidc_ssh_key_exchange: false,
                not_before: 10,
                not_after: 20,
            },
        )
        .unwrap();
        let encoded = serde_json::to_value(&record.statement).unwrap();
        assert!(encoded.get("oidc_audiences").is_none());
        assert!(encoded.get("oidc_ssh_key_exchange").is_none());
        record.verify().unwrap();
        if let AccessStatement::Grant { scopes, .. } = &mut record.statement {
            scopes.push("prod".into());
        }
        assert!(record.verify().is_err());
    }

    #[test]
    fn access_revocation_matches_all_supplied_selectors() {
        let grant = AccessStatement::Grant {
            grant_id: "avery-laptop".into(),
            principal: "avery".into(),
            serial: 42,
            roles: vec![],
            scopes: vec![],
            unix_users: vec![],
            ssh_public_keys: vec![],
            oidc_audiences: vec![],
            oidc_ssh_key_exchange: false,
            not_before: 10,
            not_after: 20,
        };
        let matching = AccessStatement::Revoke {
            revocation_id: "lost-laptop".into(),
            grant_id: None,
            principal: Some("avery".into()),
            serial: Some(42),
            revoked_at: 15,
            reason: "lost".into(),
        };
        let wrong_serial = AccessStatement::Revoke {
            revocation_id: "wrong-serial".into(),
            grant_id: None,
            principal: Some("avery".into()),
            serial: Some(43),
            revoked_at: 15,
            reason: "lost".into(),
        };
        assert!(matching.revokes(&grant));
        assert!(!wrong_serial.revokes(&grant));
    }

    #[test]
    fn authority_signature_covers_capability_constraints() {
        let key = SigningKey::from_bytes(&[17; 32]);
        let mut record = AuthorityRecord::sign(
            &key,
            AuthorityStatement::Delegate {
                delegation_id: "fabd".into(),
                subject: "11".repeat(32),
                capabilities: vec![AuthorityCapability::PackagePromote {
                    packages: BTreeSet::from(["unibus".into()]),
                    channels: BTreeSet::from(["stable".into()]),
                    targets: BTreeSet::new(),
                }],
                not_before: 10,
                not_after: 20,
            },
        )
        .unwrap();
        record.verify().unwrap();
        if let AuthorityStatement::Delegate { capabilities, .. } = &mut record.statement {
            capabilities.push(AuthorityCapability::AccessPublish);
        }
        assert!(record.verify().is_err());
    }

    #[test]
    fn documented_authority_statements_match_the_protocol() {
        let access: AuthorityStatement = serde_json::from_str(include_str!(
            "../../../docs/examples/authority-access-delegation.json"
        ))
        .unwrap();
        let package: AuthorityStatement = serde_json::from_str(include_str!(
            "../../../docs/examples/authority-package-delegation.json"
        ))
        .unwrap();
        let revocation: AuthorityStatement = serde_json::from_str(include_str!(
            "../../../docs/examples/authority-revocation.json"
        ))
        .unwrap();
        assert!(matches!(access, AuthorityStatement::Delegate { .. }));
        assert!(matches!(package, AuthorityStatement::Delegate { .. }));
        assert!(matches!(revocation, AuthorityStatement::Revoke { .. }));
    }

    #[test]
    fn documented_access_statements_match_the_protocol() {
        let grant: AccessStatement =
            serde_json::from_str(include_str!("../../../docs/examples/access-grant.json")).unwrap();
        let revocation: AccessStatement = serde_json::from_str(include_str!(
            "../../../docs/examples/access-revocation.json"
        ))
        .unwrap();
        assert!(matches!(grant, AccessStatement::Grant { .. }));
        assert!(revocation.revokes(&grant));
    }
}
