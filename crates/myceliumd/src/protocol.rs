use mycelium_core::{DiscoveryProtocol, MyceliumError, Value};
use serde::{Deserialize, Serialize};

/// One JSON-RPC request (newline-delimited over the socket).
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "method", content = "params", rename_all = "snake_case")]
pub enum Request {
    Hello,
    /// List daemon-owned pulses, including system pulses where applicable.
    PulseList,
    PulsePut {
        pulse: crate::pulse::UserPulse,
        #[serde(default)]
        write: bool,
    },
    PulseRemove {
        id: String,
        #[serde(default)]
        write: bool,
    },
    PulseRuns {
        #[serde(default)]
        id: Option<String>,
        #[serde(default)]
        limit: Option<usize>,
    },
    NodeObserve,
    NodeRefresh {
        write: bool,
    },
    /// Registered drivers (builtin + Lua plugins).
    Drivers,
    /// Recognize + open a device. `driver` pins the class; otherwise each
    /// driver probes in order and the first match attaches.
    DeviceAdd {
        target: String,
        /// Stable operator-facing name, independent of probed hostnames.
        #[serde(default)]
        name: Option<String>,
        #[serde(default)]
        driver: Option<String>,
        #[serde(default)]
        username: Option<String>,
        #[serde(default)]
        credential_ref: Option<mycelium_core::CredentialRef>,
        /// NAME of an env var holding the password. Literals are rejected
        /// at the CLI so secrets don't cross the socket or hit the disk.
        #[serde(default)]
        password_env: Option<String>,
        #[serde(default)]
        key_path: Option<String>,
    },
    DeviceRemove {
        id: String,
    },
    DeviceList,
    DeviceDescribe {
        id: String,
    },
    DeviceCall {
        id: String,
        capability: String,
        #[serde(default)]
        params: serde_json::Map<String, serde_json::Value>,
        /// Explicit write opt-in.
        #[serde(default)]
        write: bool,
        #[serde(default)]
        dry_run: bool,
    },
    CredentialMapList,
    CredentialMapSet {
        rule: crate::credential_map::CredentialRule,
        #[serde(default)]
        write: bool,
    },
    CredentialMapRemove {
        name: String,
        #[serde(default)]
        write: bool,
    },
    ActionPlanApply {
        plan: mycelium_core::ActionPlan,
        #[serde(default)]
        write: bool,
        #[serde(default)]
        dry_run: bool,
    },
    /// Typed replacement for ActionPlanApply. The legacy request remains
    /// readable during the pre-1.0 protocol migration.
    ActionPlanExecute {
        plan: mycelium_core::ActionPlan,
        mode: mycelium_core::ExecutionMode,
    },
    ExecutionReceiptList,
    /// Pull observations from every open device and merge the topology.
    Scan,
    Topology,
    TopologyWatch {
        #[serde(default)]
        since: u64,
        #[serde(default = "default_topology_watch_limit")]
        limit: usize,
    },
    /// Provider-neutral usable resources projected from discovery facts.
    Resources,
    /// Provider-neutral recognized services projected from topology facts.
    Services,
    /// The L3 tunnel this daemon owns: process, identity, learned routes, and
    /// whether its claim is currently being published.
    IrohTunStatus,
    /// Bounce the tunnel without restarting the daemon.
    IrohTunRestart {
        #[serde(default)]
        write: bool,
    },
    DiscoveryScopeList,
    DiscoveryScopeSet {
        observer: String,
        protocols: Vec<DiscoveryProtocol>,
        segments: Vec<String>,
        #[serde(default)]
        write: bool,
        #[serde(default)]
        dry_run: bool,
    },
    DiscoveryScopeRemove {
        observer: String,
        #[serde(default)]
        write: bool,
        #[serde(default)]
        dry_run: bool,
    },
    AllocationList,
    AllocationImport {
        site: String,
        #[serde(default)]
        write: bool,
        #[serde(default)]
        dry_run: bool,
    },
    AllocationRecord {
        site: String,
        #[serde(default)]
        vlan: Option<u16>,
        #[serde(default)]
        subnet: Option<String>,
        #[serde(default)]
        gateway: Option<String>,
        source: String,
        #[serde(default)]
        write: bool,
        #[serde(default)]
        dry_run: bool,
    },
    NetworkList,
    NetworkAdopt {
        name: String,
        site: String,
        #[serde(default)]
        vlan: Option<u16>,
        subnet: String,
        #[serde(default)]
        write: bool,
        #[serde(default)]
        dry_run: bool,
    },
    NetworkDrift {
        #[serde(default)]
        name: Option<String>,
    },
    NetworkPlan {
        #[serde(default)]
        name: Option<String>,
    },
    NetworkBindingList {
        #[serde(default)]
        network: Option<String>,
    },
    NetworkBindingSet {
        network: String,
        device: String,
        port: String,
        tagged: bool,
        #[serde(default)]
        write: bool,
        #[serde(default)]
        dry_run: bool,
    },
    NetworkDhcpList {
        #[serde(default)]
        network: Option<String>,
    },
    NetworkDhcpSet {
        network: String,
        device: String,
        pool: String,
        range_start: String,
        range_end: String,
        #[serde(default)]
        dns_servers: Vec<String>,
        #[serde(default)]
        write: bool,
        #[serde(default)]
        dry_run: bool,
    },
    /// Return the locally converged view of signed peer observations.
    PeerList,
    EgressList,
    EgressPublish {
        observation: mycelium_peer_protocol::EgressObservation,
    },
    WireGuardBindingList,
    WireGuardBindingInit {
        advertised_prefixes: Vec<String>,
        #[serde(default)]
        endpoint: Option<String>,
        #[serde(default)]
        write: bool,
        #[serde(default)]
        dry_run: bool,
    },
    SecurityPostureList,
    SecurityEventList,
    SecuritySinkList,
    SecuritySinkAdd {
        config: crate::siem::SinkConfig,
        #[serde(default)]
        write: bool,
        #[serde(default)]
        dry_run: bool,
    },
    SecurityExportStatus,
    SecurityExportRun {
        #[serde(default)]
        sink: Option<String>,
        #[serde(default)]
        write: bool,
        #[serde(default)]
        dry_run: bool,
    },
    SecurityInspectionPlan {
        intent: mycelium_core::InspectionIntent,
        candidates: Vec<mycelium_core::InspectionCandidate>,
    },
    SecurityScan {
        #[serde(default)]
        stig_content: Option<String>,
        #[serde(default)]
        stig_profile: Option<String>,
        #[serde(default)]
        remediation_plan: bool,
    },
    SecurityRemediationList,
    SecurityRemediationApply {
        digest: String,
        #[serde(default)]
        write: bool,
    },
    SecurityRemediationVerify {
        digest: String,
    },
    ReleaseList,
    ReleaseKeygen {
        path: String,
        #[serde(default)]
        write: bool,
    },
    ReleasePublish {
        binary: String,
        signing_key: String,
        version: String,
        channel: String,
        #[serde(default)]
        target: Option<String>,
        #[serde(default)]
        write: bool,
        #[serde(default)]
        dry_run: bool,
    },
    ReleasePublishSet {
        manifest: String,
        signing_key: String,
        #[serde(default)]
        write: bool,
        #[serde(default)]
        dry_run: bool,
    },
    ReleaseSeed {
        binary: String,
        digest: String,
        #[serde(default)]
        write: bool,
        #[serde(default)]
        dry_run: bool,
    },
    PackageList,
    PackagePublish {
        name: String,
        binary: String,
        signing_key: String,
        version: String,
        channel: String,
        #[serde(default)]
        target: Option<String>,
        #[serde(default)]
        write: bool,
        #[serde(default)]
        dry_run: bool,
    },
    SoftwarePlan {
        policy: String,
    },
    SoftwarePolicySet {
        policy: String,
        #[serde(default)]
        write: bool,
        #[serde(default)]
        dry_run: bool,
    },
    SoftwareActivate {
        name: String,
        channel: String,
        #[serde(default)]
        write: bool,
        #[serde(default)]
        dry_run: bool,
    },
    SoftwareStatus,
    SoftwareReconcile {
        #[serde(default)]
        write: bool,
        #[serde(default)]
        dry_run: bool,
    },
    SoftwareAutoRun,
    AccessList,
    AccessKeygen {
        path: String,
        #[serde(default)]
        write: bool,
    },
    AccessPublish {
        statement: String,
        signing_key: String,
        #[serde(default)]
        write: bool,
        #[serde(default)]
        dry_run: bool,
    },
    AuthorityList,
    AuthorityPublish {
        statement: String,
        signing_key: String,
        #[serde(default)]
        write: bool,
        #[serde(default)]
        dry_run: bool,
    },
    AuthorityExplain {
        action: String,
        signer: String,
        #[serde(default)]
        package: Option<String>,
        #[serde(default)]
        channel: Option<String>,
        #[serde(default)]
        target: Option<String>,
    },
    /// Set durable human knowledge on exactly one discovered node.
    TopologyAnnotate {
        selector: String,
        #[serde(default)]
        name: Option<String>,
        #[serde(default)]
        kind: Option<String>,
        #[serde(default)]
        write: bool,
        #[serde(default)]
        dry_run: bool,
    },
    /// Plan one local SSH forward through an inventory gateway. The daemon
    /// returns only argv and an optional env-var name, never secret values.
    TunnelPlan {
        target: String,
        remote_port: u16,
        local_port: u16,
        #[serde(default)]
        via: Option<String>,
    },
    /// Resolve a managed device to a secret-free SSH execution plan.
    SshPlan {
        selector: String,
        #[serde(default)]
        username: Option<String>,
    },
    /// Resolve a device's interactive out-of-band console without sending
    /// credentials over RPC.
    ConsolePlan {
        id: String,
    },
    /// Persist state and exit.
    Shutdown,
}

fn default_topology_watch_limit() -> usize {
    32
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Response {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// Machine-readable error class for callers that branch on it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
}

impl Response {
    pub fn ok(result: serde_json::Value) -> Self {
        Self {
            ok: true,
            result: Some(result),
            error: None,
            kind: None,
        }
    }

    pub fn err(e: &MyceliumError) -> Self {
        let kind = match e {
            MyceliumError::WritesNotPermitted(_) => "writes_not_permitted",
            MyceliumError::UnknownDevice(_) => "unknown_device",
            MyceliumError::UnknownCapability(_) => "unknown_capability",
            MyceliumError::Validation(_) => "validation",
            MyceliumError::Transport(_) => "transport",
            MyceliumError::Auth(_) => "auth",
            MyceliumError::Device { .. } => "device",
            MyceliumError::Plugin { .. } => "plugin",
            MyceliumError::Parse(_) => "parse",
            MyceliumError::Unsupported { .. } => "unsupported",
            MyceliumError::Io(_) => "io",
        };
        Self {
            ok: false,
            result: None,
            error: Some(e.to_string()),
            kind: Some(kind.into()),
        }
    }

    pub fn fail(msg: impl Into<String>) -> Self {
        Self {
            ok: false,
            result: None,
            error: Some(msg.into()),
            kind: Some("daemon".into()),
        }
    }
}

/// Coerce CLI `k=v` strings into typed values: try bool, int, then string.
pub fn coerce_param(v: &str) -> Value {
    match v {
        "true" => Value::Bool(true),
        "false" => Value::Bool(false),
        _ => {
            if let Ok(i) = v.parse::<i64>() {
                Value::Int(i)
            } else if v.starts_with('{') || v.starts_with('[') {
                serde_json::from_str::<serde_json::Value>(v)
                    .map(|j| Value::from_json(&j))
                    .unwrap_or_else(|_| Value::Str(v.to_owned()))
            } else {
                Value::Str(v.to_owned())
            }
        }
    }
}
