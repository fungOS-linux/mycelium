//! Core abstractions for mycelium: a management layer over heterogeneous
//! network appliances (routers, switches, APs, IPMI/BMC, DNS filters...).
//!
//! The seam is deliberately narrow:
//! - [`driver::Driver`] discovers and opens a class of appliances.
//! - [`device::Device`] is a live, self-describing handle on one appliance.
//!   Everything structured (capabilities, params, results) is *declared data*;
//!   only [`device::Device::exec`] is code, and it is gated: mutations require
//!   `allow_writes`, dry-run is honored end-to-end (tenet: secure by default).
//! - Capability subtraits ([`capabilities`]) are typed facades over declared
//!   capabilities; drivers may override them for native implementations.

pub mod allocation;
pub mod boot;
pub mod capabilities;
pub mod classification;
pub mod credentials;
pub mod device;
pub mod discovery;
pub mod driver;
pub mod error;
pub mod exec;
pub mod inspection;
pub mod inventory;
pub mod naming;
pub mod primitives;
pub mod reconcile;
pub mod spec;
pub mod topology;
pub mod value;

pub use allocation::{
    AllocationBasis, AllocationReceipt, AllocationStrategy, AllocationValue, DhcpScopeIntent,
    LogicalNetwork, NetworkBinding, NetworkDriftReport, NetworkDriftState,
};
pub use boot::{
    BootArtifact, BootArtifactKind, BootContractError, BootFirmware, BootIntentMode, BootIntentV1,
    BootMachineSelector, BootPath, BootPlanError, BootPostInstall, BootProfileV1, BootReachability,
    BootReceiptState, BootReceiptV1, BootSecurityPolicy, BootTarget, NbdePlan, SecureBootPolicy,
    TangPolicy, BOOT_CONTRACT_SCHEMA_VERSION,
};
pub use capabilities::{DhcpManagement, DnsFiltering, Identity, Sensors, VlanManagement, Wireless};
pub use capabilities::{
    ID_CAPABILITIES, ID_DHCP_ADD_STATIC_LEASE, ID_DHCP_ENSURE_POOL, ID_DHCP_LIST_POOLS,
    ID_DNS_BLOCK, ID_DNS_LIST_ENTRIES, ID_IDENTIFY, ID_NET_FORWARD_ENSURE, ID_NET_VIP_ENSURE,
    ID_SENSOR_HISTORY, ID_SENSOR_READ, ID_SWITCH_OBSERVE, ID_SYSTEM_HEALTH, ID_VLAN_ASSIGN,
    ID_VLAN_CREATE, ID_VLAN_LIST, ID_WLAN_GUEST_ENABLE, ID_WLAN_LIST_SSID,
};
pub use classification::{DeviceClassification, DeviceClassifier, DeviceIdentityEvidence};
pub use credentials::{CredentialRef, CredentialSet, Secret};
pub use device::{DeviceId, DeviceKind, DeviceMeta};
pub use discovery::{DiscoveryProtocol, DiscoveryRequest, DiscoveryScope};
pub use driver::{Driver, Target};
pub use error::{MyceliumError, Result};
pub use exec::{ExecContext, ExecOutcome, RecordingTransport, Transport};
pub use inspection::{
    plan_inspection, CandidateAssessment, InspectionCandidate, InspectionDepth, InspectionIntent,
    InspectionPlacement, InspectionPlan, ObservationMethod, INSPECTION_SCHEMA_VERSION,
};
pub use inventory::{result_from_outcome, CapabilityInfo, Device, Inventory, InvokeResult};
pub use naming::{fleet_name, is_myc_name, sanitize_label};
pub use primitives::{
    host_target, optional_str, parse_cidr, required_str, stable_slug, HostTarget,
};
pub use reconcile::{
    canonical_digest, verification_matches, ActionPlan, ActionReceipt, ActionRisk, ExecutionMode,
    ExecutionReceipt, ExecutionState, PlanBlocker, PlannedAction, StateChangePlan,
    StateChangeReceipt, VerificationPredicate, VerificationSpec, ACTION_PLAN_SCHEMA_VERSION,
};
pub use spec::{CapResult, CapSpec, MutationVerification, ParamSpec, ParamType};
pub use topology::{
    ipv4_in_cidr, is_host_local_listener, Conflict, DiscoveredDevice, DiscoveredService, IpRecord,
    LeaseRecord, Link, LinkDuplex, LinkMedium, LinkState, MacAddress, MeshControlPlane,
    MeshCoordinator, MeshProtocol, NodeAnnotation, Observation, Origin, OverlayPeerRecord, PortRef,
    Segment, SegmentKind, ServiceAdvertisement, ServiceRecord, ServiceState, TopoNode, Topology,
    TopologyReport, VlanId,
};
pub use value::{IntoValue, Params, Value};
