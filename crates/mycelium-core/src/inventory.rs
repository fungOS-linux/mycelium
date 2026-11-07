use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::device::{DeviceId, DeviceKind, DeviceMeta};
use crate::error::{MyceliumError, Result};
use crate::exec::{ExecContext, ExecOutcome};
use crate::spec::{CapResult, CapSpec};
use crate::value::{IntoValue, Params, Value};

/// A live handle on one appliance.
///
/// Contract for driver implementors:
/// - `capabilities()` returns *declared* capabilities (data, see [`CapSpec`]).
/// - `exec()` runs one capability. It must validate params against the
///   declared spec, honor [`ExecContext::gate`] before any mutation, and
///   honor `dry_run` by building-but-not-applying.
/// - Capability subtraits (see [`crate::capabilities`]) are typed facades
///   over `exec`; default impls provide them for free, drivers may override
///   for native implementations.
#[async_trait]
pub trait Device: Send + Sync {
    fn meta(&self) -> &DeviceMeta;

    /// Declared capability id -> its spec. IDs are dotted:
    /// `vlan.list`, `dhcp.add-static-lease`, `system.identify`.
    fn capabilities(&self) -> BTreeMap<String, CapSpec>;

    /// Raw, gated execution of one declared capability. The only code-side
    /// seam; everything above it is data.
    async fn exec(&self, ctx: &ExecContext, cap: &str, params: Params) -> Result<CapResult>;

    /// Shared dispatch: refuse unknown caps, validate params, gate writes.
    /// Used by both Rust drivers and the Lua plugin host so the two paths
    /// cannot drift (tenet #1: one source of truth per fact).
    async fn invoke(&self, ctx: &ExecContext, cap: &str, params: Params) -> Result<CapResult> {
        let spec = self
            .capabilities()
            .remove(cap)
            .ok_or_else(|| MyceliumError::UnknownCapability(cap.to_owned()))?;
        spec.validate(&params).map_err(MyceliumError::Validation)?;
        ctx.gate(spec.mutation)?;
        self.exec(ctx, cap, params).await
    }

    fn kind(&self) -> DeviceKind {
        self.meta().kind
    }

    fn id(&self) -> DeviceId {
        self.meta().id.clone()
    }

    /// Topology facts as seen from this device. Default: contributes
    /// nothing. Devices with real visibility (routers, switches) override;
    /// second item is non-fatal scan warnings (degraded passes stay loud).
    async fn observe(&self) -> Result<(Vec<crate::topology::Observation>, Vec<String>)> {
        Ok((Vec::new(), Vec::new()))
    }

    /// Execute one explicitly authorized routed-discovery probe. Ordinary
    /// local observation remains in `observe`; this seam never infers policy.
    async fn discover(
        &self,
        request: &crate::discovery::DiscoveryRequest,
    ) -> Result<Vec<crate::topology::Observation>> {
        Err(MyceliumError::Unsupported {
            device: self.id().to_string(),
            capability: format!("discovery.{:?}", request.protocol).to_ascii_lowercase(),
        })
    }
}

/// Info about one capability as surfaced by `mycelium describe`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CapabilityInfo {
    pub id: String,
    pub spec: CapSpec,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct InvokeResult {
    pub device: DeviceId,
    pub capability: String,
    pub result: CapResult,
}

impl InvokeResult {
    pub fn new(device: DeviceId, capability: impl Into<String>, result: CapResult) -> Self {
        Self {
            device,
            capability: capability.into(),
            result,
        }
    }
}

/// Uniform "the command ran" result for simple exec-based capabilities.
pub fn result_from_outcome(outcome: ExecOutcome) -> CapResult {
    if outcome.success() {
        CapResult::ok(outcome.stdout.into_value())
    } else {
        CapResult {
            ok: false,
            output: Value::Null,
            message: Some(outcome.stderr.trim().to_owned()),
            dry_run: false,
        }
    }
}

/// In-memory registry of open devices.
///
/// The durable half of the inventory is just `Vec<DeviceMeta>` + specs, all
/// already serde types; this holds the live handles.
#[derive(Default, Clone)]
pub struct Inventory {
    devices: Arc<Mutex<BTreeMap<DeviceId, Arc<dyn Device>>>>,
}

impl Inventory {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add(&self, device: Arc<dyn Device>) {
        let mut guard = self.devices.lock().expect("inventory mutex poisoned");
        guard.insert(device.id(), device);
    }

    pub fn remove(&self, id: &str) -> Option<Arc<dyn Device>> {
        let mut guard = self.devices.lock().expect("inventory mutex poisoned");
        guard.remove(&DeviceId::new(id))
    }

    pub fn get(&self, id: &str) -> Result<Arc<dyn Device>> {
        let guard = self.devices.lock().expect("inventory mutex poisoned");
        guard
            .get(&DeviceId::new(id))
            .cloned()
            .ok_or_else(|| MyceliumError::UnknownDevice(id.to_owned()))
    }

    pub fn devices(&self) -> Vec<Arc<dyn Device>> {
        let guard = self.devices.lock().expect("inventory mutex poisoned");
        guard.values().cloned().collect()
    }

    pub fn capabilities(&self, id: &str) -> Result<Vec<CapabilityInfo>> {
        let device = self.get(id)?;
        Ok(device
            .capabilities()
            .into_iter()
            .map(|(id, spec)| CapabilityInfo { id, spec })
            .collect())
    }
}

/// Build a `Params` map from literal pairs.
#[macro_export]
macro_rules! params {
    ($($k:literal => $v:expr),* $(,)?) => {{
        let mut m = $crate::value::Params::new();
        $(m.insert($k.to_owned(), $crate::value::IntoValue::into_value($v));)*
        m
    }};
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::spec::ParamType;
    use crate::value::Params;

    fn test_meta(id: &str) -> DeviceMeta {
        DeviceMeta {
            id: DeviceId::new(id),
            kind: DeviceKind::Other,
            driver: "fake".into(),
            vendor: None,
            model: None,
            firmware: None,
            address: "nowhere".into(),
        }
    }

    struct Fake;

    #[async_trait]
    impl Device for Fake {
        fn meta(&self) -> &DeviceMeta {
            // 'static lifetime hook: fine for tests.
            Box::leak(Box::new(test_meta("fake")))
        }

        fn capabilities(&self) -> BTreeMap<String, CapSpec> {
            BTreeMap::from_iter([
                (
                    "test.echo".to_owned(),
                    CapSpec::readonly("echo").param("msg", ParamType::Str, "text"),
                ),
                ("test.apply".to_owned(), CapSpec::mutation("change things")),
            ])
        }

        async fn exec(&self, _ctx: &ExecContext, cap: &str, params: Params) -> Result<CapResult> {
            Ok(CapResult::ok(Value::Str(format!("{cap}:{}", params.len()))))
        }
    }

    #[tokio::test]
    async fn invoke_validates_gates_and_dispatches() {
        let dev = Fake;

        // happy path
        let ctx = ExecContext::readonly("test.echo");
        let out = dev
            .invoke(&ctx, "test.echo", params!("msg" => "hi"))
            .await
            .unwrap();
        assert_eq!(out.output, Value::Str("test.echo:1".into()));

        // unknown cap
        let err = dev.invoke(&ctx, "nope", Params::new()).await.unwrap_err();
        assert!(matches!(err, MyceliumError::UnknownCapability(_)));

        // missing required param
        let err = dev
            .invoke(&ctx, "test.echo", Params::new())
            .await
            .unwrap_err();
        assert!(matches!(err, MyceliumError::Validation(_)));

        // write gate refuses mutation without allow_writes
        let gated = ExecContext {
            capability: "test.apply".into(),
            allow_writes: false,
            dry_run: false,
        };
        let err = dev
            .invoke(&gated, "test.apply", Params::new())
            .await
            .unwrap_err();
        assert!(matches!(err, MyceliumError::WritesNotPermitted(_)));

        // Planning a mutation never requires write permission.
        let dry_run = ExecContext {
            capability: "test.apply".into(),
            allow_writes: false,
            dry_run: true,
        };
        assert!(dev
            .invoke(&dry_run, "test.apply", Params::new())
            .await
            .is_ok());

        // Applying passes only with explicit opt-in.
        let opted = ExecContext {
            capability: "test.apply".into(),
            allow_writes: true,
            dry_run: false,
        };
        assert!(dev
            .invoke(&opted, "test.apply", Params::new())
            .await
            .is_ok());
    }

    #[tokio::test]
    async fn inventory_roundtrip() {
        let inv = Inventory::new();
        inv.add(Arc::new(Fake));
        assert_eq!(inv.devices().len(), 1);
        assert!(inv.get("fake").is_ok());
        assert!(inv.get("missing").is_err());
        let caps = inv.capabilities("fake").unwrap();
        assert_eq!(caps.len(), 2);
        assert_eq!(caps[0].id, "test.apply");
    }
}
