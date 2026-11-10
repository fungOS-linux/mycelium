use async_trait::async_trait;

use crate::error::Result;
use crate::exec::ExecContext;
use crate::inventory::Device;
use crate::params;
use crate::spec::CapResult;
use crate::value::{IntoValue, Params, Value};

/// Typed facades over declared capabilities.
///
/// These traits are convenience + a compile-time checklist for the common
/// feature slices every target shares (DNS, DHCP, VLAN, wireless, sensors).
/// Default implementations route through `exec` using conventional
/// capability ids; drivers that can do better natively just override.
/// A device that lacks the slice simply doesn't declare those ids, and the
/// default facades return [`crate::MyceliumError::Unsupported`].

pub const ID_IDENTIFY: &str = "system.identify";
pub const ID_CAPABILITIES: &str = "system.capabilities";
pub const ID_SYSTEM_HEALTH: &str = "system.health";
pub const ID_VLAN_LIST: &str = "vlan.list";
pub const ID_VLAN_CREATE: &str = "vlan.create";
pub const ID_VLAN_ASSIGN: &str = "vlan.assign";
pub const ID_SWITCH_OBSERVE: &str = "switch.observe";
pub const ID_NET_VIP_ENSURE: &str = "net.vip.ensure";
pub const ID_NET_FORWARD_ENSURE: &str = "net.forward.ensure";
pub const ID_DHCP_LIST_POOLS: &str = "dhcp.list-pools";
pub const ID_DHCP_ENSURE_POOL: &str = "dhcp.ensure-pool";
pub const ID_DHCP_ADD_STATIC_LEASE: &str = "dhcp.add-static-lease";
pub const ID_DNS_LIST_ENTRIES: &str = "dns.list-entries";
pub const ID_DNS_BLOCK: &str = "dns.block";
pub const ID_WLAN_LIST_SSID: &str = "wlan.list-ssids";
pub const ID_WLAN_GUEST_ENABLE: &str = "wlan.guest-enable";
pub const ID_SENSOR_READ: &str = "sensor.read";
pub const ID_SENSOR_HISTORY: &str = "sensor.history";

#[async_trait]
pub trait Identity: Device {
    /// Vendor/model/firmware as inferred by the driver.
    async fn identify(&self, ctx: &ExecContext) -> Result<Value> {
        Ok(self.invoke(ctx, ID_IDENTIFY, Params::new()).await?.output)
    }
}

#[async_trait]
pub trait VlanManagement: Device {
    async fn list_vlans(&self, ctx: &ExecContext) -> Result<CapResult> {
        self.invoke(ctx, ID_VLAN_LIST, Params::new()).await
    }

    async fn create_vlan(
        &self,
        ctx: &ExecContext,
        id: u16,
        name: Option<&str>,
    ) -> Result<CapResult> {
        let mut params = params!("id" => Value::Int(id as i64));
        if let Some(name) = name {
            params.insert("name".into(), name.to_owned().into_value());
        }
        self.invoke(ctx, ID_VLAN_CREATE, params).await
    }

    async fn assign_port(
        &self,
        ctx: &ExecContext,
        port: &str,
        vlan: u16,
        tagged: bool,
    ) -> Result<CapResult> {
        let params = params!(
            "port" => port,
            "vlan" => Value::Int(vlan as i64),
            "tagged" => tagged,
        );
        self.invoke(ctx, ID_VLAN_ASSIGN, params).await
    }
}

#[async_trait]
pub trait DhcpManagement: Device {
    async fn list_pools(&self, ctx: &ExecContext) -> Result<CapResult> {
        self.invoke(ctx, ID_DHCP_LIST_POOLS, Params::new()).await
    }

    async fn add_static_lease(
        &self,
        ctx: &ExecContext,
        interface: &str,
        mac: &str,
        ip: &str,
        name: Option<&str>,
    ) -> Result<CapResult> {
        let mut params = params!("interface" => interface, "mac" => mac, "ip" => ip);
        if let Some(name) = name {
            params.insert("name".into(), name.to_owned().into_value());
        }
        self.invoke(ctx, ID_DHCP_ADD_STATIC_LEASE, params).await
    }
}

#[async_trait]
pub trait DnsFiltering: Device {
    async fn list_entries(&self, ctx: &ExecContext) -> Result<CapResult> {
        self.invoke(ctx, ID_DNS_LIST_ENTRIES, Params::new()).await
    }

    async fn block_domain(
        &self,
        ctx: &ExecContext,
        domain: &str,
        comment: Option<&str>,
    ) -> Result<CapResult> {
        let mut params = params!("domain" => domain);
        if let Some(comment) = comment {
            params.insert("comment".into(), comment.to_owned().into_value());
        }
        self.invoke(ctx, ID_DNS_BLOCK, params).await
    }
}

#[async_trait]
pub trait Wireless: Device {
    async fn list_ssids(&self, ctx: &ExecContext) -> Result<CapResult> {
        self.invoke(ctx, ID_WLAN_LIST_SSID, Params::new()).await
    }

    async fn set_guest_enabled(
        &self,
        ctx: &ExecContext,
        ssid: &str,
        enabled: bool,
    ) -> Result<CapResult> {
        let params = params!("ssid" => ssid, "enabled" => enabled);
        self.invoke(ctx, ID_WLAN_GUEST_ENABLE, params).await
    }
}

#[async_trait]
pub trait Sensors: Device {
    /// Current readings (iDRAC/IPMI style devices).
    async fn read_sensors(&self, ctx: &ExecContext) -> Result<CapResult> {
        self.invoke(ctx, ID_SENSOR_READ, Params::new()).await
    }

    async fn sensor_history(
        &self,
        ctx: &ExecContext,
        sensor: &str,
        last: u32,
    ) -> Result<CapResult> {
        let params = params!("sensor" => sensor, "last" => Value::Int(last as i64));
        self.invoke(ctx, ID_SENSOR_HISTORY, params).await
    }
}

// No blanket impls: a device implements only the slices it honestly
// supports, and may override any method where the conventional shape does
// not match the appliance (e.g. EdgeOS has no VLAN objects separable from
// port membership). The default bodies route to the conventional ids so
// supporting a slice is usually a one-line `impl Trait for Device {}`.

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device::{DeviceId, DeviceKind, DeviceMeta};
    use crate::inventory::Device;
    use crate::spec::CapSpec;
    use crate::MyceliumError;
    use std::collections::BTreeMap;

    struct OnlyVlans;

    #[async_trait]
    impl VlanManagement for OnlyVlans {}

    #[async_trait]
    impl Device for OnlyVlans {
        fn meta(&self) -> &DeviceMeta {
            Box::leak(Box::new(DeviceMeta {
                id: DeviceId::new("sw0"),
                kind: DeviceKind::Switch,
                driver: "fake".into(),
                vendor: None,
                model: None,
                firmware: None,
                address: "10.0.0.2".into(),
            }))
        }

        fn capabilities(&self) -> BTreeMap<String, CapSpec> {
            BTreeMap::from_iter([(
                ID_VLAN_LIST.to_owned(),
                CapSpec::readonly("list vlans").returns("list of {id, name} maps"),
            )])
        }

        async fn exec(&self, _c: &ExecContext, cap: &str, _p: Params) -> Result<CapResult> {
            assert_eq!(cap, ID_VLAN_LIST);
            let row = Value::Map(Params::from_iter([
                ("id".to_owned(), Value::Int(10)),
                ("name".to_owned(), Value::Str("lab".into())),
            ]));
            Ok(CapResult::ok(Value::List(vec![row])))
        }
    }

    #[tokio::test]
    async fn facade_dispatches_declared_capability() {
        let dev = OnlyVlans;
        let ctx = ExecContext::readonly(ID_VLAN_LIST);
        let res = dev.list_vlans(&ctx).await.unwrap();
        assert_eq!(res.output.as_list().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn undeclared_slice_is_unsupported_not_panic() {
        let dev = OnlyVlans;
        let ctx = ExecContext::readonly(ID_DHCP_LIST_POOLS);
        let err = dev
            .invoke(&ctx, ID_DHCP_LIST_POOLS, Params::new())
            .await
            .unwrap_err();
        assert!(matches!(err, MyceliumError::UnknownCapability(_)));
    }
}
