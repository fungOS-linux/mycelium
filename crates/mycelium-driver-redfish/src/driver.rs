use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use mycelium_core::{
    ActionRisk, CapResult, CapSpec, CredentialSet, Device, DeviceId, DeviceKind, DeviceMeta,
    Driver, ExecContext, Inventory, MacAddress, MyceliumError, Observation, Origin, Params, Result,
    Secret, ServiceRecord, ServiceState, Target, Value, ID_IDENTIFY,
};
use reqwest::{Client, StatusCode};
use serde_json::Value as Json;

pub const DRIVER_NAME: &str = "redfish";
pub const ID_POWER_STATE: &str = "server.power-state";
pub const ID_POWER_ON: &str = "server.power-on";
pub const ID_THERMAL: &str = "server.thermal";
const SYSTEM_PATH: &str = "/redfish/v1/Systems/1/";
const RESET_PATH: &str = "/redfish/v1/Systems/1/Actions/ComputerSystem.Reset/";

pub struct RedfishDriver {
    timeout: Duration,
}

impl Default for RedfishDriver {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(8),
        }
    }
}

#[derive(Clone)]
struct RedfishHandle {
    base: String,
    credentials: CredentialSet,
    client: Client,
}

pub struct RedfishDevice {
    handle: RedfishHandle,
    meta: DeviceMeta,
    management_mac: Option<MacAddress>,
}

fn target_host(target: &Target) -> Result<(&str, Option<u16>)> {
    match target {
        Target::Host {
            host,
            port,
            jump: None,
        } => Ok((host, *port)),
        Target::Host { jump: Some(_), .. } => Err(MyceliumError::Validation(
            "iLO Redfish does not support SSH ProxyJump targets".into(),
        )),
        Target::Subnet { .. } => Err(MyceliumError::Validation(
            "iLO driver probes one controller at a time".into(),
        )),
    }
}

fn make_handle(target: &Target, creds: &CredentialSet, timeout: Duration) -> Result<RedfishHandle> {
    let (host, port) = target_host(target)?;
    if creds.username.as_deref().unwrap_or_default().is_empty() || creds.password.is_none() {
        return Err(MyceliumError::Auth(
            "iLO requires --user and --password-env".into(),
        ));
    }
    let authority = match port {
        Some(port) => format!("{host}:{port}"),
        None => host.to_owned(),
    };
    let client = Client::builder()
        .danger_accept_invalid_certs(true)
        .https_only(true)
        .timeout(timeout)
        .build()
        .map_err(|e| MyceliumError::Transport(e.to_string()))?;
    Ok(RedfishHandle {
        base: format!("https://{authority}"),
        credentials: creds.clone(),
        client,
    })
}

impl RedfishHandle {
    fn auth(&self, request: reqwest::RequestBuilder) -> Result<reqwest::RequestBuilder> {
        let username = self
            .credentials
            .username
            .as_deref()
            .ok_or_else(|| MyceliumError::Auth("iLO username is unavailable".into()))?;
        let password = self
            .credentials
            .password
            .as_ref()
            .and_then(Secret::resolve)
            .ok_or_else(|| {
                MyceliumError::Auth("iLO password environment variable is unavailable".into())
            })?;
        Ok(request.basic_auth(username, Some(password)))
    }

    async fn get(&self, path: &str) -> Result<Json> {
        let response = self
            .auth(self.client.get(format!("{}{path}", self.base)))?
            .send()
            .await
            .map_err(|e| MyceliumError::Transport(e.to_string()))?;
        if response.status() == StatusCode::UNAUTHORIZED {
            return Err(MyceliumError::Auth(
                "iLO rejected the configured credentials".into(),
            ));
        }
        if !response.status().is_success() {
            return Err(MyceliumError::Device {
                exit_code: response.status().as_u16() as i32,
                stderr: format!("Redfish GET {path} returned {}", response.status()),
            });
        }
        response
            .json()
            .await
            .map_err(|e| MyceliumError::Parse(format!("Redfish {path}: {e}")))
    }

    async fn system(&self) -> Result<Json> {
        self.get(SYSTEM_PATH).await
    }

    async fn power_on(&self) -> Result<()> {
        let response = self
            .auth(
                self.client
                    .post(format!("{}{}", self.base, RESET_PATH))
                    .json(&serde_json::json!({"ResetType": "On"})),
            )?
            .send()
            .await
            .map_err(|e| MyceliumError::Transport(e.to_string()))?;
        if response.status() == StatusCode::UNAUTHORIZED {
            return Err(MyceliumError::Auth(
                "iLO rejected the configured credentials".into(),
            ));
        }
        if !response.status().is_success() {
            return Err(MyceliumError::Device {
                exit_code: response.status().as_u16() as i32,
                stderr: format!("Redfish power-on returned {}", response.status()),
            });
        }
        Ok(())
    }
}

fn string(value: &Json, key: &str) -> Option<String> {
    value
        .get(key)?
        .as_str()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
}

fn identity_value(system: &Json) -> Value {
    Value::Map(Params::from_iter([
        (
            "vendor".into(),
            string(system, "Manufacturer")
                .map(Value::Str)
                .unwrap_or(Value::Null),
        ),
        (
            "model".into(),
            string(system, "Model")
                .map(Value::Str)
                .unwrap_or(Value::Null),
        ),
        (
            "serial".into(),
            string(system, "SerialNumber")
                .map(Value::Str)
                .unwrap_or(Value::Null),
        ),
        (
            "bios".into(),
            string(system, "BiosVersion")
                .map(Value::Str)
                .unwrap_or(Value::Null),
        ),
        (
            "power_state".into(),
            string(system, "PowerState")
                .map(Value::Str)
                .unwrap_or(Value::Null),
        ),
    ]))
}

fn thermal_value(thermal: &Json) -> Value {
    let rows = |key: &str, name_key: &str, reading_key: &str| {
        thermal
            .get(key)
            .and_then(Json::as_array)
            .into_iter()
            .flatten()
            .map(|item| {
                Value::Map(Params::from_iter([
                    (
                        "name".into(),
                        string(item, name_key)
                            .map(Value::Str)
                            .unwrap_or(Value::Null),
                    ),
                    (
                        "reading".into(),
                        item.get(reading_key)
                            .and_then(Json::as_i64)
                            .map(Value::Int)
                            .unwrap_or(Value::Null),
                    ),
                    (
                        "units".into(),
                        string(item, "Units").map(Value::Str).unwrap_or(Value::Null),
                    ),
                    (
                        "state".into(),
                        item.pointer("/Status/State")
                            .and_then(Json::as_str)
                            .map(|s| Value::Str(s.into()))
                            .unwrap_or(Value::Null),
                    ),
                ]))
            })
            .collect()
    };
    Value::Map(Params::from_iter([
        (
            "fans".into(),
            Value::List(rows("Fans", "FanName", "CurrentReading")),
        ),
        (
            "temperatures".into(),
            Value::List(rows("Temperatures", "Name", "ReadingCelsius")),
        ),
    ]))
}

#[async_trait]
impl Driver for RedfishDriver {
    fn name(&self) -> &str {
        DRIVER_NAME
    }

    async fn recognizes(&self, target: &Target, creds: &CredentialSet) -> Result<bool> {
        let handle = make_handle(target, creds, self.timeout)?;
        let root = handle.get("/redfish/v1/").await?;
        Ok(root.get("RedfishVersion").and_then(Json::as_str).is_some())
    }

    async fn attach(
        &self,
        target: &Target,
        creds: &CredentialSet,
        inventory: &Inventory,
    ) -> Result<DeviceId> {
        let handle = make_handle(target, creds, self.timeout)?;
        let system = handle.system().await?;
        let (host, port) = target_host(target)?;
        let serial = string(&system, "SerialNumber").unwrap_or_else(|| host.to_owned());
        let slug = serial
            .to_lowercase()
            .replace(|c: char| !c.is_ascii_alphanumeric(), "-");
        let manager = handle.get("/redfish/v1/Managers/1/").await.ok();
        let management_mac = handle
            .get("/redfish/v1/Managers/1/EthernetInterfaces/1/")
            .await
            .ok()
            .and_then(|nic| string(&nic, "PermanentMACAddress"))
            .and_then(|mac| MacAddress::parse(&mac));
        let meta = DeviceMeta {
            id: DeviceId::new(format!("ilo-{slug}")),
            kind: DeviceKind::Bmc,
            driver: DRIVER_NAME.into(),
            vendor: string(&system, "Manufacturer"),
            model: string(&system, "Model"),
            firmware: manager
                .as_ref()
                .and_then(|value| string(value, "FirmwareVersion")),
            address: match port {
                Some(port) => format!("{host}:{port}"),
                None => host.to_owned(),
            },
        };
        let id = meta.id.clone();
        inventory.add(Arc::new(RedfishDevice {
            handle,
            meta,
            management_mac,
        }));
        Ok(id)
    }
}

#[async_trait]
impl Device for RedfishDevice {
    fn meta(&self) -> &DeviceMeta {
        &self.meta
    }

    fn capabilities(&self) -> BTreeMap<String, CapSpec> {
        BTreeMap::from_iter([
            (
                ID_IDENTIFY.into(),
                CapSpec::readonly("HPE server identity from Redfish"),
            ),
            (
                ID_POWER_STATE.into(),
                CapSpec::readonly("current server power state"),
            ),
            (
                ID_POWER_ON.into(),
                CapSpec::mutation("power on the server through Redfish")
                    .verified_by(ActionRisk::Disruptive, ID_POWER_STATE),
            ),
            (
                ID_THERMAL.into(),
                CapSpec::readonly("fan and temperature telemetry from Redfish"),
            ),
        ])
    }

    async fn exec(&self, ctx: &ExecContext, cap: &str, _params: Params) -> Result<CapResult> {
        match cap {
            ID_IDENTIFY => Ok(CapResult::ok(identity_value(&self.handle.system().await?))),
            ID_POWER_STATE => {
                let system = self.handle.system().await?;
                Ok(CapResult::ok(
                    string(&system, "PowerState")
                        .map(Value::Str)
                        .unwrap_or(Value::Null),
                ))
            }
            ID_THERMAL => Ok(CapResult::ok(thermal_value(
                &self.handle.get("/redfish/v1/Chassis/1/Thermal/").await?,
            ))),
            ID_POWER_ON if ctx.dry_run => Ok(CapResult::dry_run(Value::Map(Params::from_iter([
                ("action".into(), Value::Str(RESET_PATH.into())),
                ("reset_type".into(), Value::Str("On".into())),
            ])))),
            ID_POWER_ON => {
                self.handle.power_on().await?;
                Ok(CapResult::ok(Value::Str("power-on accepted".into())))
            }
            other => Err(MyceliumError::Unsupported {
                device: self.meta.id.to_string(),
                capability: other.into(),
            }),
        }
    }

    async fn observe(&self) -> Result<(Vec<Observation>, Vec<String>)> {
        let system = self.handle.system().await?;
        let Some(ip) = self
            .meta
            .address
            .split(':')
            .next()
            .and_then(|s| s.parse().ok())
        else {
            return Ok((Vec::new(), vec!["iLO address is not an IP literal".into()]));
        };
        Ok((
            vec![
                Observation::Neighbor {
                    mac: self.management_mac,
                    ip,
                    hostname: Some(format!(
                        "ilo-{}",
                        string(&system, "SerialNumber")
                            .unwrap_or_else(|| "unknown".into())
                            .to_lowercase()
                    )),
                    port: None,
                    origin: Origin::new(self.meta.id.to_string(), "redfish"),
                },
                Observation::Service {
                    device: self.meta.id.to_string(),
                    mac: self.management_mac,
                    ip: Some(ip),
                    service: ServiceRecord {
                        name: "redfish".into(),
                        transport: "tcp".into(),
                        port: 443,
                        product: self
                            .meta
                            .firmware
                            .clone()
                            .map(|version| format!("HPE iLO {version}")),
                        state: ServiceState::Up,
                        observed_at: std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_secs(),
                        host_local: false,
                        origin: Origin::new(self.meta.id.to_string(), "redfish"),
                    },
                },
            ],
            Vec::new(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn simplifies_redfish_identity_and_thermal_data() {
        let system = serde_json::json!({
            "Manufacturer": "HPE",
            "Model": "ProLiant DL360p Gen8",
            "SerialNumber": " MXQ33702Q8 ",
            "PowerState": "Off"
        });
        assert_eq!(
            identity_value(&system)
                .get("serial")
                .and_then(Value::as_str),
            Some("MXQ33702Q8")
        );

        let thermal = serde_json::json!({
            "Fans": [{"FanName":"Fan 1","CurrentReading":23,"Units":"Percent","Status":{"State":"Enabled"}}],
            "Temperatures": [{"Name":"Inlet","ReadingCelsius":19,"Units":"Celsius","Status":{"State":"Enabled"}}]
        });
        assert_eq!(
            thermal_value(&thermal)
                .get("fans")
                .and_then(Value::as_list)
                .unwrap()
                .len(),
            1
        );
    }
}
