use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use mycelium_core::{
    stable_slug, ActionRisk, CapResult, CapSpec, CredentialSet, Device, DeviceId, DeviceKind,
    DeviceMeta, Driver, ExecContext, Inventory, MacAddress, MyceliumError, Observation, Origin,
    ParamType, Params, PortRef, Result, Secret, ServiceRecord, ServiceState, Target, Value,
    ID_IDENTIFY, ID_WLAN_GUEST_ENABLE, ID_WLAN_LIST_SSID,
};
use reqwest::header::{COOKIE, SET_COOKIE};
use serde_json::{json, Map as JsonMap};

pub const CONTROLLER_DRIVER_NAME: &str = "unifi-controller";
const ID_LIST_APS: &str = "unifi.list-aps";
const ID_LIST_CLIENTS: &str = "unifi.list-clients";

pub struct UnifiControllerDriver {
    timeout: Duration,
}

impl Default for UnifiControllerDriver {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(10),
        }
    }
}

struct ControllerDevice {
    handle: ControllerHandle,
    meta: DeviceMeta,
    sites: Vec<String>,
}

#[derive(Clone)]
struct ControllerHandle {
    client: reqwest::Client,
    base: String,
    credentials: CredentialSet,
}

#[derive(Debug)]
struct Session {
    cookie: String,
}

fn endpoint(target: &Target) -> Result<String> {
    let Target::Host { host, port, .. } = target else {
        return Err(MyceliumError::Validation(
            "UniFi controller attachment needs one host".into(),
        ));
    };
    if host.starts_with("http://") {
        return Err(MyceliumError::Validation(
            "UniFi controller transport must use HTTPS".into(),
        ));
    }
    if host.starts_with("https://") {
        return Ok(host.trim_end_matches('/').to_owned());
    }
    Ok(format!("https://{host}:{}", port.unwrap_or(8443)))
}

impl ControllerHandle {
    fn new(base: String, credentials: CredentialSet, timeout: Duration) -> Result<Self> {
        let client = reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .timeout(timeout)
            .build()
            .map_err(|error| MyceliumError::Transport(error.to_string()))?;
        Ok(Self {
            client,
            base,
            credentials,
        })
    }

    async fn status(&self) -> Result<serde_json::Value> {
        self.request_json(self.client.get(format!("{}/status", self.base)))
            .await
    }

    async fn login(&self) -> Result<Session> {
        let username = self
            .credentials
            .username()
            .ok_or_else(|| MyceliumError::Auth("controller username is required".into()))?;
        let password = self
            .credentials
            .password
            .as_ref()
            .and_then(Secret::resolve)
            .ok_or_else(|| {
                MyceliumError::Auth("controller password environment is unset".into())
            })?;
        let response = self
            .client
            .post(format!("{}/api/login", self.base))
            .json(&json!({"username": username, "password": password, "remember": false}))
            .send()
            .await
            .map_err(http_error)?;
        let status = response.status();
        let cookie = response
            .headers()
            .get_all(SET_COOKIE)
            .iter()
            .filter_map(|value| value.to_str().ok())
            .filter_map(|value| value.split(';').next())
            .collect::<Vec<_>>()
            .join("; ");
        let body: serde_json::Value = response.json().await.map_err(http_error)?;
        if !status.is_success() || body.pointer("/meta/rc").and_then(|v| v.as_str()) != Some("ok") {
            return Err(MyceliumError::Auth(format!(
                "UniFi controller rejected login (HTTP {status})"
            )));
        }
        if cookie.is_empty() {
            return Err(MyceliumError::Auth(
                "UniFi controller login returned no session cookie".into(),
            ));
        }
        Ok(Session { cookie })
    }

    async fn get(&self, session: &Session, path: &str) -> Result<serde_json::Value> {
        self.request_json(
            self.client
                .get(format!("{}{}", self.base, path))
                .header(COOKIE, &session.cookie),
        )
        .await
    }

    async fn put(
        &self,
        session: &Session,
        path: &str,
        body: &serde_json::Value,
    ) -> Result<serde_json::Value> {
        self.request_json(
            self.client
                .put(format!("{}{}", self.base, path))
                .header(COOKIE, &session.cookie)
                .json(body),
        )
        .await
    }

    async fn request_json(&self, request: reqwest::RequestBuilder) -> Result<serde_json::Value> {
        let response = request.send().await.map_err(http_error)?;
        let status = response.status();
        let body: serde_json::Value = response.json().await.map_err(http_error)?;
        if !status.is_success()
            || body.pointer("/meta/rc").and_then(|v| v.as_str()) == Some("error")
        {
            let message = body
                .pointer("/meta/msg")
                .and_then(|value| value.as_str())
                .unwrap_or("controller request failed");
            return Err(MyceliumError::Device {
                exit_code: status.as_u16() as i32,
                stderr: message.to_owned(),
            });
        }
        Ok(body)
    }
}

#[async_trait]
impl Driver for UnifiControllerDriver {
    fn name(&self) -> &str {
        CONTROLLER_DRIVER_NAME
    }

    async fn recognizes(&self, target: &Target, creds: &CredentialSet) -> Result<bool> {
        let handle = ControllerHandle::new(endpoint(target)?, creds.clone(), self.timeout)?;
        Ok(handle
            .status()
            .await
            .ok()
            .and_then(|body| body.pointer("/meta/up").and_then(|value| value.as_bool()))
            == Some(true))
    }

    async fn attach(
        &self,
        target: &Target,
        creds: &CredentialSet,
        inventory: &Inventory,
    ) -> Result<DeviceId> {
        let base = endpoint(target)?;
        let handle = ControllerHandle::new(base.clone(), creds.clone(), self.timeout)?;
        let status = handle.status().await?;
        let session = handle.login().await?;
        let sites_body = handle.get(&session, "/api/self/sites").await?;
        let sites = data(&sites_body)
            .iter()
            .filter_map(|site| site.get("name").and_then(|value| value.as_str()))
            .map(str::to_owned)
            .collect::<Vec<_>>();
        if sites.is_empty() {
            return Err(MyceliumError::Auth(
                "controller account has no accessible sites".into(),
            ));
        }
        let host = base
            .trim_start_matches("https://")
            .split(':')
            .next()
            .unwrap_or("controller");
        let firmware = status
            .pointer("/meta/server_version")
            .and_then(|value| value.as_str())
            .map(str::to_owned);
        let meta = DeviceMeta {
            id: DeviceId::new(format!("unifi-controller-{}", stable_slug(host))),
            kind: DeviceKind::Other,
            driver: CONTROLLER_DRIVER_NAME.into(),
            vendor: Some("Ubiquiti".into()),
            model: Some("UniFi Network Controller".into()),
            firmware,
            address: base,
        };
        let id = meta.id.clone();
        inventory.add(Arc::new(ControllerDevice {
            handle,
            meta,
            sites,
        }));
        Ok(id)
    }
}

#[async_trait]
impl Device for ControllerDevice {
    fn meta(&self) -> &DeviceMeta {
        &self.meta
    }

    fn capabilities(&self) -> BTreeMap<String, CapSpec> {
        BTreeMap::from_iter([
            (
                ID_IDENTIFY.into(),
                CapSpec::readonly("UniFi Network controller identity and sites"),
            ),
            (
                ID_WLAN_LIST_SSID.into(),
                CapSpec::readonly("WLAN definitions across accessible sites"),
            ),
            (
                ID_LIST_APS.into(),
                CapSpec::readonly("adopted access points and live state"),
            ),
            (
                ID_LIST_CLIENTS.into(),
                CapSpec::readonly("active clients across accessible sites"),
            ),
            (
                ID_WLAN_GUEST_ENABLE.into(),
                CapSpec::mutation("set guest policy on a WLAN")
                    .verified_by(ActionRisk::Disruptive, ID_WLAN_LIST_SSID)
                    .param("ssid", ParamType::Str, "exact WLAN name")
                    .param("enabled", ParamType::Bool, "guest policy state"),
            ),
        ])
    }

    async fn exec(&self, ctx: &ExecContext, cap: &str, params: Params) -> Result<CapResult> {
        match cap {
            ID_IDENTIFY => Ok(CapResult::ok(Value::Map(Params::from_iter([
                ("vendor".into(), Value::Str("Ubiquiti".into())),
                (
                    "model".into(),
                    Value::Str("UniFi Network Controller".into()),
                ),
                (
                    "version".into(),
                    self.meta
                        .firmware
                        .clone()
                        .map(Value::Str)
                        .unwrap_or(Value::Null),
                ),
                (
                    "sites".into(),
                    Value::List(self.sites.iter().cloned().map(Value::Str).collect()),
                ),
            ])))),
            ID_WLAN_LIST_SSID => self.collect("rest/wlanconf", wlan_view).await,
            ID_LIST_APS => self.collect("stat/device", ap_view).await,
            ID_LIST_CLIENTS => self.collect("stat/sta", client_view).await,
            ID_WLAN_GUEST_ENABLE => self.set_guest(ctx, &params).await,
            other => Err(MyceliumError::Unsupported {
                device: self.meta.id.to_string(),
                capability: other.into(),
            }),
        }
    }

    async fn observe(&self) -> Result<(Vec<Observation>, Vec<String>)> {
        let session = self.handle.login().await?;
        let mut observations = Vec::new();
        let mut warnings = Vec::new();
        observations.push(Observation::Service {
            device: self.meta.id.to_string(),
            mac: None,
            ip: None,
            service: ServiceRecord {
                name: "unifi-controller".into(),
                transport: "tcp".into(),
                port: 8443,
                product: self
                    .meta
                    .firmware
                    .clone()
                    .map(|version| format!("UniFi Network {version}")),
                state: ServiceState::Up,
                observed_at: unix_time(),
                host_local: false,
                origin: Origin::new(self.meta.id.to_string(), "controller-api"),
            },
        });
        for site in &self.sites {
            let path = format!("/api/s/{site}/stat/sta");
            match self.handle.get(&session, &path).await {
                Ok(body) => {
                    for client in data(&body) {
                        let Some(mac) = client
                            .get("mac")
                            .and_then(|value| value.as_str())
                            .and_then(MacAddress::parse)
                        else {
                            continue;
                        };
                        let ap = client
                            .get("ap_mac")
                            .and_then(|value| value.as_str())
                            .and_then(MacAddress::parse)
                            .map(|value| value.to_string())
                            .or_else(|| {
                                client
                                    .get("ap_name")
                                    .and_then(|value| value.as_str())
                                    .map(str::to_owned)
                            })
                            .unwrap_or_else(|| self.meta.id.to_string());
                        observations.push(Observation::Attachment {
                            mac,
                            hostname: client
                                .get("hostname")
                                .and_then(|value| value.as_str())
                                .map(str::to_owned),
                            port: PortRef {
                                device: ap,
                                port: client
                                    .get("essid")
                                    .and_then(|value| value.as_str())
                                    .unwrap_or("wifi")
                                    .to_owned(),
                                vif: None,
                            },
                            origin: Origin::new(self.meta.id.to_string(), "unifi-stations")
                                .at_site(site),
                        });
                    }
                }
                Err(error) => warnings.push(format!("site {site} clients: {error}")),
            }
        }
        Ok((observations, warnings))
    }
}

impl ControllerDevice {
    async fn collect(
        &self,
        resource: &str,
        view: fn(&str, &serde_json::Value) -> Option<Value>,
    ) -> Result<CapResult> {
        let session = self.handle.login().await?;
        let mut rows = Vec::new();
        for site in &self.sites {
            let body = self
                .handle
                .get(&session, &format!("/api/s/{site}/{resource}"))
                .await?;
            rows.extend(data(&body).iter().filter_map(|item| view(site, item)));
        }
        Ok(CapResult::ok(Value::List(rows)))
    }

    async fn set_guest(&self, ctx: &ExecContext, params: &Params) -> Result<CapResult> {
        let ssid = params
            .get("ssid")
            .and_then(Value::as_str)
            .ok_or_else(|| MyceliumError::Validation("`ssid` must be a string".into()))?;
        let enabled = match params.get("enabled") {
            Some(Value::Bool(value)) => *value,
            _ => {
                return Err(MyceliumError::Validation(
                    "`enabled` must be a boolean".into(),
                ))
            }
        };
        let session = self.handle.login().await?;
        let mut matches = Vec::new();
        for site in &self.sites {
            let body = self
                .handle
                .get(&session, &format!("/api/s/{site}/rest/wlanconf"))
                .await?;
            for wlan in data(&body) {
                if wlan.get("name").and_then(|value| value.as_str()) == Some(ssid) {
                    let id = wlan
                        .get("_id")
                        .and_then(|value| value.as_str())
                        .ok_or_else(|| MyceliumError::Parse("WLAN has no object id".into()))?;
                    matches.push((site.clone(), id.to_owned()));
                }
            }
        }
        match matches.as_slice() {
            [] => {
                return Err(MyceliumError::Validation(format!(
                    "WLAN `{ssid}` was not found"
                )))
            }
            [(_, _)] => {}
            _ => {
                return Err(MyceliumError::Validation(format!(
                    "WLAN `{ssid}` exists in multiple sites; site selection is required"
                )))
            }
        }
        let (site, id) = &matches[0];
        let plan = json!({
            "site": site,
            "ssid": ssid,
            "object_id": id,
            "guest_policy": enabled,
        });
        if ctx.dry_run {
            return Ok(CapResult::dry_run(Value::from_json(&plan)));
        }
        self.handle
            .put(
                &session,
                &format!("/api/s/{site}/rest/wlanconf/{id}"),
                &json!({"guest_policy": enabled}),
            )
            .await?;
        Ok(CapResult::ok(Value::from_json(&plan)))
    }
}

fn data(body: &serde_json::Value) -> &[serde_json::Value] {
    body.get("data")
        .and_then(|value| value.as_array())
        .map(Vec::as_slice)
        .unwrap_or(&[])
}

fn selected(item: &serde_json::Value, keys: &[&str]) -> JsonMap<String, serde_json::Value> {
    keys.iter()
        .filter_map(|key| item.get(*key).cloned().map(|value| ((*key).into(), value)))
        .collect()
}

fn with_site(site: &str, mut fields: JsonMap<String, serde_json::Value>) -> Value {
    fields.insert("site".into(), json!(site));
    Value::from_json(&serde_json::Value::Object(fields))
}

fn wlan_view(site: &str, item: &serde_json::Value) -> Option<Value> {
    item.get("name")?;
    Some(with_site(
        site,
        selected(
            item,
            &[
                "_id",
                "name",
                "enabled",
                "security",
                "wpa_mode",
                "vlan_enabled",
                "vlan",
                "guest_policy",
                "hide_ssid",
            ],
        ),
    ))
}

fn ap_view(site: &str, item: &serde_json::Value) -> Option<Value> {
    (item.get("type").and_then(|value| value.as_str()) == Some("uap")).then(|| {
        with_site(
            site,
            selected(
                item,
                &[
                    "_id", "name", "model", "ip", "mac", "state", "adopted", "version", "uptime",
                    "num_sta",
                ],
            ),
        )
    })
}

fn client_view(site: &str, item: &serde_json::Value) -> Option<Value> {
    item.get("mac")?;
    Some(with_site(
        site,
        selected(
            item,
            &[
                "hostname", "ip", "mac", "ap_name", "essid", "channel", "radio", "signal", "noise",
                "uptime", "ap_mac",
            ],
        ),
    ))
}

fn http_error(error: reqwest::Error) -> MyceliumError {
    MyceliumError::Transport(error.to_string())
}

fn unix_time() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requires_https_and_builds_legacy_controller_endpoint() {
        assert_eq!(
            endpoint(&Target::parse("192.168.20.12:8443").unwrap()).unwrap(),
            "https://192.168.20.12:8443"
        );
        assert!(endpoint(&Target::host("http://controller")).is_err());
    }

    #[test]
    fn views_do_not_leak_wlan_keys_or_client_private_fields() {
        let wlan = wlan_view(
            "default",
            &json!({"name":"lab", "x_passphrase":"secret", "enabled":true}),
        )
        .unwrap()
        .to_json();
        assert_eq!(wlan["name"], "lab");
        assert!(wlan.get("x_passphrase").is_none());

        let client = client_view(
            "default",
            &json!({"mac":"00:11:22:33:44:55", "hostname":"phone", "key":"secret"}),
        )
        .unwrap()
        .to_json();
        assert!(client.get("key").is_none());
    }
}
