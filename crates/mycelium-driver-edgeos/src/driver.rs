use std::time::Duration;

use async_trait::async_trait;
use mycelium_core::{
    host_target, stable_slug, CredentialSet, DeviceId, DeviceKind, DeviceMeta, Driver, Inventory,
    MyceliumError, Result, Target,
};

use crate::device::{EdgeOsDevice, DRIVER_NAME};
use crate::transport::SshSession;

/// Discovery of EdgeOS/vyos appliances over SSH: recognize by probing
/// `show version` (the vyos banner), never by a configured vendor label.
pub struct EdgeOsDriver {
    connect_timeout: Duration,
}

impl Default for EdgeOsDriver {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(8),
        }
    }
}

impl EdgeOsDriver {
    pub fn with_timeout(connect_timeout: Duration) -> Self {
        Self { connect_timeout }
    }

    /// Device id slug: model-tail + address, sanitized, e.g. `edgerouter-10x-10-0-7-1`.
    fn slug(model: Option<&str>, host: &str) -> DeviceId {
        let tail = model
            .map(|m| stable_slug(m.split_whitespace().last().unwrap_or(m)))
            .unwrap_or_else(|| "vyos".into());
        let host_part = stable_slug(host);
        DeviceId::new(format!("{tail}-{host_part}"))
    }
}

#[async_trait]
impl Driver for EdgeOsDriver {
    fn name(&self) -> &str {
        DRIVER_NAME
    }

    async fn recognizes(&self, target: &Target, creds: &CredentialSet) -> Result<bool> {
        let endpoint = host_target(target, crate::DEFAULT_PORT, "edgeos probe")?;
        let host = endpoint.host;
        let session =
            match SshSession::connect_target(target, creds, self.connect_timeout, "edgeos probe")
                .await
            {
                Ok(s) => s,
                // Unreachable/refused => not this class. But bad credentials is
                // the user's error, not a negative observation: fail loud.
                Err(MyceliumError::Auth(_)) => {
                    return Err(MyceliumError::Auth(format!(
                        "{host}: {}",
                        creds.username().unwrap_or("?")
                    )))
                }
                Err(e) => {
                    eprintln!("edgeos: recognize {host} failed: {e}");
                    return Ok(false);
                }
            };
        match session.cli("show version").await {
            Ok(out) if out.success() => {
                let text = out.stdout;
                let hit = text.contains("vyos")
                    || text.contains("EdgeOS")
                    || text.contains("EdgeRouter")
                    || text.contains("EdgeRunner")
                    || text.contains("Ubiquiti");
                if !hit {
                    eprintln!(
                        "edgeos: {host} banner matched no known marker:\n{}",
                        &text[..text.len().min(400)]
                    );
                }
                Ok(hit)
            }
            Ok(out) => {
                eprintln!(
                    "edgeos: {host} probe exit {}: {}",
                    out.exit_code,
                    out.stderr.trim().lines().next().unwrap_or("")
                );
                Ok(false)
            }
            Err(e) => {
                eprintln!("edgeos: recognize {host} probe failed: {e}");
                Ok(false)
            }
        }
    }

    async fn attach(
        &self,
        target: &Target,
        creds: &CredentialSet,
        inventory: &Inventory,
    ) -> Result<DeviceId> {
        let endpoint = host_target(target, crate::DEFAULT_PORT, "edgeos attachment")?;
        let host = endpoint.host.to_owned();
        let session =
            SshSession::connect_target(target, creds, self.connect_timeout, "edgeos attachment")
                .await?;
        let (identity, config) = EdgeOsDevice::identify(&session).await?;
        let model = identity.model.clone().or_else(|| config.hostname.clone());
        let kind = model.as_deref().map(classify).unwrap_or(DeviceKind::Router);
        let meta = DeviceMeta {
            id: Self::slug(identity.model.as_deref(), &host),
            kind,
            driver: DRIVER_NAME.to_owned(),
            vendor: identity.vendor,
            model: identity.model,
            firmware: identity.firmware,
            address: host,
        };
        let id = meta.id.clone();
        inventory.add(std::sync::Arc::new(EdgeOsDevice::new(session, meta)));
        Ok(id)
    }
}

fn classify(model: &str) -> DeviceKind {
    let m = model.to_lowercase();
    if m.contains("switch") || m.starts_with("es-") || m.contains("epx") {
        DeviceKind::Switch
    } else {
        DeviceKind::Router
    }
}
