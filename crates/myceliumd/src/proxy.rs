//! Local service proxy: a loopback SOCKS5/HTTP listener that reaches a peer's
//! service over iroh with the `mycelium/service/1` ALPN.
//!
//! Layers this deliberately keeps separate:
//! - The *transport* here is proxy+iroh, the default service-access path when a
//!   peer's overlay address is not routed to a WireGuard fast path.
//! - The *records/topology sync* feed (a different ALPN and a different
//!   endpoint) is what tells the resolver which peer and hints exist. This
//!   module never speaks the sync protocol.
//! - The overlay address space is transport-agnostic. A target that resolves to
//!   a node is reached here; whether the kernel could have taken a WireGuard
//!   fast path instead is a routing decision made before this code runs.
//!
//! Configuration is read from `home/proxy.json`. The listener binds loopback
//! only. The serving side dials loopback targets only, and only when
//! `allow_loopback_targets` is set; otherwise it fails closed.
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::service::{
    decode_request, encode_request, validate_target, ServiceRequest, ACK_OK, ACK_REFUSED,
    MAX_REQUEST_BYTES, SERVICE_ALPN,
};

/// One resolved destination: the peer's iroh address plus the loopback target
/// that peer should dial on our behalf.
#[derive(Clone, Debug)]
pub struct ProxyTarget {
    pub peer: iroh::EndpointAddr,
    pub request: ServiceRequest,
}

/// The daemon supplies this from the .myc catalog (overlay records + service
/// leases). It resolves a requested host/port to a peer and a remote target.
#[async_trait::async_trait]
pub trait TargetResolver: Send + Sync {
    async fn resolve(&self, host: &str, port: u16) -> Option<ProxyTarget>;
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProxyConfig {
    /// A proxy that is not explicitly enabled never starts.
    #[serde(default)]
    pub enabled: bool,
    /// SOCKS5 + HTTP CONNECT listener. Loopback only; a non-loopback value is
    /// refused rather than silently widened.
    #[serde(default = "default_listen")]
    pub listen: String,
    /// UDP port for the service endpoint. Stable so hints stay valid across a
    /// reload, exactly like the sync endpoint.
    #[serde(default)]
    pub port: Option<u16>,
    /// Public relays stay opt-in, matching the sync transport.
    #[serde(default)]
    pub public_relays: bool,
    /// Serving side only: permit dialing loopback targets. Defaults to false so
    /// a misconfigured listener cannot become an open relay.
    #[serde(default)]
    pub allow_loopback_targets: bool,
}

fn default_listen() -> String {
    "127.0.0.1:1080".into()
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            listen: default_listen(),
            port: None,
            public_relays: false,
            allow_loopback_targets: false,
        }
    }
}

impl ProxyConfig {
    pub fn validate(&self) -> Result<(), String> {
        let listen: SocketAddr = self
            .listen
            .parse()
            .map_err(|_| format!("invalid proxy listen address `{}`", self.listen))?;
        if !listen.ip().is_loopback() {
            return Err("proxy listener must bind a loopback address".into());
        }
        if listen.port() == 0 {
            return Err("proxy listener port must not be 0".into());
        }
        Ok(())
    }
}

/// Read `home/proxy.json`. An absent file means "proxy disabled"; a malformed
/// file is an error so a broken config never silently becomes a listener.
pub fn load_config(home: &Path) -> Result<ProxyConfig, String> {
    let path = home.join("proxy.json");
    match std::fs::read(&path) {
        Ok(bytes) => {
            let config: ProxyConfig = serde_json::from_slice(&bytes)
                .map_err(|error| format!("invalid proxy.json: {error}"))?;
            config.validate()?;
            Ok(config)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(ProxyConfig::default()),
        Err(error) => Err(format!("cannot read proxy.json: {error}")),
    }
}

/// Bind the dedicated service endpoint. It shares the transport identity
/// (`iroh-secret.key`) with sync so a peer has one endpoint id, but uses its own
/// UDP port, ALPN, and stream budget. The service endpoint never carries gossip.
#[cfg(feature = "iroh-sync")]
pub async fn bind_service_endpoint(
    home: &Path,
    config: &ProxyConfig,
) -> Result<iroh::Endpoint, String> {
    use iroh::endpoint::{BindOpts, PortmapperConfig, QuicTransportConfig};
    let key = crate::peer::transport_key(&home.join("iroh-secret.key"))
        .map_err(|error| format!("service transport key: {error}"))?;
    let port = config.port.unwrap_or(0);
    let builder = iroh::Endpoint::builder(iroh::endpoint::presets::N0)
        .secret_key(key)
        .clear_ip_transports()
        .bind_addr(format!("0.0.0.0:{port}"))
        .map_err(|error| format!("service endpoint bind: {error}"))?
        .bind_addr_with_opts(
            format!("[::]:{port}"),
            BindOpts::default().set_is_required(false),
        )
        .map_err(|error| format!("service endpoint bind: {error}"))?
        .clear_address_lookup()
        .portmapper_config(PortmapperConfig::Disabled)
        .transport_config(
            QuicTransportConfig::builder()
                .max_concurrent_bidi_streams(64u8.into())
                .max_concurrent_uni_streams(0u8.into())
                .build(),
        )
        .alpns(vec![SERVICE_ALPN.to_vec()]);
    let builder = if config.public_relays {
        builder
    } else {
        builder.relay_mode(iroh::RelayMode::Disabled)
    };
    builder
        .bind()
        .await
        .map_err(|error| format!("service endpoint bind: {error}"))
}

/// Serve one accepted service connection: read the framed target, dial it, ack,
/// then relay bytes in both directions. Errors are per-connection, never fatal
/// to the listener.
#[cfg(feature = "iroh-sync")]
pub async fn serve_connection(
    connection: iroh::endpoint::Connection,
    allow_loopback_targets: bool,
) -> Result<(), String> {
    let (mut send, mut recv) = connection
        .accept_bi()
        .await
        .map_err(|error| format!("service accept_bi: {error}"))?;
    let request = match read_request(&mut recv).await {
        Ok(request) => request,
        Err(error) => {
            let _ = send.write_all(&[ACK_REFUSED]).await;
            let _ = send.finish();
            return Err(error);
        }
    };
    if let Err(error) = validate_target(&request, allow_loopback_targets) {
        let _ = send.write_all(&[ACK_REFUSED]).await;
        let _ = send.finish();
        return Err(error.to_string());
    }
    // Only loopback targets survive validation above, so bind to that address.
    let address = format!("{}:{}", request.host, request.port);
    let mut target = match tokio::net::TcpStream::connect(&address).await {
        Ok(target) => target,
        Err(error) => {
            let _ = send.write_all(&[ACK_REFUSED]).await;
            let _ = send.finish();
            return Err(format!("service target {address}: {error}"));
        }
    };
    send.write_all(&[ACK_OK])
        .await
        .map_err(|error| format!("service ack: {error}"))?;
    let mut peer = tokio::io::join(recv, send);
    tokio::io::copy_bidirectional(&mut peer, &mut target)
        .await
        .map_err(|error| format!("service relay: {error}"))?;
    Ok(())
}

/// Read exactly one framed request off a QUIC receive stream.
#[cfg(feature = "iroh-sync")]
async fn read_request(recv: &mut iroh::endpoint::RecvStream) -> Result<ServiceRequest, String> {
    let mut prefix = [0u8; 4];
    recv.read_exact(&mut prefix)
        .await
        .map_err(|error| format!("service frame length: {error}"))?;
    let length = u32::from_be_bytes(prefix) as usize;
    if length == 0 || length > MAX_REQUEST_BYTES {
        return Err("service frame length out of bounds".into());
    }
    let mut body = vec![0u8; length];
    recv.read_exact(&mut body)
        .await
        .map_err(|error| format!("service frame body: {error}"))?;
    let mut frame = Vec::with_capacity(4 + length);
    frame.extend_from_slice(&prefix);
    frame.extend_from_slice(&body);
    decode_request(&frame)
        .map(|(request, _)| request)
        .map_err(|error| error.to_string())
}

/// Client side: dial a peer over iroh, send the target, verify the ack, and
/// hand back a duplex stream for relaying to the local SOCKS/HTTP client.
#[cfg(feature = "iroh-sync")]
pub async fn dial_service(
    endpoint: &iroh::Endpoint,
    target: &ProxyTarget,
) -> Result<impl tokio::io::AsyncRead + tokio::io::AsyncWrite, String> {
    let connection = endpoint
        .connect(target.peer.clone(), SERVICE_ALPN)
        .await
        .map_err(|error| format!("service dial: {error}"))?;
    let (mut send, mut recv) = connection
        .open_bi()
        .await
        .map_err(|error| format!("service open_bi: {error}"))?;
    let frame = encode_request(&target.request).map_err(|error| error.to_string())?;
    send.write_all(&frame)
        .await
        .map_err(|error| format!("service request: {error}"))?;
    let mut ack = [0u8; 1];
    recv.read_exact(&mut ack)
        .await
        .map_err(|error| format!("service ack: {error}"))?;
    if ack[0] != ACK_OK {
        return Err("service peer refused the target".into());
    }
    Ok(tokio::io::join(recv, send))
}

/// Start the proxy: bind the service endpoint, accept peer relay sessions, and
/// serve the local SOCKS5/HTTP listener. Returns once both loops are running;
/// callers keep the task alive.
#[cfg(feature = "iroh-sync")]
pub async fn start(
    home: PathBuf,
    config: ProxyConfig,
    resolver: Arc<dyn TargetResolver>,
) -> Result<(), String> {
    config.validate()?;
    if !config.enabled {
        return Err("proxy is not enabled in proxy.json".into());
    }
    let endpoint = bind_service_endpoint(&home, &config).await?;
    let allow_loopback = config.allow_loopback_targets;

    // Serving loop: accept peer relay sessions and bridge them to loopback.
    {
        let endpoint = endpoint.clone();
        tokio::spawn(async move {
            while let Some(incoming) = endpoint.accept().await {
                tokio::spawn(async move {
                    let Ok(connection) = incoming.await else {
                        return;
                    };
                    if let Err(error) = serve_connection(connection, allow_loopback).await {
                        eprintln!("myceliumd: service relay: {error}");
                    }
                });
            }
        });
    }

    let listen: SocketAddr = config
        .listen
        .parse()
        .map_err(|error| format!("proxy listen: {error}"))?;
    let listener = tokio::net::TcpListener::bind(listen)
        .await
        .map_err(|error| format!("proxy listener {listen}: {error}"))?;
    let endpoint = Arc::new(endpoint);
    tokio::spawn(async move {
        while let Ok((client, _)) = listener.accept().await {
            let resolver = resolver.clone();
            let endpoint = endpoint.clone();
            tokio::spawn(async move {
                if let Err(error) = handle_client(client, endpoint, resolver).await {
                    eprintln!("myceliumd: proxy client: {error}");
                }
            });
        }
    });
    eprintln!("myceliumd: service proxy listening on {listen}");
    Ok(())
}

#[cfg(feature = "iroh-sync")]
async fn handle_client(
    mut client: tokio::net::TcpStream,
    endpoint: Arc<iroh::Endpoint>,
    resolver: Arc<dyn TargetResolver>,
) -> Result<(), String> {
    let mut first = [0u8; 1];
    client
        .read_exact(&mut first)
        .await
        .map_err(|error| format!("proxy handshake: {error}"))?;
    let (host, port) = if first[0] == 0x05 {
        read_socks5_target(&mut client).await?
    } else {
        read_http_connect(&mut client, first[0]).await?
    };
    let target = resolver
        .resolve(&host, port)
        .await
        .ok_or_else(|| format!("no .myc target for {host}:{port}"))?;
    let mut peer = dial_service(&endpoint, &target).await?;
    tokio::io::copy_bidirectional(&mut client, &mut peer)
        .await
        .map_err(|error| format!("proxy relay: {error}"))?;
    Ok(())
}

/// Minimal SOCKS5 CONNECT (no authentication). Returns the requested host/port.
#[cfg(feature = "iroh-sync")]
async fn read_socks5_target(client: &mut tokio::net::TcpStream) -> Result<(String, u16), String> {
    // Greeting: version, nmethods, methods. We only advertise "no auth" (0x00).
    let mut header = [0u8; 2];
    client
        .read_exact(&mut header)
        .await
        .map_err(|error| format!("socks5 greeting: {error}"))?;
    let nmethods = header[1] as usize;
    let mut methods = vec![0u8; nmethods];
    client
        .read_exact(&mut methods)
        .await
        .map_err(|error| format!("socks5 methods: {error}"))?;
    if !methods.contains(&0x00) {
        let _ = client.write_all(&[0x05, 0xFF]).await;
        return Err("socks5 client offered no no-auth method".into());
    }
    client
        .write_all(&[0x05, 0x00])
        .await
        .map_err(|error| format!("socks5 method reply: {error}"))?;
    // Request: ver, cmd, rsv, atyp, addr, port.
    let mut request = [0u8; 4];
    client
        .read_exact(&mut request)
        .await
        .map_err(|error| format!("socks5 request: {error}"))?;
    if request[0] != 0x05 || request[1] != 0x01 {
        let _ = client
            .write_all(&[0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .await;
        return Err("socks5 only supports CONNECT".into());
    }
    let host = match request[3] {
        0x01 => {
            let mut octets = [0u8; 4];
            client
                .read_exact(&mut octets)
                .await
                .map_err(|error| format!("socks5 ipv4: {error}"))?;
            std::net::Ipv4Addr::from(octets).to_string()
        }
        0x03 => {
            let mut length = [0u8; 1];
            client
                .read_exact(&mut length)
                .await
                .map_err(|error| format!("socks5 domain length: {error}"))?;
            let mut name = vec![0u8; length[0] as usize];
            client
                .read_exact(&mut name)
                .await
                .map_err(|error| format!("socks5 domain: {error}"))?;
            String::from_utf8(name).map_err(|_| "socks5 domain is not utf-8".to_string())?
        }
        0x04 => {
            let mut octets = [0u8; 16];
            client
                .read_exact(&mut octets)
                .await
                .map_err(|error| format!("socks5 ipv6: {error}"))?;
            std::net::Ipv6Addr::from(octets).to_string()
        }
        _ => {
            let _ = client
                .write_all(&[0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await;
            return Err("socks5 unknown address type".into());
        }
    };
    let mut port = [0u8; 2];
    client
        .read_exact(&mut port)
        .await
        .map_err(|error| format!("socks5 port: {error}"))?;
    // Success reply: bind address 0.0.0.0:0. The connection is a relay, so the
    // bind address is meaningless and clients ignore it.
    client
        .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await
        .map_err(|error| format!("socks5 reply: {error}"))?;
    Ok((host, u16::from_be_bytes(port)))
}

/// Minimal HTTP CONNECT. The first byte was already read into `first`.
#[cfg(feature = "iroh-sync")]
async fn read_http_connect(
    client: &mut tokio::net::TcpStream,
    first: u8,
) -> Result<(String, u16), String> {
    let mut buffer = vec![first];
    let mut chunk = [0u8; 1024];
    while !buffer.windows(4).any(|window| window == b"\r\n\r\n") && buffer.len() < 8192 {
        let read = client
            .read(&mut chunk)
            .await
            .map_err(|error| format!("http connect: {error}"))?;
        if read == 0 {
            break;
        }
        buffer.extend_from_slice(&chunk[..read]);
    }
    let text = String::from_utf8_lossy(&buffer);
    let request_line = text.lines().next().unwrap_or_default();
    let mut parts = request_line.split_whitespace();
    if parts.next() != Some("CONNECT") {
        let _ = client
            .write_all(b"HTTP/1.1 405 Method Not Allowed\r\n\r\n")
            .await;
        return Err("proxy only supports HTTP CONNECT".into());
    }
    let authority = parts.next().ok_or("http connect has no authority")?;
    let (host, port) = authority
        .rsplit_once(':')
        .ok_or("http connect authority has no port")?;
    let port = port
        .parse::<u16>()
        .map_err(|_| "http connect authority has an invalid port".to_string())?;
    client
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await
        .map_err(|error| format!("http connect reply: {error}"))?;
    Ok((host.to_string(), port))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::service::ServiceError;

    #[test]
    fn config_defaults_to_disabled_and_loopback() {
        let config = ProxyConfig::default();
        assert!(!config.enabled);
        assert!(!config.allow_loopback_targets);
        assert!(config.validate().is_ok());
    }

    #[test]
    fn non_loopback_listeners_are_refused() {
        let config = ProxyConfig {
            enabled: true,
            listen: "0.0.0.0:1080".into(),
            ..ProxyConfig::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn absent_config_is_disabled_but_malformed_is_an_error() {
        let home = std::env::temp_dir().join(format!(
            "mycelium-proxy-config-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&home).unwrap();
        assert_eq!(load_config(&home).unwrap(), ProxyConfig::default());
        std::fs::write(home.join("proxy.json"), b"{ not json").unwrap();
        assert!(load_config(&home).is_err());
        std::fs::write(
            home.join("proxy.json"),
            br#"{"enabled":true,"listen":"127.0.0.1:1080","allow_loopback_targets":true}"#,
        )
        .unwrap();
        let config = load_config(&home).unwrap();
        assert!(config.enabled);
        assert!(config.allow_loopback_targets);
    }

    #[test]
    fn service_error_display_is_stable() {
        assert_eq!(
            ServiceError::Malformed.to_string(),
            "malformed service request"
        );
    }
}
