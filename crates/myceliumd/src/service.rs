//! The framed service protocol carried over the `mycelium/service/1` ALPN.
//!
//! This is deliberately not the gossip/sync protocol. Sync carries the records
//! feed; this carries one opaque byte stream toward a service a peer chose to
//! expose. The framing is a small length-prefixed JSON request followed by a
//! single ack byte, after which both sides relay raw bytes.
//!
//! Security posture:
//! - The service listener on the *serving* peer only ever dials loopback
//!   targets, and only when configuration explicitly permits it. Anything else
//!   fails closed; there is no implicit "connect anywhere" mode.
//! - Iroh endpoint keys identify transports, never users. Reaching this ALPN is
//!   not an access grant; a peer still has to run the service listener and the
//!   payload is still the service's own authentication problem.
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// ALPN for one service relay stream. Distinct from `mycelium/sync/1`.
pub const SERVICE_ALPN: &[u8] = b"mycelium/service/1";

/// Upper bound on the framed request. The request is a tiny target tuple; a
/// larger frame is a protocol error, not a longer hostname.
pub const MAX_REQUEST_BYTES: usize = 512;

/// Ack byte the serving peer sends once it has dialed the target.
pub const ACK_OK: u8 = 0;
pub const ACK_REFUSED: u8 = 1;

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ServiceRequest {
    pub host: String,
    pub port: u16,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ServiceError {
    /// The frame was malformed or exceeded `MAX_REQUEST_BYTES`.
    Malformed,
    /// The requested target is not an allowed loopback endpoint.
    ForbiddenTarget(String),
}

impl std::fmt::Display for ServiceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ServiceError::Malformed => write!(f, "malformed service request"),
            ServiceError::ForbiddenTarget(reason) => {
                write!(f, "forbidden service target: {reason}")
            }
        }
    }
}

impl std::error::Error for ServiceError {}

/// A target is allowed only when it names a loopback address (or `localhost`)
/// and the operator opted in via `allow_loopback_targets`. There is no fallback
/// to a remote host: the relay exists to reach services the peer itself hosts.
pub fn validate_target(
    request: &ServiceRequest,
    allow_loopback_targets: bool,
) -> Result<(), ServiceError> {
    if request.port == 0 {
        return Err(ServiceError::ForbiddenTarget("port 0".into()));
    }
    if !allow_loopback_targets {
        return Err(ServiceError::ForbiddenTarget(
            "loopback targets are not enabled".into(),
        ));
    }
    let host = request.host.trim();
    let is_loopback = match host.parse::<IpAddr>() {
        Ok(IpAddr::V4(address)) => address == Ipv4Addr::LOCALHOST,
        Ok(IpAddr::V6(address)) => address == Ipv6Addr::LOCALHOST,
        Err(_) => host.eq_ignore_ascii_case("localhost"),
    };
    if !is_loopback {
        return Err(ServiceError::ForbiddenTarget(
            "target must be a loopback address".into(),
        ));
    }
    Ok(())
}

/// Encode a request as `[len: u32 BE][json]`.
pub fn encode_request(request: &ServiceRequest) -> Result<Vec<u8>, ServiceError> {
    let json = serde_json::to_vec(request).map_err(|_| ServiceError::Malformed)?;
    if json.len() > MAX_REQUEST_BYTES {
        return Err(ServiceError::Malformed);
    }
    let mut out = Vec::with_capacity(4 + json.len());
    out.extend_from_slice(&(json.len() as u32).to_be_bytes());
    out.extend_from_slice(&json);
    Ok(out)
}

/// Read a length-prefixed JSON request from a byte slice, returning the request
/// and the number of bytes consumed. Rejects oversized frames without allocating.
pub fn decode_request(bytes: &[u8]) -> Result<(ServiceRequest, usize), ServiceError> {
    if bytes.len() < 4 {
        return Err(ServiceError::Malformed);
    }
    let length = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
    if length == 0 || length > MAX_REQUEST_BYTES {
        return Err(ServiceError::Malformed);
    }
    let end = 4 + length;
    if bytes.len() < end {
        return Err(ServiceError::Malformed);
    }
    let request: ServiceRequest =
        serde_json::from_slice(&bytes[4..end]).map_err(|_| ServiceError::Malformed)?;
    Ok((request, end))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(host: &str, port: u16) -> ServiceRequest {
        ServiceRequest {
            host: host.into(),
            port,
        }
    }

    #[test]
    fn round_trips_a_loopback_request() {
        let request = request("127.0.0.1", 9000);
        let encoded = encode_request(&request).unwrap();
        let (decoded, consumed) = decode_request(&encoded).unwrap();
        assert_eq!(decoded, request);
        assert_eq!(consumed, encoded.len());
    }

    #[test]
    fn rejects_non_loopback_and_zero_port_targets() {
        assert!(validate_target(&request("127.0.0.1", 9000), true).is_ok());
        assert!(validate_target(&request("localhost", 9000), true).is_ok());
        assert!(validate_target(&request("::1", 9000), true).is_ok());
        assert!(validate_target(&request("10.0.0.1", 9000), true).is_err());
        assert!(validate_target(&request("127.0.0.1", 0), true).is_err());
        // Fails closed when the operator has not opted in, even for loopback.
        assert!(validate_target(&request("127.0.0.1", 9000), false).is_err());
    }

    #[test]
    fn rejects_malformed_frames() {
        assert!(decode_request(&[]).is_err());
        assert!(decode_request(&[0, 0, 0, 0]).is_err());
        // Declared length longer than the buffer.
        assert!(decode_request(&[0, 0, 0, 9, b'{']).is_err());
        // Declared length above the bound.
        let oversized = ((MAX_REQUEST_BYTES as u32) + 1).to_be_bytes();
        assert!(decode_request(&oversized).is_err());
        // Valid length but not JSON.
        assert!(decode_request(&[0, 0, 0, 1, b'x']).is_err());
    }
}
