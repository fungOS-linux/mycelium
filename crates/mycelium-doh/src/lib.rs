//! DNS-over-HTTPS forwarding for the local resolver.
//!
//! dnsmasq cannot speak DoH, so it points its default upstream here and this
//! forwarder owns the encrypted hop. Every failure path answers SERVFAIL:
//! there is no plaintext retry, because a resolver that silently falls back
//! is worse than one that reports it cannot answer.
//!
//! Messages are relayed byte for byte (RFC 8484 `application/dns-message`),
//! so this never parses a DNS answer. The only structure it reads is the
//! header and the question section, and only to build a well-formed SERVFAIL
//! and to reject a response whose ID does not match the query.
use async_trait::async_trait;
use mycelium_dns_policy::resolver::DohUpstream;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::Semaphore;

/// Largest DNS message either side may carry.
pub const MAX_MESSAGE: usize = 65_535;
/// Standard EDNS-capable UDP receive size; larger replies arrive over TCP.
const UDP_BUFFER: usize = 4_096;

/// One HTTPS POST of a DNS message. The trait exists so the relay logic can
/// be tested without a live endpoint.
#[async_trait]
pub trait Transport: Send + Sync {
    async fn post(&self, query: &[u8]) -> Result<Vec<u8>, String>;
}

/// The real hop: a verified TLS POST to the configured endpoint. Redirects
/// are refused, since following one could downgrade the scheme.
pub struct Https {
    client: reqwest::Client,
    endpoint: String,
}

impl Https {
    pub fn new(upstream: &DohUpstream) -> Result<Self, String> {
        upstream.validate()?;
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(u64::from(upstream.timeout_seconds)))
            .build()
            .map_err(|error| format!("build DoH client: {error}"))?;
        Ok(Self {
            client,
            endpoint: upstream.endpoint.clone(),
        })
    }
}

#[async_trait]
impl Transport for Https {
    async fn post(&self, query: &[u8]) -> Result<Vec<u8>, String> {
        let response = self
            .client
            .post(&self.endpoint)
            .header("content-type", "application/dns-message")
            .header("accept", "application/dns-message")
            .body(query.to_vec())
            .send()
            .await
            .map_err(|error| format!("DoH request failed: {error}"))?;
        if !response.status().is_success() {
            return Err(format!("DoH endpoint answered {}", response.status()));
        }
        if response
            .content_length()
            .is_some_and(|length| length > MAX_MESSAGE as u64)
        {
            return Err("DoH response exceeds one DNS message".into());
        }
        let body = response
            .bytes()
            .await
            .map_err(|error| format!("read DoH response: {error}"))?;
        if body.len() > MAX_MESSAGE {
            return Err("DoH response exceeds one DNS message".into());
        }
        Ok(body.to_vec())
    }
}

/// Relay one query, or answer SERVFAIL. A response carrying another ID is
/// not an answer to this question and never reaches the client.
pub async fn exchange(transport: &dyn Transport, query: &[u8]) -> Vec<u8> {
    let servfail = || servfail(query).unwrap_or_default();
    if query.len() < 12 {
        return servfail();
    }
    match transport.post(query).await {
        Ok(response)
            if response.len() >= 12
                && response.len() <= MAX_MESSAGE
                && response[..2] == query[..2] =>
        {
            response
        }
        Ok(_) => servfail(),
        Err(error) => {
            eprintln!("DoH forward failed: {error}");
            servfail()
        }
    }
}

/// A SERVFAIL that echoes the ID and question, or `None` for a truncated
/// query that cannot be answered at all.
pub fn servfail(query: &[u8]) -> Option<Vec<u8>> {
    if query.len() < 12 {
        return None;
    }
    let questions = u16::from_be_bytes([query[4], query[5]]);
    let mut end = 12;
    for _ in 0..questions {
        end = skip_name(query, end)?;
        end = end.checked_add(4)?; // type and class
        if end > query.len() {
            return None;
        }
    }
    let mut response = query[..end].to_vec();
    // QR=1, RD copied from the query, RA=0: this server does not offer
    // recursion, it either forwards or reports failure.
    response[2] = 0x80 | (query[2] & 0x01);
    response[3] = 2; // RCODE SERVFAIL
    response[4..6].copy_from_slice(&questions.to_be_bytes());
    response[6..12].fill(0);
    Some(response)
}

/// Skip one (possibly compressed) name, returning the offset after it.
fn skip_name(message: &[u8], mut offset: usize) -> Option<usize> {
    loop {
        let length = *message.get(offset)?;
        if length == 0 {
            return Some(offset + 1);
        }
        if length & 0xc0 == 0xc0 {
            return (offset + 2 <= message.len()).then_some(offset + 2);
        }
        offset = offset.checked_add(1 + usize::from(length))?;
        if offset > message.len() {
            return None;
        }
    }
}

/// A forwarder whose sockets are already bound, so the caller can publish the
/// listener before dnsmasq starts asking.
pub struct Forwarder {
    udp: UdpSocket,
    tcp: TcpListener,
    transport: Arc<dyn Transport>,
    limit: Arc<Semaphore>,
    timeout: Duration,
}

impl Forwarder {
    pub async fn bind(upstream: &DohUpstream) -> Result<Self, String> {
        upstream.validate()?;
        let transport: Arc<dyn Transport> = Arc::new(Https::new(upstream)?);
        Self::with_transport(
            upstream.listen,
            transport,
            Duration::from_secs(u64::from(upstream.timeout_seconds)),
            usize::from(upstream.max_inflight),
        )
        .await
    }

    /// Bind with a caller-supplied transport. The relay loop is the part worth
    /// testing over a real socket, and it does not care where the encrypted
    /// hop goes.
    pub async fn with_transport(
        listen: SocketAddr,
        transport: Arc<dyn Transport>,
        timeout: Duration,
        max_inflight: usize,
    ) -> Result<Self, String> {
        Ok(Self {
            udp: UdpSocket::bind(listen)
                .await
                .map_err(|error| format!("bind DoH forwarder UDP: {error}"))?,
            tcp: TcpListener::bind(listen)
                .await
                .map_err(|error| format!("bind DoH forwarder TCP: {error}"))?,
            transport,
            limit: Arc::new(Semaphore::new(max_inflight.max(1))),
            timeout,
        })
    }

    pub fn udp_addr(&self) -> Result<SocketAddr, String> {
        self.udp
            .local_addr()
            .map_err(|error| format!("read DoH forwarder address: {error}"))
    }

    pub fn tcp_addr(&self) -> Result<SocketAddr, String> {
        self.tcp
            .local_addr()
            .map_err(|error| format!("read DoH forwarder address: {error}"))
    }

    pub async fn serve(self) -> Result<(), String> {
        let Forwarder {
            udp,
            tcp,
            transport,
            limit,
            timeout,
        } = self;
        tokio::try_join!(
            udp_loop(Arc::new(udp), transport.clone(), limit.clone(), timeout),
            tcp_loop(tcp, transport, limit, timeout)
        )?;
        Ok(())
    }
}

/// Overload answers SERVFAIL immediately rather than queueing: a client that
/// waits learns less than one that is told to retry elsewhere.
async fn udp_loop(
    socket: Arc<UdpSocket>,
    transport: Arc<dyn Transport>,
    limit: Arc<Semaphore>,
    timeout: Duration,
) -> Result<(), String> {
    let mut buffer = vec![0u8; UDP_BUFFER];
    loop {
        let (length, peer) = socket
            .recv_from(&mut buffer)
            .await
            .map_err(|error| format!("DoH forwarder UDP receive: {error}"))?;
        let query = buffer[..length].to_vec();
        let Ok(permit) = limit.clone().try_acquire_owned() else {
            let _ = socket
                .send_to(&servfail(&query).unwrap_or_default(), peer)
                .await;
            continue;
        };
        let socket = socket.clone();
        let transport = transport.clone();
        tokio::spawn(async move {
            let reply = match tokio::time::timeout(timeout, exchange(&*transport, &query)).await {
                Ok(reply) => reply,
                Err(_) => servfail(&query).unwrap_or_default(),
            };
            let _ = socket.send_to(&reply, peer).await;
            drop(permit);
        });
    }
}

async fn tcp_loop(
    listener: TcpListener,
    transport: Arc<dyn Transport>,
    limit: Arc<Semaphore>,
    timeout: Duration,
) -> Result<(), String> {
    loop {
        let (stream, _) = listener
            .accept()
            .await
            .map_err(|error| format!("DoH forwarder TCP accept: {error}"))?;
        let transport = transport.clone();
        let limit = limit.clone();
        tokio::spawn(async move {
            if let Err(error) = serve_tcp(stream, transport, limit, timeout).await {
                eprintln!("DoH forwarder TCP connection closed: {error}");
            }
        });
    }
}

/// RFC 1035 TCP framing: a two-byte length before every message.
async fn serve_tcp(
    mut stream: TcpStream,
    transport: Arc<dyn Transport>,
    limit: Arc<Semaphore>,
    timeout: Duration,
) -> Result<(), String> {
    loop {
        let mut prefix = [0u8; 2];
        match stream.read_exact(&mut prefix).await {
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(error) => return Err(error.to_string()),
        }
        let length = usize::from(u16::from_be_bytes(prefix));
        if length < 12 {
            return Err("DNS message shorter than a header".into());
        }
        let mut query = vec![0u8; length];
        stream
            .read_exact(&mut query)
            .await
            .map_err(|error| format!("read DNS query: {error}"))?;
        let reply = match limit.clone().try_acquire_owned() {
            Ok(permit) => {
                let reply = match tokio::time::timeout(timeout, exchange(&*transport, &query)).await
                {
                    Ok(reply) => reply,
                    Err(_) => servfail(&query).unwrap_or_default(),
                };
                drop(permit);
                reply
            }
            Err(_) => servfail(&query).unwrap_or_default(),
        };
        let mut framed = Vec::with_capacity(reply.len() + 2);
        framed.extend(u16::try_from(reply.len()).unwrap_or(0).to_be_bytes());
        framed.extend(reply);
        stream
            .write_all(&framed)
            .await
            .map_err(|error| format!("write DNS answer: {error}"))?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn upstream() -> DohUpstream {
        DohUpstream {
            endpoint: "https://dns.example/dns-query".into(),
            listen: "127.0.0.1:5353".parse().unwrap(),
            timeout_seconds: 5,
            max_inflight: 8,
        }
    }

    fn query() -> Vec<u8> {
        let mut query = vec![0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
        query.extend(b"\x03www\x07example\x03com\x00");
        query.extend([0x00, 0x01, 0x00, 0x01]);
        query
    }

    struct Fixed(Result<Vec<u8>, String>);

    #[async_trait]
    impl Transport for Fixed {
        async fn post(&self, _query: &[u8]) -> Result<Vec<u8>, String> {
            self.0.clone()
        }
    }

    #[test]
    fn servfail_echoes_the_id_and_question() {
        let query = query();
        let response = servfail(&query).unwrap();
        assert_eq!(&response[..2], &[0x12, 0x34]);
        assert_eq!(response[2], 0x81); // QR set, RD copied
        assert_eq!(response[3], 2); // SERVFAIL
        assert_eq!(&response[4..6], &[0, 1]); // one question preserved
        assert_eq!(&response[6..12], &[0, 0, 0, 0, 0, 0]);
        assert_eq!(&response[12..], &query[12..]);
    }

    #[test]
    fn servfail_refuses_queries_it_cannot_frame() {
        assert!(servfail(&[]).is_none());
        assert!(servfail(&[0u8; 11]).is_none());
        // A header claiming one question that is not there cannot be echoed.
        assert!(servfail(b"\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00").is_none());
        // No question at all is a legal message and still gets an answer.
        assert!(servfail(&[0u8; 12]).is_some());
        // Truncated label length.
        assert!(servfail(b"\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x3fwww").is_none());
    }

    #[tokio::test]
    async fn exchange_relays_only_a_matching_answer() {
        let query = query();
        let mut answered = query.clone();
        answered[2] = 0x81;
        answered[3] = 0;
        assert_eq!(
            exchange(&Fixed(Ok(answered.clone())), &query).await,
            answered
        );
        // Another query's answer is not an answer to this one.
        let mut stranger = answered.clone();
        stranger[0] = 0x99;
        assert_eq!(
            exchange(&Fixed(Ok(stranger)), &query).await,
            servfail(&query).unwrap()
        );
        // Errors and oversized bodies fail closed.
        assert_eq!(
            exchange(&Fixed(Err("tls".into())), &query).await,
            servfail(&query).unwrap()
        );
        assert_eq!(
            exchange(&Fixed(Ok(vec![0u8; MAX_MESSAGE + 1])), &query).await,
            servfail(&query).unwrap()
        );
    }

    #[tokio::test]
    async fn answers_over_a_real_udp_socket_and_relays_the_reply() {
        let query = query();
        let mut answer = query.clone();
        answer[2] = 0x81;
        answer[3] = 0;
        let transport: Arc<dyn Transport> = Arc::new(Fixed(Ok(answer.clone())));
        let forwarder = Forwarder::with_transport(
            "127.0.0.1:0".parse().unwrap(),
            transport,
            Duration::from_secs(2),
            4,
        )
        .await
        .unwrap();
        let address = forwarder.udp_addr().unwrap();
        tokio::spawn(async move { forwarder.serve().await });
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client.send_to(&query, address).await.unwrap();
        let mut buffer = vec![0u8; UDP_BUFFER];
        let (length, _) =
            tokio::time::timeout(Duration::from_secs(5), client.recv_from(&mut buffer))
                .await
                .unwrap()
                .unwrap();
        assert_eq!(&buffer[..length], &answer[..]);
    }

    #[tokio::test]
    async fn a_failing_transport_answers_servfail_over_the_socket() {
        let query = query();
        let transport: Arc<dyn Transport> = Arc::new(Fixed(Err("no route".into())));
        let forwarder = Forwarder::with_transport(
            "127.0.0.1:0".parse().unwrap(),
            transport,
            Duration::from_secs(2),
            4,
        )
        .await
        .unwrap();
        let address = forwarder.udp_addr().unwrap();
        tokio::spawn(async move { forwarder.serve().await });
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client.send_to(&query, address).await.unwrap();
        let mut buffer = vec![0u8; UDP_BUFFER];
        let (length, _) =
            tokio::time::timeout(Duration::from_secs(5), client.recv_from(&mut buffer))
                .await
                .unwrap()
                .unwrap();
        assert_eq!(&buffer[..length], &servfail(&query).unwrap()[..]);
    }

    /// Live check of the encrypted hop: `cargo test -p mycelium-doh -- --ignored`.
    #[tokio::test]
    #[ignore = "network: exercises the real TLS hop"]
    async fn forwards_to_a_real_endpoint() {
        let upstream = DohUpstream {
            endpoint: "https://cloudflare-dns.com/dns-query".into(),
            listen: "127.0.0.1:5353".parse().unwrap(),
            timeout_seconds: 5,
            max_inflight: 8,
        };
        let answer = exchange(&Https::new(&upstream).unwrap(), &query()).await;
        assert_eq!(&answer[..2], &[0x12, 0x34], "the id must come back");
        assert_eq!(
            answer[3] & 0x0f,
            0,
            "expected NOERROR, got {}",
            answer[3] & 0x0f
        );
    }

    #[test]
    fn doh_upstream_rejects_plaintext_and_public_listeners() {
        assert!(upstream().validate().is_ok());
        for endpoint in ["http://dns.example/dns-query", "dns.example", "https://"] {
            let mut bad = upstream();
            bad.endpoint = endpoint.into();
            assert!(bad.validate().is_err(), "{endpoint}");
        }
        for listen in ["0.0.0.0:5353", "[::]:5353", "127.0.0.1:0"] {
            let mut bad = upstream();
            bad.listen = listen.parse::<SocketAddr>().unwrap();
            assert!(bad.validate().is_err(), "{listen}");
        }
        let mut bad = upstream();
        bad.timeout_seconds = 0;
        assert!(bad.validate().is_err());
        bad.timeout_seconds = 5;
        bad.max_inflight = 0;
        assert!(bad.validate().is_err());
    }
}
