//! Key-pinned, short-lived enrollment transport. Authorization remains in
//! the existing invite store/redemption handler, never in Iroh discovery.
use myceliumd::iroh_transport::{Endpoint, EndpointAddr, RelayMode};
use myceliumd::peer::{SyncConfig, SyncRendezvous};
use serde::{Deserialize, Serialize};
use std::{
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

const ALPN: &[u8] = b"mycelium/pair/1";
const MAX_FRAME: usize = 128 * 1024;
const DEADLINE: Duration = Duration::from_secs(30);
const PREFIX: &str = "iroh-pair:";

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Rendezvous {
    address: EndpointAddr,
    expires_at: u64,
    public_relays: bool,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Reply {
    response: Option<crate::invite::RedeemResponse>,
    sync: Option<SyncRendezvous>,
    error: Option<String>,
}

fn decode(value: &str) -> Result<Rendezvous, String> {
    let encoded = value
        .strip_prefix(PREFIX)
        .ok_or("not an Iroh pairing endpoint")?;
    if encoded.len() > 2048 || encoded.len() % 2 != 0 || !encoded.is_ascii() {
        return Err("invalid Iroh pairing endpoint encoding".into());
    }
    let bytes = (0..encoded.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&encoded[i..i + 2], 16))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| "invalid Iroh pairing endpoint encoding")?;
    let result: Rendezvous = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
    if result.expires_at <= crate::invite::now()? {
        return Err("Iroh pairing claim expired".into());
    }
    if result.address.addrs.is_empty() || result.address.addrs.len() > 5 {
        return Err("Iroh pairing needs at most five explicit address hints".into());
    }
    Ok(result)
}

async fn endpoint(public_relays: bool) -> Result<Endpoint, String> {
    let builder = Endpoint::builder(myceliumd::iroh_transport::endpoint::presets::N0)
        .clear_address_lookup()
        .portmapper_config(myceliumd::iroh_transport::endpoint::PortmapperConfig::Disabled)
        .transport_config(
            myceliumd::iroh_transport::endpoint::QuicTransportConfig::builder()
                .max_concurrent_bidi_streams(1u8.into())
                .max_concurrent_uni_streams(0u8.into())
                .build(),
        )
        .alpns(vec![ALPN.to_vec()]);
    let builder = if public_relays {
        builder
    } else {
        builder.relay_mode(RelayMode::Disabled)
    };
    builder.bind().await.map_err(|e| e.to_string())
}

async fn read_frame<R: AsyncRead + Unpin, T: serde::de::DeserializeOwned>(
    reader: &mut R,
) -> Result<T, String> {
    let size = reader.read_u32().await.map_err(|e| e.to_string())? as usize;
    if size == 0 || size > MAX_FRAME {
        return Err("pairing frame exceeds bound".into());
    }
    let mut bytes = vec![0; size];
    reader
        .read_exact(&mut bytes)
        .await
        .map_err(|e| e.to_string())?;
    serde_json::from_slice(&bytes).map_err(|e| e.to_string())
}

async fn write_frame<W: AsyncWrite + Unpin, T: Serialize>(
    writer: &mut W,
    value: &T,
) -> Result<(), String> {
    let bytes = serde_json::to_vec(value).map_err(|e| e.to_string())?;
    if bytes.is_empty() || bytes.len() > MAX_FRAME {
        return Err("pairing frame exceeds bound".into());
    }
    writer
        .write_u32(bytes.len() as u32)
        .await
        .map_err(|e| e.to_string())?;
    writer.write_all(&bytes).await.map_err(|e| e.to_string())?;
    writer.flush().await.map_err(|e| e.to_string())
}

pub(crate) fn fresh_sync() -> Result<SyncRendezvous, String> {
    fresh_sync_from(&myceliumd::home_dir().join("iroh-rendezvous.json"))
}

fn fresh_sync_from(path: &Path) -> Result<SyncRendezvous, String> {
    use std::io::Read;
    let mut bytes = Vec::new();
    std::fs::File::open(path)
        .map_err(|_| "enable Iroh sync on the authority peer before pairing")?
        .take(65537)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() > 65536 {
        return Err("sync rendezvous exceeds bound".into());
    }
    let sync: SyncRendezvous = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
    sync.validate(Some(crate::invite::now()?))?;
    Ok(sync)
}

pub(crate) async fn serve(
    ca: PathBuf,
    enrollment_ca: PathBuf,
    store: PathBuf,
    created: crate::invite::CreatedInvitation,
    name: &str,
    public_relays: bool,
    qr: bool,
) -> Result<(), String> {
    fresh_sync()?;
    let endpoint = endpoint(public_relays).await?;
    // Allow direct address collection to settle; public relays may need longer.
    let address = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let address = endpoint.addr();
            if (!public_relays && address.ip_addrs().next().is_some())
                || (public_relays && address.relay_urls().next().is_some())
            {
                break address;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .map_err(|_| "pairing endpoint address discovery timed out")?;
    let mut bounded = EndpointAddr::new(address.id);
    for ip in address.ip_addrs().take(4) {
        bounded = bounded.with_ip_addr(*ip);
    }
    for relay in address.relay_urls().take(1) {
        bounded = bounded.with_relay_url(relay.clone());
    }
    let rendezvous = Rendezvous {
        address: bounded,
        expires_at: created.expires_at,
        public_relays,
    };
    let encoded = mycelium_peer_protocol::encode_hex(
        &serde_json::to_vec(&rendezvous).map_err(|e| e.to_string())?,
    );
    let claim = crate::invite::encode_pair_claim(
        &format!("{PREFIX}{encoded}"),
        &created.code,
        name,
        crate::invite::InvitationKind::Peer,
    )?;
    // Validate before displaying a claim the client cannot decode.
    crate::invite::decode_pair_claim(&claim)?;
    if qr {
        let code = qrcode::QrCode::new(claim.as_bytes()).map_err(|e| format!("pairing QR: {e}"))?;
        println!(
            "{}",
            code.render::<qrcode::render::unicode::Dense1x2>().build()
        );
    }
    println!("Pairing claim (secret; share privately): {claim}");
    println!(
        "Expires: {}; waiting for one redemption over Iroh",
        created.expires_at
    );
    let state = crate::oidc_gateway::pairing_state(ca, enrollment_ca, store.clone());
    serve_endpoint(
        endpoint,
        state,
        store,
        created.id,
        created.expires_at,
        myceliumd::home_dir().join("iroh-rendezvous.json"),
    )
    .await
}

async fn serve_endpoint(
    endpoint: Endpoint,
    state: crate::oidc_gateway::GatewayState,
    store: PathBuf,
    invitation_id: String,
    expires_at: u64,
    sync_path: PathBuf,
) -> Result<(), String> {
    let permits = Arc::new(tokio::sync::Semaphore::new(4));
    let mut jobs = tokio::task::JoinSet::new();
    let mut tick = tokio::time::interval(Duration::from_millis(250));
    let result = loop {
        tokio::select! {
            incoming = endpoint.accept() => {
                let Some(incoming) = incoming else { break Err("pairing endpoint closed".into()); };
                if jobs.len() >= 4 { incoming.refuse(); continue; }
                let Ok(permit) = permits.clone().try_acquire_owned() else { incoming.refuse(); continue; };
                let state = state.clone();
                let sync_path = sync_path.clone();
                jobs.spawn(async move {
                    let _permit = permit;
                    tokio::time::timeout(DEADLINE, async {
                        let connection = incoming.await.map_err(|e| e.to_string())?;
                        let (mut send, mut recv) = connection.accept_bi().await.map_err(|e| e.to_string())?;
                        let request = read_frame(&mut recv).await?;
                        let sync = fresh_sync_from(&sync_path)?;
                        let reply = match crate::oidc_gateway::redeem_pair_request(state, request).await {
                            Ok(response) => Reply { response: Some(response), sync: Some(sync), error: None },
                            Err(error) => Reply { response: None, sync: None, error: Some(error) },
                        };
                        write_frame(&mut send, &reply).await?;
                        let ack: String = read_frame(&mut recv).await?;
                        if ack != "received" { return Err("invalid pairing acknowledgement".into()); }
                        send.finish().map_err(|e| e.to_string())?;
                        send.stopped().await.map_err(|e| e.to_string())?;
                        Ok::<_, String>(reply.error.is_none())
                    }).await.map_err(|_| "pairing exchange timed out".to_owned())?
                });
            }
            result = jobs.join_next(), if !jobs.is_empty() => {
                match result {
                    Some(Ok(Ok(true))) if crate::oidc_gateway::pairing_finished(&store, &invitation_id, expires_at)? => break Ok(()),
                    Some(Ok(Err(_))) | Some(Err(_)) => eprintln!("mycelium: Iroh pairing exchange failed; check claim and retry before expiry"),
                    _ => {}
                }
            }
            _ = tick.tick() => {
                if crate::invite::now()? >= expires_at { break Err("pairing claim expired before acknowledged redemption".into()); }
            }
        }
    };
    jobs.abort_all();
    endpoint.close().await;
    result
}

pub(crate) async fn redeem(
    gateway: &str,
    request: crate::invite::RedeemRequest,
) -> Result<(crate::invite::RedeemResponse, SyncRendezvous, bool), String> {
    let rendezvous = decode(gateway)?;
    let endpoint = endpoint(rendezvous.public_relays).await?;
    let result = tokio::time::timeout(DEADLINE, async {
        let connection = endpoint
            .connect(rendezvous.address, ALPN)
            .await
            .map_err(|e| e.to_string())?;
        let (mut send, mut recv) = connection.open_bi().await.map_err(|e| e.to_string())?;
        write_frame(&mut send, &request).await?;
        let reply: Reply = read_frame(&mut recv).await?;
        write_frame(&mut send, &"received").await?;
        // Wait for the authority to read the ACK before dropping the QUIC connection.
        send.finish().map_err(|e| e.to_string())?;
        let _ = recv.read_to_end(1).await.map_err(|e| e.to_string())?;
        let _ = connection.closed().await;
        if let Some(error) = reply.error {
            return Err(error);
        }
        let response = reply
            .response
            .ok_or("pairing response is missing credentials")?;
        if response.peer.is_none() {
            return Err("Iroh pairing expected peer credentials".into());
        }
        let sync = reply
            .sync
            .ok_or("pairing response is missing persistent sync endpoint")?;
        sync.validate(Some(crate::invite::now()?))?;
        Ok((response, sync, rendezvous.public_relays))
    })
    .await
    .map_err(|_| "Iroh claim redemption timed out".to_owned());
    endpoint.close().await;
    result?
}

pub(crate) fn install_seed(
    home: &Path,
    seed: SyncRendezvous,
    public_relays: bool,
) -> Result<(), String> {
    let config = SyncConfig {
        public_relays,
        seeds: vec![seed],
        pkarr: Default::default(),
    };
    config.validate()?;
    std::fs::create_dir_all(home).map_err(|e| e.to_string())?;
    // Enrollment must not silently replace an existing peer's sync configuration.
    use std::io::Write;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(home.join("iroh-sync.json"))
        .map_err(|e| e.to_string())?;
    file.write_all(&serde_json::to_vec(&config).map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())?;
    file.sync_all().map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encode(address: EndpointAddr, expires_at: u64) -> String {
        format!(
            "{PREFIX}{}",
            mycelium_peer_protocol::encode_hex(
                &serde_json::to_vec(&Rendezvous {
                    address,
                    expires_at,
                    public_relays: false
                })
                .unwrap()
            )
        )
    }

    #[test]
    fn rendezvous_is_bounded_expiring_and_qr_encodable() {
        let address = EndpointAddr::new(myceliumd::iroh_transport::SecretKey::generate().public())
            .with_ip_addr("127.0.0.1:23456".parse().unwrap());
        let endpoint = encode(address.clone(), crate::invite::now().unwrap() + 900);
        assert!(decode(&endpoint).is_ok());
        assert!(decode(&encode(address, 1)).is_err());
        assert!(decode(&format!("{PREFIX}{}", "a".repeat(2049))).is_err());
        let claim = crate::invite::encode_pair_claim(
            &endpoint,
            "MYC-TEST-SECRET",
            "new-peer",
            crate::invite::InvitationKind::Peer,
        )
        .unwrap();
        crate::invite::decode_pair_claim(&claim).unwrap().unwrap();
        qrcode::QrCode::new(claim.as_bytes()).unwrap();
    }

    #[tokio::test]
    async fn frames_reject_sizes_before_allocating() {
        let size = (MAX_FRAME as u32 + 1).to_be_bytes();
        assert!(read_frame::<_, Reply>(&mut &size[..]).await.is_err());
        let (mut write, mut read) = tokio::io::duplex(128);
        write_frame(&mut write, &"roundtrip").await.unwrap();
        assert_eq!(
            read_frame::<_, String>(&mut read).await.unwrap(),
            "roundtrip"
        );
    }

    #[tokio::test]
    async fn new_peer_redemption_over_iroh_consumes_once_and_installs_sync_seed() {
        let root = std::env::temp_dir().join(format!(
            "mycelium-iroh-enroll-{}",
            myceliumd::iroh_transport::SecretKey::generate().public()
        ));
        std::fs::create_dir(&root).unwrap();
        let ca = root.join("ca");
        crate::enroll::init(&ca).unwrap();
        let key = root.join("new.key");
        let csr = root.join("new.csr");
        let run = |args: &[&str]| {
            let output = std::process::Command::new("openssl")
                .args(args)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
        };
        run(&[
            "genpkey",
            "-algorithm",
            "ED25519",
            "-out",
            key.to_str().unwrap(),
        ]);
        run(&[
            "req",
            "-new",
            "-key",
            key.to_str().unwrap(),
            "-out",
            csr.to_str().unwrap(),
            "-subj",
            "/CN=new-peer",
        ]);
        let store = root.join("invites.json");
        let created = crate::invite::create(&[
            "--kind".into(),
            "peer".into(),
            "--name".into(),
            "new-peer".into(),
            "--site".into(),
            "test-site".into(),
            "--iroh".into(),
            "--invite-store".into(),
            store.to_string_lossy().into_owned(),
            "--write".into(),
        ])
        .unwrap();
        let sync_endpoint = endpoint(false).await.unwrap();
        let at = crate::invite::now().unwrap();
        let sync = SyncRendezvous {
            server_name: "authority.test".into(),
            endpoint: serde_json::from_value(serde_json::json!({
                "id":"mycelium-sync", "endpoint_id":sync_endpoint.id().to_string(),
                "alpns":["mycelium/sync/1"], "direct_addresses":["127.0.0.1:12345"],
                "relay_urls":[], "observed_at":at, "expires_at":at+120
            }))
            .unwrap(),
        };
        let sync_path = root.join("sync.json");
        std::fs::write(&sync_path, serde_json::to_vec(&sync).unwrap()).unwrap();
        let listener = endpoint(false).await.unwrap();
        let addr = listener.addr();
        let ip = addr.ip_addrs().next().unwrap();
        let gateway = encode(
            EndpointAddr::new(addr.id).with_ip_addr(*ip),
            created.expires_at,
        );
        let state = crate::oidc_gateway::pairing_state(
            root.join("unused-ssh-ca"),
            ca.clone(),
            store.clone(),
        );
        let task = tokio::spawn(serve_endpoint(
            listener,
            state.clone(),
            store.clone(),
            created.id.clone(),
            created.expires_at,
            sync_path,
        ));
        let request = crate::invite::RedeemRequest {
            claim: created.code.clone(),
            public_key: String::new(),
            peer_csr: Some(std::fs::read_to_string(&csr).unwrap()),
        };
        let mut invalid = request.clone();
        invalid.claim = "invalid".into();
        assert!(redeem(&gateway, invalid).await.is_err());
        assert_eq!(
            crate::invite::load(&store).unwrap().invitations[0].remaining_uses,
            1
        );
        let (response, seed, relays) = redeem(&gateway, request.clone()).await.unwrap();
        assert!(!relays);
        assert_eq!(response.principal, "new-peer");
        let peer = response.peer.unwrap();
        assert_eq!(peer.site, "test-site");
        assert!(peer.peers.is_empty()); // No TCP/tailnet bootstrap needed.
        let cert = root.join("node.pem");
        std::fs::write(&cert, peer.node_certificate).unwrap();
        run(&[
            "verify",
            "-CAfile",
            ca.join("ca.pem").to_str().unwrap(),
            "-verify_hostname",
            "new-peer",
            cert.to_str().unwrap(),
        ]);
        let home = root.join("new-peer");
        install_seed(&home, seed, relays).unwrap();
        let config: SyncConfig =
            serde_json::from_slice(&std::fs::read(home.join("iroh-sync.json")).unwrap()).unwrap();
        assert_eq!(
            config.seeds[0].endpoint.endpoint_id,
            sync.endpoint.endpoint_id
        );
        assert!(install_seed(&home, sync, relays).is_err());
        tokio::time::timeout(DEADLINE, task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert!(crate::oidc_gateway::redeem_pair_request(state, request)
            .await
            .unwrap_err()
            .contains("consumed"));
        sync_endpoint.close().await;
        std::fs::remove_dir_all(root).unwrap();
    }
}
