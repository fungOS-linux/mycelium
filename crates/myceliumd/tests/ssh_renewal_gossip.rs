//! Three isolated daemon processes: client -> relay -> issuer. No production
//! CA, identity, configuration, listener or credential file is used.
#![cfg(unix)]
use mycelium_peer_protocol::{AccessRecord, AccessStatement, PeerEvent, SignedEnvelope};
use std::{
    fs,
    path::PathBuf,
    process::{Child, Command, Stdio},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

struct Sandbox {
    directory: PathBuf,
    children: Vec<Child>,
}
impl Drop for Sandbox {
    fn drop(&mut self) {
        for child in &mut self.children {
            let _ = child.kill();
            let _ = child.wait();
        }
        let _ = fs::remove_dir_all(&self.directory);
    }
}
fn timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

#[test]
fn expired_client_renews_through_relay_without_issuer_connection() {
    use std::os::unix::fs::PermissionsExt;
    let mut sandbox = Sandbox {
        directory: PathBuf::from("/tmp").join(format!(
            "myc-r-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        )),
        children: vec![],
    };
    fs::create_dir(&sandbox.directory).unwrap();
    fs::set_permissions(&sandbox.directory, fs::Permissions::from_mode(0o700)).unwrap();
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let tls_key = rcgen::KeyPair::generate().unwrap();
    let tls_ca = params.self_signed(&tls_key).unwrap();
    let ssh_ca = ssh_key::PrivateKey::new(
        ssh_key::private::Ed25519Keypair::from_seed(&[17; 32]).into(),
        "test CA",
    )
    .unwrap();
    let subject = ssh_key::PrivateKey::new(
        ssh_key::private::Ed25519Keypair::from_seed(&[11; 32]).into(),
        "test subject",
    )
    .unwrap();
    let access_key = ed25519_dalek::SigningKey::from_bytes(&[7; 32]);
    let peer_keys: Vec<_> = (91..=93)
        .map(|seed| ed25519_dalek::SigningKey::from_bytes(&[seed; 32]))
        .collect();
    let nodes: Vec<_> = peer_keys
        .iter()
        .map(|key| mycelium_peer_protocol::encode_hex(key.verifying_key().as_bytes()))
        .collect();
    let listeners: Vec<_> = (0..3)
        .map(|_| std::net::TcpListener::bind("127.0.0.1:0").unwrap())
        .collect();
    let addresses: Vec<_> = listeners
        .iter()
        .map(|s| s.local_addr().unwrap().to_string())
        .collect();
    drop(listeners);
    let at = timestamp();
    let grant = AccessRecord::sign(
        &access_key,
        AccessStatement::Grant {
            grant_id: "test-renewal".into(),
            principal: "james".into(),
            serial: 42,
            roles: vec!["home-operator".into()],
            scopes: vec![myceliumd::ssh_renewal::scope(&nodes[2], 300).unwrap()],
            unix_users: vec!["mames".into()],
            ssh_public_keys: vec![subject.public_key().to_openssh().unwrap()],
            oidc_audiences: vec![],
            oidc_ssh_key_exchange: false,
            not_before: at - 30,
            not_after: at + 3600,
        },
    )
    .unwrap();
    let grant_envelope =
        SignedEnvelope::sign(&peer_keys[0], 1, at, PeerEvent::Access(grant)).unwrap();
    let mut old = ssh_key::certificate::Builder::new(
        vec![1; 32],
        subject.public_key().key_data().clone(),
        at - 9 * 86400,
        at - 8 * 86400,
    )
    .unwrap();
    old.cert_type(ssh_key::certificate::CertType::User).unwrap();
    old.valid_principal("mycelium-role-home-operator").unwrap();
    let old = old.sign(&ssh_ca).unwrap().to_openssh().unwrap();
    for index in 0..3 {
        let directory = sandbox.directory.join(format!("node{index}"));
        fs::create_dir(&directory).unwrap();
        fs::create_dir(directory.join("ssh")).unwrap();
        fs::write(directory.join("peer.key"), peer_keys[index].to_bytes()).unwrap();
        fs::write(directory.join("ca.pem"), tls_ca.pem()).unwrap();
        let key = rcgen::KeyPair::generate().unwrap();
        let mut params =
            rcgen::CertificateParams::new(vec!["127.0.0.1".into(), "localhost".into()]).unwrap();
        params.extended_key_usages = vec![
            rcgen::ExtendedKeyUsagePurpose::ServerAuth,
            rcgen::ExtendedKeyUsagePurpose::ClientAuth,
        ];
        let leaf = params.signed_by(&key, &tls_ca, &tls_key).unwrap();
        fs::write(directory.join("node.pem"), leaf.pem()).unwrap();
        fs::write(directory.join("node.key"), key.serialize_pem()).unwrap();
        if index == 0 {
            fs::write(
                directory.join("ssh/user_ca"),
                ssh_ca
                    .to_openssh(ssh_key::LineEnding::LF)
                    .unwrap()
                    .as_bytes(),
            )
            .unwrap();
            fs::write(
                directory.join("peer-observations.json"),
                serde_json::to_vec(&vec![grant_envelope.clone()]).unwrap(),
            )
            .unwrap();
        }
        if index == 2 {
            fs::write(
                directory.join("ssh/public-key.pub"),
                subject.public_key().to_openssh().unwrap(),
            )
            .unwrap();
            fs::write(directory.join("ssh/user-cert.pub"), &old).unwrap();
        }
        let log = fs::File::create(directory.join("daemon.log")).unwrap();
        let seeds = if index == 0 {
            String::new()
        } else {
            addresses[index - 1].clone()
        };
        let child = Command::new(env!("CARGO_BIN_EXE_myceliumd"))
            .arg("serve")
            .env_clear()
            .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
            .env("MYCELIUM_HOME", &directory)
            .env("MYCELIUM_SITE", "isolated-renewal-test")
            .env("MYCELIUM_PEER_LISTEN", &addresses[index])
            .env("MYCELIUM_PEERS", seeds)
            .env("MYCELIUM_PEER_CA", directory.join("ca.pem"))
            .env("MYCELIUM_PEER_CERT", directory.join("node.pem"))
            .env("MYCELIUM_PEER_KEY", directory.join("node.key"))
            .env(
                "MYCELIUM_ACCESS_KEYS",
                mycelium_peer_protocol::encode_hex(access_key.verifying_key().as_bytes()),
            )
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::from(log))
            .spawn()
            .unwrap();
        sandbox.children.push(child);
    }
    let deadline = Instant::now() + Duration::from_secs(120);
    let certificate_path = sandbox.directory.join("node2/ssh/user-cert.pub");
    loop {
        let encoded = fs::read_to_string(&certificate_path).unwrap();
        if encoded != old {
            let cert = ssh_key::Certificate::from_openssh(&encoded).unwrap();
            cert.validate_at(
                timestamp(),
                [&ssh_ca.public_key().fingerprint(ssh_key::HashAlg::Sha256)],
            )
            .unwrap();
            assert_eq!(cert.serial(), 42);
            assert_eq!(cert.public_key(), subject.public_key().key_data());
            assert!(cert
                .valid_principals()
                .contains(&"mycelium-role-home-operator".into()));
            assert!(cert
                .valid_principals()
                .contains(&mycelium_peer_protocol::ssh_role_principal(
                    "james",
                    "home-operator"
                )));
            assert!(cert.valid_before() > timestamp());
            let observations: Vec<SignedEnvelope> = serde_json::from_slice(
                &fs::read(sandbox.directory.join("node1/peer-observations.json")).unwrap(),
            )
            .unwrap();
            assert!(observations
                .iter()
                .any(|e| matches!(e.event, PeerEvent::SshCredentialRequest(_))));
            assert!(observations
                .iter()
                .any(|e| matches!(e.event, PeerEvent::SshCredentialResponses(_))));
            assert!(!sandbox.directory.join("node1/ssh/user_ca").exists());
            assert!(!sandbox.directory.join("node2/ssh/user_ca").exists());
            break;
        }
        if Instant::now() >= deadline {
            let logs = (0..3)
                .map(|i| {
                    fs::read_to_string(sandbox.directory.join(format!("node{i}/daemon.log")))
                        .unwrap_or_default()
                })
                .collect::<Vec<_>>();
            panic!(
                "renewal did not traverse relay before deadline: {}",
                logs.join("\n")
            );
        }
        for child in &mut sandbox.children {
            assert!(
                child.try_wait().unwrap().is_none(),
                "isolated daemon exited"
            );
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}
