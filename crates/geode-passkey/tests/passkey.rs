use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use geode::{GeodeRef, MemoryBackend, Store};
use geode_passkey::{PasskeyCredential, SoftwarePasskey};
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{DerSignature, VerifyingKey};
use sha2::{Digest, Sha256};

const RP_ID: &str = "sso.fpl.dev";
const ORIGIN: &str = "https://sso.fpl.dev";
const CHALLENGE: &str = "dGhpcy1pcy1hLWNoYWxsZW5nZQ";

fn passkey() -> SoftwarePasskey {
    SoftwarePasskey::generate(RP_ID, ORIGIN, b"user-handle".to_vec()).unwrap()
}

fn verified_assertion(passkey: &SoftwarePasskey, assertion: &geode_passkey::Assertion) {
    let auth_data = URL_SAFE_NO_PAD
        .decode(&assertion.authenticator_data)
        .unwrap();
    let client_data = URL_SAFE_NO_PAD.decode(&assertion.client_data_json).unwrap();
    let signature = URL_SAFE_NO_PAD.decode(&assertion.signature).unwrap();

    assert_eq!(
        &auth_data[..32],
        Sha256::digest(RP_ID.as_bytes()).as_slice()
    );
    assert_eq!(auth_data[32] & 0x01, 0x01, "user presence");
    assert_eq!(auth_data[32] & 0x04, 0x04, "user verification");
    assert_eq!(auth_data[32] & 0x40, 0, "assertions omit attested data");

    let mut signing_input = auth_data.clone();
    signing_input.extend_from_slice(&Sha256::digest(&client_data));
    let signature = DerSignature::try_from(signature.as_slice()).unwrap();
    VerifyingKey::from_sec1_bytes(&passkey.public_key_sec1())
        .unwrap()
        .verify(&signing_input, &signature)
        .unwrap();

    let client: serde_json::Value = serde_json::from_slice(&client_data).unwrap();
    assert_eq!(client["type"], "webauthn.get");
    assert_eq!(client["challenge"], CHALLENGE);
    assert_eq!(client["origin"], ORIGIN);
    assert_eq!(client["crossOrigin"], false);
}

#[test]
fn assertions_are_real_es256_signatures_over_the_expected_input() {
    let mut passkey = passkey();
    let assertion = passkey.assertion(CHALLENGE).unwrap();
    verified_assertion(&passkey, &assertion);
    assert_eq!(assertion.user_handle.as_deref(), Some("dXNlci1oYW5kbGU"));
    assert_eq!(
        assertion.credential_id,
        passkey.credential().credential_id_base64url()
    );

    // The counter advances and is signed.
    let second = passkey.assertion(CHALLENGE).unwrap();
    verified_assertion(&passkey, &second);
    let auth_data = URL_SAFE_NO_PAD.decode(&second.authenticator_data).unwrap();
    assert_eq!(u32::from_be_bytes(auth_data[33..37].try_into().unwrap()), 2);
}

#[test]
fn registration_is_none_attestation_with_a_cose_public_key() {
    let passkey = passkey();
    let registration = passkey.registration(CHALLENGE).unwrap();
    let attestation = URL_SAFE_NO_PAD
        .decode(&registration.attestation_object)
        .unwrap();
    let parsed: ciborium::value::Value = ciborium::de::from_reader(attestation.as_slice()).unwrap();
    let ciborium::value::Value::Map(map) = parsed else {
        panic!("attestation is not a CBOR map");
    };
    let field = |name: &str| {
        map.iter()
            .find(|(key, _)| key.as_text() == Some(name))
            .map(|(_, value)| value)
    };
    assert_eq!(field("fmt").and_then(|v| v.as_text()), Some("none"));
    let auth_data = field("authData").and_then(|v| v.as_bytes()).unwrap();
    assert_eq!(
        &auth_data[..32],
        Sha256::digest(RP_ID.as_bytes()).as_slice()
    );
    assert_eq!(auth_data[32] & 0x40, 0x40, "attested data is included");
    let credential_id = &passkey.credential().credential_id;
    assert!(
        auth_data
            .windows(credential_id.len())
            .any(|window| window == credential_id),
        "credential id is present in attested data"
    );

    let client_data = URL_SAFE_NO_PAD
        .decode(&registration.client_data_json)
        .unwrap();
    let client: serde_json::Value = serde_json::from_slice(&client_data).unwrap();
    assert_eq!(client["type"], "webauthn.create");
}

#[test]
fn private_keys_round_trip_through_geode_without_leaking_in_debug() {
    let store = Store::new(MemoryBackend::new());
    let reference = GeodeRef::parse("geode://auth/work/passkey-sso").unwrap();
    let passkey = passkey();
    let meta = passkey.store(&store, &reference, Some("work SSO")).unwrap();
    assert_eq!(meta.kind, geode::CredentialKind::Passkey);
    assert!(meta.purposes.contains(&geode::Purpose::passkey_assert()));
    assert!(format!("{passkey:?}").contains("redacted"));
    let pkcs8 = passkey.to_pkcs8().unwrap();
    assert!(!format!("{passkey:?}").contains(&URL_SAFE_NO_PAD.encode(pkcs8.expose())));

    let mut loaded =
        SoftwarePasskey::load(&store, &reference, passkey.credential().clone()).unwrap();
    assert_eq!(loaded.public_key_sec1(), passkey.public_key_sec1());
    let assertion = loaded.assertion(CHALLENGE).unwrap();
    verified_assertion(&loaded, &assertion);
}

#[test]
fn metadata_rejects_unsafe_or_unsupported_values() {
    assert!(
        PasskeyCredential::new("sso.fpl.dev", "http://sso.fpl.dev", vec![1; 16], vec![]).is_err()
    );
    assert!(PasskeyCredential::new("", ORIGIN, vec![1; 16], vec![]).is_err());
    assert!(PasskeyCredential::new(RP_ID, ORIGIN, vec![], vec![]).is_err());
    let mut metadata = passkey().credential().clone();
    metadata.algorithm = -257;
    assert!(metadata.validate().is_err());
}
