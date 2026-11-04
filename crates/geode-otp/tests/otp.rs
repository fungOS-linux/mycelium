use geode::{GeodeRef, MemoryBackend, Store};
use geode_otp::{parse_otpauth, OtpAlgorithm, OtpConfig, OtpKind, OtpSecret};

fn config(algorithm: OtpAlgorithm) -> OtpConfig {
    OtpConfig {
        kind: OtpKind::Totp,
        digits: 8,
        period: 30,
        algorithm,
        issuer: None,
        account: None,
    }
}

#[test]
fn totp_matches_rfc_6238_vectors() {
    let cases = [
        (
            OtpAlgorithm::Sha1,
            b"12345678901234567890".as_slice(),
            [
                (59, "94287082"),
                (1_111_111_109, "07081804"),
                (1_111_111_111, "14050471"),
                (1_234_567_890, "89005924"),
                (2_000_000_000, "69279037"),
                (20_000_000_000, "65353130"),
            ],
        ),
        (
            OtpAlgorithm::Sha256,
            b"12345678901234567890123456789012".as_slice(),
            [
                (59, "46119246"),
                (1_111_111_109, "68084774"),
                (1_111_111_111, "67062674"),
                (1_234_567_890, "91819424"),
                (2_000_000_000, "90698825"),
                (20_000_000_000, "77737706"),
            ],
        ),
        (
            OtpAlgorithm::Sha512,
            b"1234567890123456789012345678901234567890123456789012345678901234".as_slice(),
            [
                (59, "90693936"),
                (1_111_111_109, "25091201"),
                (1_111_111_111, "99943326"),
                (1_234_567_890, "93441116"),
                (2_000_000_000, "38618901"),
                (20_000_000_000, "47863826"),
            ],
        ),
    ];

    for (algorithm, seed, vectors) in cases {
        let secret = OtpSecret::from_bytes(seed.to_vec()).unwrap();
        let config = config(algorithm);
        for (time, expected) in vectors {
            assert_eq!(
                secret.code_at(&config, time).unwrap(),
                expected,
                "{algorithm:?} at {time}"
            );
        }
    }
}

#[test]
fn verification_honours_a_bounded_skew() {
    let secret = OtpSecret::from_bytes(b"12345678901234567890".to_vec()).unwrap();
    let config = OtpConfig {
        digits: 6,
        ..config(OtpAlgorithm::Sha1)
    };
    let code = secret.code_at(&config, 59).unwrap();
    assert!(secret.verify_at(&config, &code, 59, 0).unwrap());
    assert!(secret.verify_at(&config, &code, 89, 1).unwrap());
    assert!(!secret.verify_at(&config, &code, 89, 0).unwrap());
    assert!(!secret.verify_at(&config, "000000", 59, 0).unwrap());
}

#[test]
fn otpauth_uris_parse_without_leaking_the_secret() {
    let enrollment = parse_otpauth(
        "otpauth://totp/FPL%20Auth:alice%40fpl.dev\
         ?secret=JBSWY3DPEHPK3PXP&issuer=FPL%20Auth&algorithm=SHA1&digits=6&period=30",
    )
    .unwrap();
    assert_eq!(enrollment.config.kind, OtpKind::Totp);
    assert_eq!(enrollment.config.issuer.as_deref(), Some("FPL Auth"));
    assert_eq!(enrollment.config.account.as_deref(), Some("alice@fpl.dev"));
    assert_eq!(enrollment.config.digits, 6);
    assert_eq!(enrollment.secret.to_base32().as_str(), "JBSWY3DPEHPK3PXP");
    assert!(!format!("{enrollment:?}").contains("JBSWY3DPEHPK3PXP"));
    assert_eq!(
        enrollment.secret.to_base32().as_str(),
        "JBSWY3DPEHPK3PXP",
        "base32 round-trips"
    );

    let hotp = parse_otpauth("otpauth://hotp/FPL:alice?secret=JBSWY3DPEHPK3PXP&counter=5").unwrap();
    assert_eq!(hotp.config.kind, OtpKind::Hotp);
    assert_eq!(hotp.counter, Some(5));

    assert!(parse_otpauth("otpauth://totp/FPL:alice?digits=6").is_err());
    assert!(parse_otpauth("https://example.com").is_err());
    assert!(parse_otpauth("otpauth://totp/FPL:alice?secret=not-base32!").is_err());
}

#[test]
fn hotp_advances_a_caller_owned_counter() {
    let secret = OtpSecret::from_bytes(b"12345678901234567890".to_vec()).unwrap();
    let config = OtpConfig {
        kind: OtpKind::Hotp,
        digits: 6,
        algorithm: OtpAlgorithm::Sha1,
        ..OtpConfig::default()
    };
    // RFC 4226 Appendix D, counters 0..=9.
    let expected = [
        "755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583", "399871",
        "520489",
    ];
    for (counter, code) in expected.iter().enumerate() {
        assert_eq!(secret.hotp(&config, counter as u64).unwrap(), *code);
    }
    let code = secret.hotp(&config, 3).unwrap();
    assert_eq!(secret.verify_hotp(&config, &code, 0, 5).unwrap(), Some(4));
    assert_eq!(secret.verify_hotp(&config, &code, 5, 1).unwrap(), None);
}

#[test]
fn shared_secrets_round_trip_through_geode() {
    let store = Store::new(MemoryBackend::new());
    let reference = GeodeRef::parse("geode://auth/work/fpl-totp").unwrap();
    let secret = OtpSecret::from_base32("JBSWY3DPEHPK3PXP").unwrap();
    let meta = secret.store(&store, &reference, Some("work 2FA")).unwrap();
    assert_eq!(meta.kind, geode::CredentialKind::OtpSecret);
    assert!(meta.purposes.contains(&geode::Purpose::otp_generate()));

    let loaded = OtpSecret::load(&store, &reference).unwrap();
    assert_eq!(loaded.to_base32().as_str(), secret.to_base32().as_str());
    assert!(!format!("{loaded:?}").contains("JBSWY3DPEHPK3PXP"));
}
