//! CA recovery bundles.
//!
//! A CA private key is wrapped with a key derived from a 24-word recovery
//! phrase. The phrase is an encoding of a 32-byte secret; Shamir shares are
//! shares of that same secret, so any threshold of shares can recover without
//! the written phrase. The CA key itself is never stored in plaintext.
//!
//! This is a cold-recovery tool. It does not put the CA key on a gateway, and
//! it does not rotate a trust anchor automatically.

use argon2::{Algorithm, Argon2, Params, Version};
use bip39::Mnemonic;
use rand_core::{OsRng, RngCore};
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sharks::{Share, Sharks};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use zeroize::Zeroize;

use myceliumd::client::ClientError;

const SCHEMA: u32 = 1;
const KIND: &str = "mycelium-ca-recovery";
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
const M_COST: u32 = 64 * 1024;
const T_COST: u32 = 3;
const P_COST: u32 = 1;

#[derive(Clone, Debug, Serialize, Deserialize)]
struct Bundle {
    schema: u32,
    kind: String,
    kdf: Kdf,
    cipher: Cipher,
    key_sha256: String,
    threshold: u8,
    shares: u8,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct Kdf {
    algorithm: String,
    salt: String,
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct Cipher {
    algorithm: String,
    nonce: String,
    ciphertext: String,
}

pub fn command(args: &[String]) -> Result<Vec<String>, ClientError> {
    let Some(subcommand) = args.first().map(String::as_str) else {
        return Ok(usage());
    };
    match subcommand {
        "backup" => backup(&args[1..]),
        "restore" => restore(&args[1..], true),
        "verify" => restore(&args[1..], false),
        "split" => split(&args[1..]),
        other => Ok(vec![
            format!("ca: unknown command {other:?}"),
            usage().join("\n"),
        ]),
    }
}

fn backup(args: &[String]) -> Result<Vec<String>, ClientError> {
    let mut key = None;
    let mut bundle = PathBuf::from("ca-recovery.json");
    let mut shares_dir = PathBuf::from("ca-recovery.d");
    let mut threshold = 3u8;
    let mut share_count = 5u8;
    let mut phrase_out = None;
    let mut write = false;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--key" => key = Some(PathBuf::from(value(args, &mut index, "--key")?)),
            "--bundle" => bundle = PathBuf::from(value(args, &mut index, "--bundle")?),
            "--shares" => shares_dir = PathBuf::from(value(args, &mut index, "--shares")?),
            "--threshold" => threshold = number(args, &mut index, "--threshold")?,
            "--share-count" => share_count = number(args, &mut index, "--share-count")?,
            "--phrase-out" => {
                phrase_out = Some(PathBuf::from(value(args, &mut index, "--phrase-out")?))
            }
            "--write" => write = true,
            other => {
                return Err(ClientError::Protocol(format!(
                    "ca backup: unknown argument {other:?}"
                )))
            }
        }
        index += 1;
    }
    if !write {
        return Err(ClientError::Protocol("ca backup requires --write".into()));
    }
    let key_path = key.ok_or_else(|| ClientError::Protocol("ca backup requires --key".into()))?;
    if threshold < 2 || threshold > share_count {
        return Err(ClientError::Protocol(
            "threshold must be between 2 and share-count".into(),
        ));
    }
    let plaintext = fs::read(&key_path)
        .map_err(|error| ClientError::Protocol(format!("read {}: {error}", key_path.display())))?;
    if plaintext.is_empty() || plaintext.len() > 1024 * 1024 {
        return Err(ClientError::Protocol(
            "CA key is empty or larger than 1 MiB".into(),
        ));
    }

    let mut entropy = [0u8; 32];
    OsRng.fill_bytes(&mut entropy);
    let mnemonic = Mnemonic::from_entropy(&entropy)
        .map_err(|error| ClientError::Protocol(format!("recovery phrase: {error}")))?;
    let mut salt = [0u8; SALT_LEN];
    let mut nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut nonce);
    let mut wrapping = derive_key(&entropy, &salt)?;
    let ciphertext = encrypt(&wrapping, &nonce, &plaintext)?;
    wrapping.zeroize();
    let key_sha256 = hex::encode(Sha256::digest(&plaintext));

    let bundle_value = Bundle {
        schema: SCHEMA,
        kind: KIND.into(),
        kdf: Kdf {
            algorithm: "argon2id".into(),
            salt: hex::encode(salt),
            m_cost: M_COST,
            t_cost: T_COST,
            p_cost: P_COST,
        },
        cipher: Cipher {
            algorithm: "aes-256-gcm".into(),
            nonce: hex::encode(nonce),
            ciphertext: hex::encode(&ciphertext),
        },
        key_sha256,
        threshold,
        shares: share_count,
    };
    let bytes = serde_json::to_vec_pretty(&bundle_value)
        .map_err(|error| ClientError::Protocol(error.to_string()))?;
    write_private(&bundle, &bytes)?;

    let sharks = Sharks(threshold);
    let shares: Vec<Share> = sharks
        .dealer(&entropy)
        .take(usize::from(share_count))
        .collect();
    if shares.len() != usize::from(share_count) {
        return Err(ClientError::Protocol(
            "could not generate all shares".into(),
        ));
    }
    fs::create_dir_all(&shares_dir).map_err(|error| {
        ClientError::Protocol(format!("create {}: {error}", shares_dir.display()))
    })?;
    for (offset, share) in shares.iter().enumerate() {
        let bytes = Vec::from(share);
        let path = shares_dir.join(format!("share-{:02}.hex", offset + 1));
        write_private(&path, hex::encode(bytes).as_bytes())?;
    }
    entropy.zeroize();

    let phrase = mnemonic.to_string();
    let mut lines = vec![
        format!("bundle: {}", bundle.display()),
        format!("shares: {} (threshold {threshold})", shares_dir.display()),
        "Store the recovery phrase offline. It is not written to disk unless --phrase-out is used."
            .into(),
    ];
    if let Some(path) = phrase_out {
        write_private(&path, phrase.as_bytes())?;
        lines.push(format!("phrase: {} (mode 0600)", path.display()));
    } else {
        lines.push(format!("RECOVERY PHRASE: {phrase}"));
    }
    Ok(lines)
}

fn restore(args: &[String], write: bool) -> Result<Vec<String>, ClientError> {
    let mut bundle = PathBuf::from("ca-recovery.json");
    let mut out = None;
    let mut phrase_file = None;
    let mut share_paths = Vec::new();
    let mut force = false;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--bundle" => bundle = PathBuf::from(value(args, &mut index, "--bundle")?),
            "--out" => out = Some(PathBuf::from(value(args, &mut index, "--out")?)),
            "--phrase-file" => {
                phrase_file = Some(PathBuf::from(value(args, &mut index, "--phrase-file")?))
            }
            "--share" => share_paths.push(PathBuf::from(value(args, &mut index, "--share")?)),
            "--force" => force = true,
            "--write" => {}
            other => {
                return Err(ClientError::Protocol(format!(
                    "ca restore: unknown argument {other:?}"
                )))
            }
        }
        index += 1;
    }
    let bundle: Bundle = serde_json::from_slice(
        &fs::read(&bundle)
            .map_err(|error| ClientError::Protocol(format!("read bundle: {error}")))?,
    )
    .map_err(|error| ClientError::Protocol(format!("parse bundle: {error}")))?;
    if bundle.schema != SCHEMA || bundle.kind != KIND {
        return Err(ClientError::Protocol(
            "not a mycelium CA recovery bundle".into(),
        ));
    }
    let salt = decode_hex::<SALT_LEN>(&bundle.kdf.salt, "salt")?;
    let nonce = decode_hex::<NONCE_LEN>(&bundle.cipher.nonce, "nonce")?;
    let ciphertext = hex::decode(&bundle.cipher.ciphertext)
        .map_err(|error| ClientError::Protocol(format!("ciphertext: {error}")))?;
    let mut secret = if let Some(path) = phrase_file {
        let phrase = fs::read_to_string(&path)
            .map_err(|error| ClientError::Protocol(format!("read phrase: {error}")))?;
        let mnemonic = Mnemonic::parse(phrase.trim())
            .map_err(|error| ClientError::Protocol(format!("recovery phrase: {error}")))?;
        mnemonic.to_entropy()
    } else if !share_paths.is_empty() {
        let mut shares = Vec::new();
        for path in &share_paths {
            let encoded = fs::read_to_string(path).map_err(|error| {
                ClientError::Protocol(format!("read {}: {error}", path.display()))
            })?;
            let bytes = hex::decode(encoded.trim())
                .map_err(|error| ClientError::Protocol(format!("{}: {error}", path.display())))?;
            shares.push(
                Share::try_from(bytes.as_slice())
                    .map_err(|error| ClientError::Protocol(error.into()))?,
            );
        }
        Sharks(bundle.threshold)
            .recover(&shares)
            .map_err(|error| ClientError::Protocol(error.into()))?
    } else {
        return Err(ClientError::Protocol(
            "ca restore requires --phrase-file or --share".into(),
        ));
    };
    if secret.len() != 32 {
        return Err(ClientError::Protocol(
            "recovery secret is not 32 bytes".into(),
        ));
    }
    let mut wrapping = derive_key(&secret, &salt)?;
    let plaintext = decrypt(&wrapping, &nonce, &ciphertext)?;
    wrapping.zeroize();
    secret.zeroize();
    let digest = hex::encode(Sha256::digest(&plaintext));
    if digest != bundle.key_sha256 {
        return Err(ClientError::Protocol(
            "recovered key does not match the bundle hash".into(),
        ));
    }
    if !write {
        return Ok(vec![format!("verified CA key (sha256 {digest})")]);
    }
    let out = out.ok_or_else(|| ClientError::Protocol("ca restore requires --out".into()))?;
    if out.exists() && !force {
        return Err(ClientError::Protocol(format!(
            "{} exists; use --force to replace it",
            out.display()
        )));
    }
    write_private(&out, &plaintext)?;
    Ok(vec![format!(
        "restored {} (sha256 {digest})",
        out.display()
    )])
}

fn split(args: &[String]) -> Result<Vec<String>, ClientError> {
    let mut phrase_file = None;
    let mut out = PathBuf::from("ca-recovery.d");
    let mut threshold = 3u8;
    let mut share_count = 5u8;
    let mut write = false;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--phrase-file" => {
                phrase_file = Some(PathBuf::from(value(args, &mut index, "--phrase-file")?))
            }
            "--out" => out = PathBuf::from(value(args, &mut index, "--out")?),
            "--threshold" => threshold = number(args, &mut index, "--threshold")?,
            "--share-count" => share_count = number(args, &mut index, "--share-count")?,
            "--write" => write = true,
            other => {
                return Err(ClientError::Protocol(format!(
                    "ca split: unknown argument {other:?}"
                )))
            }
        }
        index += 1;
    }
    if !write {
        return Err(ClientError::Protocol("ca split requires --write".into()));
    }
    if threshold < 2 || threshold > share_count {
        return Err(ClientError::Protocol(
            "threshold must be between 2 and share-count".into(),
        ));
    }
    let path = phrase_file
        .ok_or_else(|| ClientError::Protocol("ca split requires --phrase-file".into()))?;
    let phrase = fs::read_to_string(&path)
        .map_err(|error| ClientError::Protocol(format!("read phrase: {error}")))?;
    let mnemonic = Mnemonic::parse(phrase.trim())
        .map_err(|error| ClientError::Protocol(format!("recovery phrase: {error}")))?;
    let mut entropy = mnemonic.to_entropy();
    let shares: Vec<Share> = Sharks(threshold)
        .dealer(&entropy)
        .take(usize::from(share_count))
        .collect();
    entropy.zeroize();
    fs::create_dir_all(&out)
        .map_err(|error| ClientError::Protocol(format!("create {}: {error}", out.display())))?;
    for (offset, share) in shares.iter().enumerate() {
        write_private(
            &out.join(format!("share-{:02}.hex", offset + 1)),
            hex::encode(Vec::from(share)).as_bytes(),
        )?;
    }
    Ok(vec![format!(
        "wrote {} shares to {} (threshold {threshold})",
        shares.len(),
        out.display()
    )])
}

fn derive_key(secret: &[u8], salt: &[u8]) -> Result<[u8; 32], ClientError> {
    let params = Params::new(M_COST, T_COST, P_COST, Some(32))
        .map_err(|error| ClientError::Protocol(format!("argon2 parameters: {error}")))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0u8; 32];
    argon
        .hash_password_into(secret, salt, &mut key)
        .map_err(|error| ClientError::Protocol(format!("argon2: {error}")))?;
    Ok(key)
}

fn encrypt(
    key: &[u8; 32],
    nonce: &[u8; NONCE_LEN],
    plaintext: &[u8],
) -> Result<Vec<u8>, ClientError> {
    let unbound = UnboundKey::new(&AES_256_GCM, key)
        .map_err(|_| ClientError::Protocol("AES-256-GCM key rejected".into()))?;
    let key = LessSafeKey::new(unbound);
    let mut out = plaintext.to_vec();
    let tag = key
        .seal_in_place_separate_tag(Nonce::assume_unique_for_key(*nonce), Aad::empty(), &mut out)
        .map_err(|_| ClientError::Protocol("encrypt recovery bundle".into()))?;
    out.extend_from_slice(tag.as_ref());
    Ok(out)
}

fn decrypt(
    key: &[u8; 32],
    nonce: &[u8; NONCE_LEN],
    ciphertext: &[u8],
) -> Result<Vec<u8>, ClientError> {
    if ciphertext.len() <= TAG_LEN {
        return Err(ClientError::Protocol(
            "recovery ciphertext is too short".into(),
        ));
    }
    let unbound = UnboundKey::new(&AES_256_GCM, key)
        .map_err(|_| ClientError::Protocol("AES-256-GCM key rejected".into()))?;
    let key = LessSafeKey::new(unbound);
    let mut out = ciphertext.to_vec();
    let plaintext = key
        .open_in_place(Nonce::assume_unique_for_key(*nonce), Aad::empty(), &mut out)
        .map_err(|_| ClientError::Protocol("wrong recovery phrase or corrupt bundle".into()))?;
    Ok(plaintext.to_vec())
}

fn decode_hex<const N: usize>(value: &str, name: &str) -> Result<[u8; N], ClientError> {
    let bytes =
        hex::decode(value).map_err(|error| ClientError::Protocol(format!("{name}: {error}")))?;
    if bytes.len() != N {
        return Err(ClientError::Protocol(format!(
            "{name} has the wrong length"
        )));
    }
    let mut out = [0u8; N];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn number(args: &[String], index: &mut usize, flag: &str) -> Result<u8, ClientError> {
    value(args, index, flag)?
        .parse()
        .map_err(|_| ClientError::Protocol(format!("{flag} expects a number")))
}

fn value(args: &[String], index: &mut usize, flag: &str) -> Result<String, ClientError> {
    *index += 1;
    args.get(*index)
        .cloned()
        .ok_or_else(|| ClientError::Protocol(format!("{flag} requires a value")))
}

fn write_private(path: &Path, bytes: &[u8]) -> Result<(), ClientError> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent).map_err(|error| {
                ClientError::Protocol(format!("create {}: {error}", parent.display()))
            })?;
        }
    }
    let mut options = OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .map_err(|error| ClientError::Protocol(format!("open {}: {error}", path.display())))?;
    file.write_all(bytes)
        .map_err(|error| ClientError::Protocol(format!("write {}: {error}", path.display())))?;
    Ok(())
}

fn usage() -> Vec<String> {
    [
        "usage: mycelium ca backup --key PATH [--bundle FILE] [--shares DIR] [--threshold N] [--share-count N] [--phrase-out FILE] --write",
        "       mycelium ca restore --bundle FILE --out PATH --phrase-file FILE [--force] --write",
        "       mycelium ca restore --bundle FILE --out PATH --share FILE --share FILE --share FILE [--force] --write",
        "       mycelium ca verify --bundle FILE --phrase-file FILE",
        "       mycelium ca split --phrase-file FILE [--out DIR] [--threshold N] [--share-count N] --write",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect()
}

#[cfg(test)]
mod tests {
    use super::{decrypt, derive_key, encrypt, Sharks};
    use sharks::Share;

    #[test]
    fn encrypt_roundtrip() {
        let key = derive_key(b"01234567890123456789012345678901", b"0123456789abcdef").unwrap();
        let nonce = [7u8; 12];
        let ciphertext = encrypt(&key, &nonce, b"ca-private-key").unwrap();
        assert_eq!(
            decrypt(&key, &nonce, &ciphertext).unwrap(),
            b"ca-private-key"
        );
    }

    #[test]
    fn three_of_five_shares_recover() {
        let secret = [42u8; 32];
        let sharks = Sharks(3);
        let shares: Vec<Share> = sharks.dealer(&secret).take(5).collect();
        let recovered = sharks.recover(&shares[..3]).unwrap();
        assert_eq!(recovered, secret);
    }
}
