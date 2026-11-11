//! `geode-pgp`: detached OpenPGP signatures through a running `geoded`.
//!
//! The broker leases the key for one signing operation; this client imports it
//! into an ephemeral GnuPG home and returns only the signature. It never writes
//! the key to configuration or a log.

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use base64::{engine::general_purpose::STANDARD, Engine as _};
use geode_pgp::{verify_detached, PgpKey};
use serde_json::{json, Value};

const DEFAULT_SOCKET: &str = ".geode/geode.sock";
const LEASE_TTL_MS: u64 = 5_000;

fn main() -> ExitCode {
    match run(std::env::args().skip(1).collect()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("geode-pgp: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run(args: Vec<String>) -> Result<(), String> {
    let Some(command) = args.first().map(String::as_str) else {
        return Err(usage().to_string());
    };
    if matches!(command, "--help" | "-h" | "help") {
        println!("{}", usage());
        return Ok(());
    }
    let rest = &args[1..];

    match command {
        "sign" => {
            let key = load_key(rest)?;
            let signature = match named(rest, "--message") {
                Some(path) if path != "-" => key
                    .sign_detached_file(Path::new(path))
                    .map_err(|error| error.to_string())?,
                _ => {
                    let message = message_bytes(rest)?;
                    key.sign_detached(&message)
                        .map_err(|error| error.to_string())?
                }
            };
            std::io::stdout()
                .write_all(signature.as_bytes())
                .map_err(|error| format!("write signature: {error}"))?;
            Ok(())
        }
        "public-key" => {
            let key = load_key(rest)?;
            print!(
                "{}",
                key.public_key_armored()
                    .map_err(|error| error.to_string())?
            );
            Ok(())
        }
        "fingerprint" => {
            let key = load_key(rest)?;
            println!("{}", key.fingerprint());
            Ok(())
        }
        "verify" => {
            let public_key = required(rest, "--public-key")?;
            let signature_path = required(rest, "--signature")?;
            let public_key =
                std::fs::read(public_key).map_err(|error| format!("read {public_key}: {error}"))?;
            let signature = std::fs::read(signature_path)
                .map_err(|error| format!("read {signature_path}: {error}"))?;
            let message = message_bytes(rest)?;
            if verify_detached(&public_key, &message, &signature)
                .map_err(|error| error.to_string())?
            {
                println!("ok");
                Ok(())
            } else {
                println!("bad");
                Err("signature did not verify".into())
            }
        }
        other => Err(format!("unknown command `{other}`\n\n{}", usage())),
    }
}

fn load_key(args: &[String]) -> Result<PgpKey, String> {
    let socket = socket_path(args)?;
    let reference = required(args, "--reference")?;
    let purpose = required(args, "--purpose")?;
    let response = call(
        &socket,
        &json!({
            "op": "lease",
            "reference": reference,
            "purpose": purpose,
            "ttl_ms": LEASE_TTL_MS,
        }),
    )?;
    let secret = response["secret_b64"]
        .as_str()
        .ok_or("geoded returned no key")?;
    let secret = STANDARD
        .decode(secret)
        .map_err(|error| format!("invalid key response: {error}"))?;
    let fingerprint = match named(args, "--fingerprint") {
        Some(fingerprint) => fingerprint.to_owned(),
        None => PgpKey::detect_fingerprint(&secret).map_err(|error| error.to_string())?,
    };
    PgpKey::from_armored(secret, &fingerprint).map_err(|error| error.to_string())
}

fn socket_path(args: &[String]) -> Result<PathBuf, String> {
    if let Some(path) = named(args, "--socket") {
        return Ok(PathBuf::from(path));
    }
    if let Ok(path) = std::env::var("GEODE_SOCKET") {
        return Ok(PathBuf::from(path));
    }
    let home = std::env::var_os("HOME").ok_or("--socket or HOME is required")?;
    Ok(PathBuf::from(home).join(DEFAULT_SOCKET))
}

fn message_bytes(args: &[String]) -> Result<Vec<u8>, String> {
    match named(args, "--message") {
        Some("-") | None => {
            let mut message = Vec::new();
            std::io::stdin()
                .read_to_end(&mut message)
                .map_err(|error| format!("read message: {error}"))?;
            Ok(message)
        }
        Some(path) => std::fs::read(path).map_err(|error| format!("read {path}: {error}")),
    }
}

fn call(socket: &Path, request: &Value) -> Result<Value, String> {
    let mut stream = UnixStream::connect(socket)
        .map_err(|error| format!("connect {}: {error}", socket.display()))?;
    let mut line = serde_json::to_vec(request).map_err(|error| error.to_string())?;
    line.push(b'\n');
    stream
        .write_all(&line)
        .map_err(|error| format!("write request: {error}"))?;
    let mut response = String::new();
    stream
        .read_to_string(&mut response)
        .map_err(|error| format!("read response: {error}"))?;
    let value: Value =
        serde_json::from_str(&response).map_err(|error| format!("invalid response: {error}"))?;
    if value["ok"].as_bool() != Some(true) {
        return Err(value["error"]
            .as_str()
            .unwrap_or("geode request failed")
            .to_owned());
    }
    Ok(value)
}

fn named<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    args.iter()
        .position(|argument| argument == name)
        .and_then(|index| args.get(index + 1))
        .map(String::as_str)
}

fn required<'a>(args: &'a [String], name: &str) -> Result<&'a str, String> {
    named(args, name).ok_or_else(|| format!("{name} is required\n\n{}", usage()))
}

fn usage() -> &'static str {
    "geode-pgp sign --reference REF --purpose PURPOSE [--fingerprint FP] [--message FILE]\n\
     geode-pgp public-key --reference REF --purpose PURPOSE [--fingerprint FP]\n\
     geode-pgp fingerprint --reference REF --purpose PURPOSE\n\
     geode-pgp verify --public-key FILE --signature FILE [--message FILE]\n\n\
     --socket PATH defaults to GEODE_SOCKET or $HOME/.geode/geode.sock.\n\
     Messages come from stdin unless --message names a file."
}
