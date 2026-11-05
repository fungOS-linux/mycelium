//! Owner-only geode broker.
//!
//! `geoded` holds an encrypted `FileBackend`, listens on a Unix socket, and
//! leases secrets only to processes with the same UID. It is read-only over the
//! socket: storing/rotating/deleting is an operator action, not a client verb.
//!
//! Protocol: one JSON request per connection, newline-terminated.
//!
//! ```json
//! {"op":"lease","reference":"geode://mail/work/imap","purpose":"mail.connect","ttl_ms":5000}
//! {"ok":true,"secret_b64":"...","expires_at":1793833200}
//! {"ok":false,"error":"..."}
//! ```
//!
//! Run:
//! `geoded --socket ~/.geode/geode.sock --store ~/.geode/store.db --key-file ~/.geode/store.key`
//! Add `--init` once to generate a 0600 key file.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::os::unix::io::AsRawFd;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, ensure, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use geode::{FileBackend, GeodeRef, NewCredential, Purpose, SecretBytes, Store};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};

const MAX_REQUEST_BYTES: usize = 8192;

#[derive(Debug, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
enum Request {
    Lease {
        reference: String,
        purpose: String,
        ttl_ms: u64,
    },
}

#[derive(Debug, Serialize)]
struct Response {
    ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    secret_b64: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    expires_at: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

fn main() -> Result<()> {
    let options = Options::parse()?;
    let key = read_or_init_key(&options.key_file, options.init)?;
    if let Some(parent) = options.store.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("create store directory {}", parent.display()))?;
    }
    let backend = FileBackend::open(&options.store, key)?;
    let store = Arc::new(Store::new(backend));
    if let Some(reference) = &options.put {
        let reference = GeodeRef::parse(reference)?;
        let purpose = Purpose::parse(
            options
                .purpose
                .as_deref()
                .context("--put requires --purpose")?,
        )?;
        let mut secret = String::new();
        std::io::Read::read_to_string(&mut std::io::stdin(), &mut secret)?;
        let secret = secret.trim_end_matches(['\r', '\n']);
        ensure!(!secret.is_empty(), "refusing to store an empty secret");
        store.insert(
            &reference,
            NewCredential::opaque(SecretBytes::from(secret)).with_purpose(purpose),
        )?;
        eprintln!("geoded: stored {reference}");
        return Ok(());
    }
    let listener = bind_socket(&options.socket)?;
    eprintln!(
        "geoded: listening on {} (store {}, backend {})",
        options.socket.display(),
        options.store.display(),
        store.backend_kind()
    );
    for connection in listener.incoming() {
        match connection {
            Ok(stream) => {
                let store = Arc::clone(&store);
                std::thread::spawn(move || {
                    if let Err(error) = handle(stream, &store) {
                        eprintln!("geoded: connection error: {error:#}");
                    }
                });
            }
            Err(error) => eprintln!("geoded: accept error: {error}"),
        }
    }
    Ok(())
}

fn handle(stream: UnixStream, store: &Store<FileBackend>) -> Result<()> {
    let uid = peer_uid(&stream).context("read peer credentials")?;
    if uid != unsafe { libc::getuid() } {
        write_response(
            &stream,
            &Response {
                ok: false,
                secret_b64: None,
                expires_at: None,
                error: Some("peer uid is not the owner".into()),
            },
        )?;
        bail!("denied peer uid {uid}");
    }
    let mut line = String::new();
    let mut reader = BufReader::new(&stream);
    let read = reader.read_line(&mut line).context("read request")?;
    if read == 0 {
        return Ok(());
    }
    ensure!(
        read <= MAX_REQUEST_BYTES,
        "request exceeds the protocol bound"
    );
    let request: Request = match serde_json::from_str(&line) {
        Ok(request) => request,
        Err(error) => {
            write_response(
                &stream,
                &Response {
                    ok: false,
                    secret_b64: None,
                    expires_at: None,
                    error: Some(format!("invalid request: {error}")),
                },
            )?;
            return Ok(());
        }
    };
    let response = lease(store, request);
    if response.ok {
        eprintln!("geoded: issued lease");
    }
    write_response(&stream, &response)
}

fn lease(store: &Store<FileBackend>, request: Request) -> Response {
    let Request::Lease {
        reference,
        purpose,
        ttl_ms,
    } = request;
    let result = (|| -> Result<String> {
        let reference = GeodeRef::parse(&reference)?;
        let purpose = Purpose::parse(purpose)?;
        ensure!(
            (1_000..=3_600_000).contains(&ttl_ms),
            "ttl_ms is outside the bounded range"
        );
        let lease = store.lease(&reference, &purpose, Duration::from_millis(ttl_ms))?;
        Ok(STANDARD.encode(lease.expose()?))
    })();
    match result {
        Ok(secret_b64) => Response {
            ok: true,
            secret_b64: Some(secret_b64),
            expires_at: None,
            error: None,
        },
        Err(error) => Response {
            ok: false,
            secret_b64: None,
            expires_at: None,
            error: Some(error.to_string()),
        },
    }
}

fn write_response(mut stream: &UnixStream, response: &Response) -> Result<()> {
    let mut bytes = serde_json::to_vec(response)?;
    bytes.push(b'\n');
    stream.write_all(&bytes)?;
    stream.flush()?;
    Ok(())
}

struct Options {
    socket: PathBuf,
    store: PathBuf,
    key_file: PathBuf,
    init: bool,
    put: Option<String>,
    purpose: Option<String>,
}

impl Options {
    fn parse() -> Result<Self> {
        let mut options = Self {
            socket: home()?.join(".geode/geode.sock"),
            store: home()?.join(".geode/store.db"),
            key_file: home()?.join(".geode/store.key"),
            init: false,
            put: None,
            purpose: None,
        };
        let mut args = std::env::args().skip(1);
        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--socket" => options.socket = next(&mut args, "--socket")?.into(),
                "--store" => options.store = next(&mut args, "--store")?.into(),
                "--key-file" => options.key_file = next(&mut args, "--key-file")?.into(),
                "--init" => options.init = true,
                "--put" => options.put = Some(next(&mut args, "--put")?),
                "--purpose" => options.purpose = Some(next(&mut args, "--purpose")?),
                other => bail!("unknown argument {other}"),
            }
        }
        if let Some(parent) = options.socket.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("create socket directory {}", parent.display()))?;
        }
        Ok(options)
    }
}

fn next(args: &mut impl Iterator<Item = String>, flag: &str) -> Result<String> {
    args.next().with_context(|| format!("{flag} needs a value"))
}

fn home() -> Result<PathBuf> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .context("HOME is not set")
}

fn read_or_init_key(path: &Path, init: bool) -> Result<[u8; 32]> {
    if !path.exists() {
        ensure!(
            init,
            "key file {} does not exist; pass --init",
            path.display()
        );
        let mut key = [0u8; 32];
        OsRng.fill_bytes(&mut key);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut file = std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(path)?;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        file.write_all(&key)?;
        file.sync_all()?;
        return Ok(key);
    }
    let metadata = std::fs::metadata(path)?;
    if metadata.permissions().mode() & 0o077 != 0 {
        bail!(
            "key file {} must not be group/world readable",
            path.display()
        );
    }
    let bytes = std::fs::read(path)?;
    if bytes.len() == 32 {
        let mut key = [0u8; 32];
        key.copy_from_slice(&bytes);
        return Ok(key);
    }
    let text = String::from_utf8(bytes).context("key file is not raw bytes or hex")?;
    let text = text.trim();
    ensure!(text.len() == 64, "hex key must be 64 characters");
    let mut key = [0u8; 32];
    for (index, byte) in key.iter_mut().enumerate() {
        let pair = text
            .get(index * 2..index * 2 + 2)
            .context("key file has invalid hex")?;
        *byte = u8::from_str_radix(pair, 16).context("key file has invalid hex")?;
    }
    Ok(key)
}

fn bind_socket(path: &Path) -> Result<UnixListener> {
    if path.exists() {
        let metadata = std::fs::symlink_metadata(path)?;
        if !metadata.file_type().is_socket() {
            bail!("{} exists and is not a socket", path.display());
        }
        std::fs::remove_file(path)?;
    }
    let listener = UnixListener::bind(path).with_context(|| format!("bind {}", path.display()))?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    Ok(listener)
}

#[cfg(target_os = "macos")]
fn peer_uid(stream: &UnixStream) -> std::io::Result<u32> {
    let mut uid: libc::uid_t = 0;
    let mut gid: libc::gid_t = 0;
    let result = unsafe { libc::getpeereid(stream.as_raw_fd(), &mut uid, &mut gid) };
    if result != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(uid)
}

#[cfg(target_os = "linux")]
fn peer_uid(stream: &UnixStream) -> std::io::Result<u32> {
    #[repr(C)]
    struct UCred {
        pid: libc::pid_t,
        uid: libc::uid_t,
        gid: libc::gid_t,
    }
    let mut cred = UCred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut length = std::mem::size_of::<UCred>() as libc::socklen_t;
    let result = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut cred as *mut UCred as *mut libc::c_void,
            &mut length,
        )
    };
    if result != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(cred.uid)
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn peer_uid(_stream: &UnixStream) -> std::io::Result<u32> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "peer credentials are not implemented on this platform",
    ))
}
