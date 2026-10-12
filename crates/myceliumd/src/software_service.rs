//! Locally authorized native service activation. Release manifests never supply
//! commands, service names, or health probes. This adapter manages only an
//! explicitly bound systemd unit whose executable is the package's current link.
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

type Error = Box<dyn std::error::Error + Send + Sync>;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceBinding {
    pub unit: String,
    #[serde(default)]
    pub user_manager: bool,
    pub readiness: Readiness,
    #[serde(default = "startup_timeout")]
    pub timeout_secs: u64,
}

fn startup_timeout() -> u64 {
    10
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Readiness {
    /// Local, bounded HTTP JSON application check. The operator supplies the
    /// request and required response values, never a release publisher.
    HttpJson {
        address: SocketAddr,
        path: String,
        request: serde_json::Value,
        expect: BTreeMap<String, serde_json::Value>,
        timeout_ms: u64,
    },
    /// A bounded newline-delimited JSON request and reply. JSON pointers name
    /// required values; this keeps application schemas out of the updater.
    UnixJson {
        path: PathBuf,
        request: serde_json::Value,
        expect: BTreeMap<String, serde_json::Value>,
    },
    Unix {
        path: PathBuf,
        request: String,
        expect_prefix: String,
    },
    Tcp {
        address: SocketAddr,
        request: String,
        expect_prefix: String,
    },
}

/// Narrow lifecycle boundary. Tests and future native adapters use the same
/// stop/start/verify transaction without changing artifact verification.
pub trait Lifecycle {
    fn preflight(&self, executable: &Path) -> Result<(), Error>;
    fn stop(&self) -> Result<(), Error>;
    fn start(&self) -> Result<(), Error>;
    fn verify(&self, digest: &str) -> Result<(), Error>;
    /// Read-only observation, without waiting for a stopped service to start.
    fn check(&self, digest: &str) -> Result<(), Error> {
        self.verify(digest)
    }
}

pub fn binding(name: &str) -> Result<Option<ServiceBinding>, Error> {
    let path = crate::home_dir().join("software-services.json");
    let bytes = match std::fs::read(&path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let metadata = std::fs::symlink_metadata(&path)?;
        if !metadata.is_file() || metadata.permissions().mode() & 0o077 != 0 {
            return Err("software-services.json must be owner-only".into());
        }
    }
    let bindings: BTreeMap<String, ServiceBinding> = serde_json::from_slice(&bytes)?;
    let binding = bindings.get(name).cloned();
    if let Some(binding) = &binding {
        binding.validate()?;
    }
    Ok(binding)
}

impl ServiceBinding {
    pub fn validate(&self) -> Result<(), Error> {
        if self.unit.len() > 128
            || !self.unit.ends_with(".service")
            || !self
                .unit
                .as_bytes()
                .first()
                .is_some_and(u8::is_ascii_alphanumeric)
            || !self
                .unit
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_.@".contains(&b))
            || !(1..=60).contains(&self.timeout_secs)
        {
            return Err("invalid native service binding".into());
        }
        let (request, prefix) = match &self.readiness {
            Readiness::HttpJson {
                address,
                path,
                request,
                expect,
                timeout_ms,
            } => {
                if !address.ip().is_loopback()
                    || !path.starts_with('/')
                    || path.starts_with("//")
                    || path.len() > 256
                    || path.bytes().any(|b| b.is_ascii_control())
                    || !(1..=5000).contains(timeout_ms)
                    || !request.is_object()
                    || serde_json::to_vec(request)?.len() > 4096
                    || expect.is_empty()
                    || expect.len() > 16
                    || expect.keys().any(|p| !p.starts_with('/') || p.len() > 256)
                {
                    return Err("invalid bounded local HTTP JSON health probe".into());
                }
                return Ok(());
            }
            Readiness::UnixJson {
                path,
                request,
                expect,
            } => {
                if !path.is_absolute()
                    || !request.is_object()
                    || serde_json::to_vec(request)?.len() > 4096
                    || expect.is_empty()
                    || expect.len() > 16
                    || expect
                        .keys()
                        .any(|pointer| !pointer.starts_with('/') || pointer.len() > 256)
                {
                    return Err("invalid bounded JSON health probe".into());
                }
                return Ok(());
            }
            Readiness::Unix {
                path,
                request,
                expect_prefix,
            } => {
                if !path.is_absolute() {
                    return Err("health socket must be absolute".into());
                }
                (request, expect_prefix)
            }
            Readiness::Tcp {
                address,
                request,
                expect_prefix,
            } => {
                if !address.ip().is_loopback() {
                    return Err("health TCP address must be loopback".into());
                }
                (request, expect_prefix)
            }
        };
        if request.is_empty() || request.len() > 4096 || prefix.is_empty() || prefix.len() > 4096 {
            return Err("health probe needs bounded request and expected response".into());
        }
        Ok(())
    }

    fn command(&self) -> Command {
        let mut command = Command::new("systemctl");
        if self.user_manager {
            command.arg("--user");
        }
        command
    }

    fn property(&self, property: &str) -> Result<String, Error> {
        let output = self
            .command()
            .args(["show", &self.unit, "--value"])
            .arg(format!("--property={property}"))
            .output()?;
        if !output.status.success() {
            return Err("native unit inspection failed".into());
        }
        Ok(String::from_utf8(output.stdout)?.trim().into())
    }

    fn action(&self, action: &str) -> Result<(), Error> {
        if !self
            .command()
            .args(["--no-block", action, &self.unit])
            .status()?
            .success()
        {
            return Err(format!("native unit {action} failed").into());
        }
        Ok(())
    }

    fn probe(&self, pid: &str) -> Result<(), Error> {
        if !self.owns_listener(pid)? {
            return Err("readiness listener is not owned by the supervised service".into());
        }
        let timeout = Duration::from_millis(250);
        match &self.readiness {
            Readiness::HttpJson {
                address,
                path,
                request,
                expect,
                timeout_ms,
            } => http_json_exchange(
                *address,
                path.clone(),
                request.clone(),
                expect.clone(),
                *timeout_ms,
            ),
            Readiness::UnixJson {
                path,
                request,
                expect,
            } => {
                let mut stream = std::os::unix::net::UnixStream::connect(path)?;
                stream.set_nonblocking(true)?;
                json_exchange(&mut stream, request, expect)
            }
            Readiness::Unix {
                path,
                request,
                expect_prefix,
            } => {
                let mut stream = std::os::unix::net::UnixStream::connect(path)?;
                stream.set_read_timeout(Some(timeout))?;
                stream.set_write_timeout(Some(timeout))?;
                exchange(&mut stream, request, expect_prefix)
            }
            Readiness::Tcp {
                address,
                request,
                expect_prefix,
            } => {
                let mut stream = TcpStream::connect_timeout(address, timeout)?;
                stream.set_read_timeout(Some(timeout))?;
                stream.set_write_timeout(Some(timeout))?;
                exchange(&mut stream, request, expect_prefix)
            }
        }
    }

    fn owns_listener(&self, pid: &str) -> Result<bool, Error> {
        let inodes: Vec<String> = match &self.readiness {
            Readiness::Unix { path, .. } | Readiness::UnixJson { path, .. } => {
                std::fs::read_to_string(format!("/proc/{pid}/net/unix"))?
                    .lines()
                    .filter_map(|line| {
                        let fields: Vec<_> = line.split_whitespace().collect();
                        (fields.len() >= 8 && Path::new(&fields[7..].join(" ")) == path)
                            .then(|| fields[6].to_owned())
                    })
                    .collect()
            }
            Readiness::Tcp { address, .. } | Readiness::HttpJson { address, .. } => {
                let (file, encoded) = match address.ip() {
                    std::net::IpAddr::V4(ip) => {
                        ("tcp", format!("{:08X}", u32::from_ne_bytes(ip.octets())))
                    }
                    std::net::IpAddr::V6(ip) => (
                        "tcp6",
                        ip.octets()
                            .chunks_exact(4)
                            .map(|chunk| {
                                format!("{:08X}", u32::from_ne_bytes(chunk.try_into().unwrap()))
                            })
                            .collect::<String>(),
                    ),
                };
                let endpoint = format!("{encoded}:{:04X}", address.port());
                let wildcard = format!("{}:{:04X}", "0".repeat(encoded.len()), address.port());
                std::fs::read_to_string(format!("/proc/{pid}/net/{file}"))?
                    .lines()
                    .filter_map(|line| {
                        let fields: Vec<_> = line.split_whitespace().collect();
                        (fields.len() >= 10
                            && fields[3] == "0A"
                            && (fields[1] == endpoint || fields[1] == wildcard))
                            .then(|| fields[9].to_owned())
                    })
                    .collect()
            }
        };
        for fd in std::fs::read_dir(format!("/proc/{pid}/fd"))? {
            let Ok(link) = std::fs::read_link(fd?.path()) else {
                continue;
            };
            if inodes
                .iter()
                .any(|inode| link.as_os_str() == std::ffi::OsStr::new(&format!("socket:[{inode}]")))
            {
                return Ok(true);
            }
        }
        Ok(false)
    }
}

pub fn exec_start_matches(exec_start: &str, executable: &Path) -> bool {
    let Some(executable) = executable.to_str() else {
        return false;
    };
    exec_start.split(';').any(|field| {
        field
            .trim()
            .trim_start_matches('{')
            .trim()
            .strip_prefix("path=")
            .is_some_and(|path| path.trim() == executable)
    })
}

impl Lifecycle for ServiceBinding {
    fn check(&self, digest: &str) -> Result<(), Error> {
        let pid = self.property("MainPID")?;
        if pid.is_empty()
            || pid == "0"
            || !pid.bytes().all(|b| b.is_ascii_digit())
            || self.property("ActiveState")? != "active"
        {
            return Err("native service is not active".into());
        }
        if mycelium_peer_protocol::sha256_hex(&std::fs::read(format!("/proc/{pid}/exe"))?) != digest
        {
            return Err("native service is not executing the desired signed digest".into());
        }
        self.probe(&pid)
    }
    fn preflight(&self, executable: &Path) -> Result<(), Error> {
        self.validate()?;
        if !cfg!(target_os = "linux") {
            return Err(
                "native package service activation currently requires Linux systemd".into(),
            );
        }
        if !exec_start_matches(&self.property("ExecStart")?, executable) {
            return Err("native unit must execute this package's current binary directly".into());
        }
        Ok(())
    }
    fn stop(&self) -> Result<(), Error> {
        self.action("stop")?;
        let deadline = Instant::now() + Duration::from_secs(self.timeout_secs);
        loop {
            if matches!(
                self.property("ActiveState")?.as_str(),
                "inactive" | "failed"
            ) {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err("native service did not stop within its activation deadline".into());
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }
    fn start(&self) -> Result<(), Error> {
        // Explicit stop can change failed to inactive without clearing Result
        // or systemd's restart-rate counter. Reset before rollback recovery,
        // but don't reset a never-started/unloaded unit (systemd rejects that).
        let result = self.property("Result")?;
        if needs_failed_reset(&self.property("ActiveState")?, &result) {
            self.action("reset-failed")?;
        }
        self.action("start")
    }
    fn verify(&self, digest: &str) -> Result<(), Error> {
        let deadline = Instant::now() + Duration::from_secs(self.timeout_secs);
        let mut consecutive = 0;
        let mut stable_pid = String::new();
        loop {
            let pid = self.property("MainPID")?;
            let healthy = self.check(digest).is_ok() && self.property("MainPID")? == pid;
            if healthy {
                consecutive = if stable_pid == pid {
                    consecutive + 1
                } else {
                    1
                };
                stable_pid = pid;
                if consecutive >= 3 {
                    return Ok(());
                }
            } else {
                consecutive = 0;
            }
            if Instant::now() >= deadline {
                return Err("native service failed readiness/stability check".into());
            }
            std::thread::sleep(Duration::from_millis(250));
        }
    }
}

fn exchange(stream: &mut (impl Read + Write), request: &str, prefix: &str) -> Result<(), Error> {
    stream.write_all(request.as_bytes())?;
    stream.flush()?;
    let mut reply = vec![0; prefix.len()];
    stream.read_exact(&mut reply)?;
    if reply != prefix.as_bytes() {
        return Err("health response did not match".into());
    }
    Ok(())
}

fn http_json_exchange(
    address: SocketAddr,
    path: String,
    request: serde_json::Value,
    expect: BTreeMap<String, serde_json::Value>,
    timeout_ms: u64,
) -> Result<(), Error> {
    // Lifecycle callers may already run within Tokio. Isolate the bounded HTTP
    // runtime rather than nesting block_on in the daemon runtime.
    std::thread::spawn(move || -> Result<(), Error> {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?
            .block_on(async move {
                let client = reqwest::Client::builder()
                    .no_proxy()
                    .redirect(reqwest::redirect::Policy::none())
                    .timeout(Duration::from_millis(timeout_ms))
                    .build()?;
                let mut response = client
                    .post(format!("http://{address}{path}"))
                    .json(&request)
                    .send()
                    .await?
                    .error_for_status()?;
                if !response.status().is_success() {
                    return Err("HTTP health reply must be successful without redirects".into());
                }
                let mut bytes = Vec::new();
                while let Some(chunk) = response.chunk().await? {
                    if bytes.len() + chunk.len() > 256 * 1024 {
                        return Err("HTTP health reply exceeds bound".into());
                    }
                    bytes.extend_from_slice(&chunk);
                }
                let value: serde_json::Value = serde_json::from_slice(&bytes)?;
                if !expect
                    .iter()
                    .all(|(pointer, expected)| value.pointer(pointer) == Some(expected))
                {
                    return Err("HTTP health reply did not match required values".into());
                }
                Ok(())
            })
    })
    .join()
    .map_err(|_| "HTTP health probe thread panicked")?
}

fn needs_failed_reset(active_state: &str, result: &str) -> bool {
    active_state == "failed" || (!result.is_empty() && result != "success")
}

fn json_exchange(
    stream: &mut (impl Read + Write),
    request: &serde_json::Value,
    expect: &BTreeMap<String, serde_json::Value>,
) -> Result<(), Error> {
    let deadline = Instant::now() + Duration::from_millis(250);
    let mut bytes = serde_json::to_vec(request)?;
    bytes.push(b'\n');
    let mut written = 0;
    let mut reply = Vec::new();
    loop {
        if Instant::now() >= deadline {
            return Err("JSON health probe deadline exceeded".into());
        }
        if written < bytes.len() {
            match stream.write(&bytes[written..]) {
                Ok(0) => return Err("health socket closed while writing".into()),
                Ok(count) => written += count,
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                    ) => {}
                Err(error) => return Err(error.into()),
            }
        } else {
            let mut chunk = [0; 4096];
            match stream.read(&mut chunk) {
                Ok(0) => return Err("health socket closed before JSON reply".into()),
                Ok(count) => {
                    reply.extend_from_slice(&chunk[..count]);
                    if reply.len() > 256 * 1024 {
                        return Err("JSON health reply exceeds bound".into());
                    }
                    if let Some(end) = reply.iter().position(|byte| *byte == b'\n') {
                        let value: serde_json::Value = serde_json::from_slice(&reply[..end])?;
                        if !expect
                            .iter()
                            .all(|(pointer, expected)| value.pointer(pointer) == Some(expected))
                        {
                            return Err("JSON health reply did not match required values".into());
                        }
                        return Ok(());
                    }
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                    ) => {}
                Err(error) => return Err(error.into()),
            }
        }
        std::thread::sleep(Duration::from_millis(1));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn http_health_checks_json_result_and_rejects_mismatch() {
        for (reply, success) in [
            ("{\"answer\":\"on\"}", true),
            ("{\"answer\":\"off\"}", false),
        ] {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let address = listener.local_addr().unwrap();
            let server = std::thread::spawn(move || {
                let (mut stream, _) = listener.accept().unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                let mut request = [0; 8192];
                stream.read(&mut request).unwrap();
                write!(
                    stream,
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{reply}",
                    reply.len()
                )
                .unwrap();
            });
            let expected = BTreeMap::from([("/answer".into(), serde_json::json!("on"))]);
            assert_eq!(
                http_json_exchange(
                    address,
                    "/infer".into(),
                    serde_json::json!({}),
                    expected,
                    1000
                )
                .is_ok(),
                success
            );
            server.join().unwrap();
        }
    }

    #[test]
    fn http_health_rejects_remote_redirect_path_and_unbounded_deadline() {
        let mut binding = ServiceBinding {
            unit: "umie.service".into(),
            user_manager: false,
            timeout_secs: 60,
            readiness: Readiness::HttpJson {
                address: "127.0.0.1:8096".parse().unwrap(),
                path: "/v1/systemone".into(),
                request: serde_json::json!({}),
                expect: BTreeMap::from([("/answer".into(), serde_json::json!("on"))]),
                timeout_ms: 5000,
            },
        };
        assert!(binding.validate().is_ok());
        if let Readiness::HttpJson { address, .. } = &mut binding.readiness {
            *address = "192.168.1.1:8096".parse().unwrap();
        }
        assert!(binding.validate().is_err());
        if let Readiness::HttpJson { address, path, .. } = &mut binding.readiness {
            *address = "127.0.0.1:8096".parse().unwrap();
            *path = "//other-host".into();
        }
        assert!(binding.validate().is_err());
        if let Readiness::HttpJson {
            path, timeout_ms, ..
        } = &mut binding.readiness
        {
            *path = "/infer".into();
            *timeout_ms = 5001;
        }
        assert!(binding.validate().is_err());
    }

    #[test]
    fn compute_binding_requires_real_inference() {
        let bindings: BTreeMap<String, ServiceBinding> = serde_json::from_str(include_str!(
            "../../../fungOS/compute/qemu/software-services.json"
        ))
        .unwrap();
        let binding = &bindings["umie"];
        binding.validate().unwrap();
        assert!(
            matches!(&binding.readiness, Readiness::HttpJson { path, expect, .. }
            if path == "/v1/systemone" && expect.contains_key("/answers/lighting/choice"))
        );
    }

    #[test]
    fn http_health_bounds_silent_and_oversized_responses() {
        for oversized in [false, true] {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let address = listener.local_addr().unwrap();
            let server = std::thread::spawn(move || {
                let (mut stream, _) = listener.accept().unwrap();
                let mut request = [0; 8192];
                stream.read(&mut request).unwrap();
                if oversized {
                    let body = vec![b' '; 256 * 1024 + 1];
                    let _ = write!(
                        stream,
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n",
                        body.len()
                    );
                    let _ = stream.write_all(&body);
                } else {
                    std::thread::sleep(Duration::from_millis(200));
                }
            });
            let started = Instant::now();
            assert!(http_json_exchange(
                address,
                "/infer".into(),
                serde_json::json!({}),
                BTreeMap::from([("/answer".into(), serde_json::json!("on"))]),
                if oversized { 1000 } else { 50 }
            )
            .is_err());
            assert!(started.elapsed() < Duration::from_secs(2));
            server.join().unwrap();
        }
    }

    #[test]
    fn http_health_does_not_follow_redirect_or_accept_http_failure() {
        for status in [
            "302 Found\r\nLocation: http://192.0.2.1/",
            "503 Unavailable",
        ] {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let address = listener.local_addr().unwrap();
            let server = std::thread::spawn(move || {
                let (mut stream, _) = listener.accept().unwrap();
                let mut request = [0; 8192];
                stream.read(&mut request).unwrap();
                write!(
                    stream,
                    "HTTP/1.1 {status}\r\nContent-Length: 15\r\nConnection: close\r\n\r\n{{\"answer\":\"on\"}}"
                )
                .unwrap();
            });
            assert!(http_json_exchange(
                address,
                "/infer".into(),
                serde_json::json!({}),
                BTreeMap::from([("/answer".into(), serde_json::json!("on"))]),
                1000
            )
            .is_err());
            server.join().unwrap();
        }
    }

    #[test]
    fn rollback_clears_failure_counters_even_after_explicit_stop() {
        assert!(needs_failed_reset("inactive", "exit-code"));
        assert!(needs_failed_reset("inactive", "start-limit-hit"));
        assert!(needs_failed_reset("failed", ""));
        assert!(!needs_failed_reset("inactive", "success"));
        assert!(!needs_failed_reset("inactive", ""));
    }
    #[test]
    fn qemu_edge_bindings_are_valid_native_health_contracts() {
        let bindings: BTreeMap<String, ServiceBinding> = serde_json::from_str(include_str!(
            "../../../fungOS/edge/qemu/software-services.json"
        ))
        .unwrap();
        assert_eq!(bindings.len(), 2);
        for binding in bindings.values() {
            binding.validate().unwrap();
        }
        let policy: crate::software::SoftwarePolicy = serde_json::from_str(include_str!(
            "../../../fungOS/edge/qemu/software-policy.json"
        ))
        .unwrap();
        assert_eq!(policy.rules[0].selector.all.len(), 2);
        assert_eq!(policy.rules[0].packages.len(), 2);
    }
    #[test]
    fn json_health_checks_application_result_not_just_a_listener() {
        let request = serde_json::json!({"command": "inspect"});
        let expect = BTreeMap::from([("/outcome/status".into(), serde_json::json!("ok"))]);
        let mut good = std::io::Cursor::new(b"{\"outcome\":{\"status\":\"ok\"}}\n".to_vec());
        // Duplex fixture keeps request writes separate from response reads.
        struct Duplex<'a>(&'a mut std::io::Cursor<Vec<u8>>);
        impl Read for Duplex<'_> {
            fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
                self.0.read(bytes)
            }
        }
        impl Write for Duplex<'_> {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                Ok(bytes.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        assert!(json_exchange(&mut Duplex(&mut good), &request, &expect).is_ok());
        let mut bad = std::io::Cursor::new(b"{\"outcome\":{\"status\":\"error\"}}\n".to_vec());
        assert!(json_exchange(&mut Duplex(&mut bad), &request, &expect).is_err());
    }
    #[test]
    #[cfg(target_os = "linux")]
    fn readiness_requires_the_managed_process_to_own_the_listener() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let binding = ServiceBinding {
            unit: "edge-test.service".into(),
            user_manager: false,
            readiness: Readiness::Tcp {
                address: listener.local_addr().unwrap(),
                request: "ping\n".into(),
                expect_prefix: "pong".into(),
            },
            timeout_secs: 2,
        };
        assert!(binding
            .owns_listener(&std::process::id().to_string())
            .unwrap());
        assert!(!matches!(binding.owns_listener("1"), Ok(true)));
    }
    #[test]
    fn bindings_reject_remote_probes_and_empty_health() {
        let mut binding = ServiceBinding {
            unit: "unibus.service".into(),
            user_manager: false,
            readiness: Readiness::Tcp {
                address: "127.0.0.1:9999".parse().unwrap(),
                request: "ping\n".into(),
                expect_prefix: "pong".into(),
            },
            timeout_secs: 2,
        };
        assert!(binding.validate().is_ok());
        binding.unit = "--help.service".into();
        assert!(binding.validate().is_err());
        binding.unit = "../evil.service".into();
        assert!(binding.validate().is_err());
        binding.unit = "unibus.service".into();
        binding.readiness = Readiness::Tcp {
            address: "192.168.1.1:9999".parse().unwrap(),
            request: "ping".into(),
            expect_prefix: "pong".into(),
        };
        assert!(binding.validate().is_err());
    }
    #[test]
    fn executable_match_never_accepts_an_argument_as_the_unit_binary() {
        let binary = Path::new("/state/software/unibus/current/unibus");
        assert!(exec_start_matches(
            "{ path=/state/software/unibus/current/unibus ; argv[]=unibus ; }",
            binary
        ));
        assert!(!exec_start_matches(
            "{ path=/bin/sh ; argv[]=/state/software/unibus/current/unibus ; }",
            binary
        ));
    }
}
