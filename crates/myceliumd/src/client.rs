use std::time::{Duration, Instant};

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufStream};
use tokio::net::UnixStream;

use crate::protocol::{Request, Response};

pub struct Client {
    stream: BufStream<UnixStream>,
}

impl Client {
    /// Connect to the daemon; if the socket is dead/absent, bring it up --
    /// through the host's supervisor when this host has one -- and wait for it
    /// to answer.
    pub async fn connect() -> Result<Self, ClientError> {
        match Self::try_connect().await {
            Ok(c) => Ok(c),
            Err(e @ ClientError::Connect(_)) => {
                if std::env::var_os("MYCELIUM_NO_AUTOSTART").is_some() {
                    return Err(e);
                }
                if let Some(started) = start_supervised() {
                    started?;
                } else {
                    Self::spawn_daemon()?;
                }
                let deadline = Instant::now() + Duration::from_secs(15);
                loop {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    match Self::try_connect().await {
                        Ok(c) => return Ok(c),
                        Err(_) if Instant::now() > deadline => {
                            return Err(ClientError::DaemonUnresponsive)
                        }
                        Err(_) => {}
                    }
                }
            }
            Err(e) => Err(e),
        }
    }

    pub async fn try_connect() -> Result<Self, ClientError> {
        let socket = crate::socket_path();
        let stream = UnixStream::connect(&socket)
            .await
            .map_err(ClientError::Connect)?;
        Ok(Self {
            stream: BufStream::new(stream),
        })
    }

    /// PID of the process answering this Unix socket, when the OS exposes it.
    pub fn peer_pid(&self) -> Result<Option<u32>, ClientError> {
        self.stream
            .get_ref()
            .peer_cred()
            .map(|cred| cred.pid().and_then(|pid| u32::try_from(pid).ok()))
            .map_err(ClientError::Io)
    }

    /// Detached spawn: process group leader, logs to $MYCELIUM_HOME.
    /// Runs `self <exe> _serve` so the same binary can host the daemon
    /// (the CLI and daemon ship together; PATH never consulted).
    pub fn spawn_daemon() -> Result<(), ClientError> {
        let exe = std::env::current_exe().map_err(|e| ClientError::Spawn(e.to_string()))?;
        if cfg!(target_os = "linux")
            && std::fs::canonicalize(&exe).map_err(ClientError::Io)?
                == std::path::Path::new("/usr/bin/mycelium")
        {
            return Err(ClientError::Spawn("package-owned Mycelium must run through its enrolled systemd service; use sudo mycelium setup --packaged, not an unmanaged daemon".into()));
        }
        // systemd sets INVOCATION_ID for every process it starts. A unit that
        // reaches this point forgot `MYCELIUM_NO_AUTOSTART`, so spawning here
        // would fork a daemon nothing supervises -- and whatever unit got there
        // first wins `myceliumd.sock`, leaving the real service crash-looping on
        // "a myceliumd is already listening". Refuse instead of racing.
        if cfg!(target_os = "linux") && std::env::var_os("INVOCATION_ID").is_some() {
            return Err(ClientError::Spawn("refusing to spawn an unsupervised daemon from inside a systemd unit; set MYCELIUM_NO_AUTOSTART=1 and start mycelium.service instead".into()));
        }
        let home = crate::home_dir();
        std::fs::create_dir_all(&home).map_err(|e| ClientError::Spawn(e.to_string()))?;
        let log = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(home.join("daemon.log"))
            .map_err(|e| ClientError::Spawn(e.to_string()))?;
        let log_err = log
            .try_clone()
            .map_err(|e| ClientError::Spawn(e.to_string()))?;
        use std::os::unix::process::CommandExt;
        let mut cmd = std::process::Command::new(exe);
        cmd.arg("_serve")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::from(log))
            .stderr(std::process::Stdio::from(log_err));
        cmd.process_group(0);
        cmd.spawn().map_err(|e| ClientError::Spawn(e.to_string()))?;
        Ok(())
    }

    pub async fn request(&mut self, req: &Request) -> Result<Response, ClientError> {
        // Publishing a local artifact must not wait forever behind daemon
        // startup or mesh work. A timeout is not evidence that a write failed.
        let deadline = match req {
            Request::Hello => Some(Duration::from_secs(10)),
            Request::PackagePublish { .. } => Some(Duration::from_secs(60)),
            _ => None,
        };
        if let Some(deadline) = deadline {
            return self.request_with_deadline(req, deadline).await;
        }
        self.request_io(req).await
    }

    async fn request_with_deadline(
        &mut self,
        req: &Request,
        deadline: Duration,
    ) -> Result<Response, ClientError> {
        match tokio::time::timeout(deadline, self.request_io(req)).await {
            Ok(result) => result,
            Err(_) => {
                // Do not allow a late response to be mistaken for the next RPC.
                let _ = self.stream.shutdown().await;
                Err(ClientError::Io(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "daemon RPC timed out; outcome is unknown: check the package catalog before retrying a publication",
                )))
            }
        }
    }

    async fn request_io(&mut self, req: &Request) -> Result<Response, ClientError> {
        let line = serde_json::to_string(req).expect("Request is serializable");
        self.stream.write_all(line.as_bytes()).await?;
        self.stream.write_all(b"\n").await?;
        self.stream.flush().await?;
        let mut buf = String::new();
        let n = self.stream.read_line(&mut buf).await?;
        if n == 0 {
            return Err(ClientError::Protocol("daemon closed the connection".into()));
        }
        serde_json::from_str(&buf).map_err(|e| ClientError::Protocol(e.to_string()))
    }

    /// Send, and unwrap ok/error into a value error.
    pub async fn call(&mut self, req: &Request) -> Result<serde_json::Value, ClientError> {
        let resp = self.request(req).await?;
        if resp.ok {
            Ok(resp.result.unwrap_or(serde_json::Value::Null))
        } else {
            Err(ClientError::Rpc {
                message: resp.error.unwrap_or_else(|| "unspecified".into()),
                kind: resp.kind.unwrap_or_else(|| "daemon".into()),
            })
        }
    }
}

/// Ask the host's service manager to start the peer, when this host has one.
///
/// An enrolled host already has a supervised peer. A client that forks its own
/// daemon races that supervisor for `myceliumd.sock`: the loser exits and the
/// supervisor restarts it on a timer, so every CLI call re-runs the contest and
/// one of the two units sits in a restart loop. Starting the unit is the only
/// path that leaves exactly one daemon owning the socket.
fn start_supervised() -> Option<Result<(), ClientError>> {
    if cfg!(target_os = "linux") {
        let loaded = std::process::Command::new("systemctl")
            .args([
                "--user",
                "show",
                "mycelium",
                "--property=LoadState",
                "--value",
            ])
            .output()
            .ok()?;
        if String::from_utf8_lossy(&loaded.stdout).trim() != "loaded" {
            return None;
        }
        return Some(system_ok(
            std::process::Command::new("systemctl")
                .args(["--user", "start", "mycelium"])
                .output(),
        ));
    }
    if cfg!(target_os = "macos") {
        let uid = uid()?;
        let domain = format!("gui/{uid}/dev.fpl.mycelium");
        let present = std::process::Command::new("launchctl")
            .args(["print", &domain])
            .output()
            .ok()?;
        if !present.status.success() {
            return None;
        }
        return Some(system_ok(
            std::process::Command::new("launchctl")
                .args(["kickstart", "-k", &domain])
                .output(),
        ));
    }
    None
}

fn uid() -> Option<String> {
    let out = std::process::Command::new("id").arg("-u").output().ok()?;
    let uid = String::from_utf8_lossy(&out.stdout).trim().to_string();
    (!uid.is_empty()).then_some(uid)
}

fn system_ok(output: std::io::Result<std::process::Output>) -> Result<(), ClientError> {
    let output = output.map_err(|e| ClientError::Spawn(e.to_string()))?;
    if output.status.success() {
        return Ok(());
    }
    Err(ClientError::Spawn(
        String::from_utf8_lossy(&output.stderr).trim().to_string(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn unresponsive_daemon_has_a_deadline_and_connection_is_not_reused() {
        let (stream, _silent_daemon) = UnixStream::pair().unwrap();
        let mut client = Client {
            stream: BufStream::new(stream),
        };
        let error = client
            .request_with_deadline(&Request::Hello, Duration::from_millis(20))
            .await
            .unwrap_err();
        assert!(
            matches!(error, ClientError::Io(ref error) if error.kind() == std::io::ErrorKind::TimedOut)
        );
        assert!(error.to_string().contains("outcome is unknown"));
        assert!(client
            .request_with_deadline(&Request::Hello, Duration::from_millis(20))
            .await
            .is_err());
    }

    #[test]
    fn a_failed_supervisor_command_reports_its_stderr() {
        let failed = std::process::Command::new("sh")
            .args(["-c", "echo nope >&2; exit 3"])
            .output()
            .unwrap();
        match system_ok(Ok(failed)) {
            Err(ClientError::Spawn(message)) => assert_eq!(message, "nope"),
            other => panic!("expected a spawn error, got {other:?}"),
        }
        let ok = std::process::Command::new("true").output().unwrap();
        assert!(system_ok(Ok(ok)).is_ok());
    }
}

#[derive(Debug)]
pub enum ClientError {
    Connect(std::io::Error),
    Io(std::io::Error),
    Protocol(String),
    Spawn(String),
    DaemonUnresponsive,
    Rpc { message: String, kind: String },
}

impl From<std::io::Error> for ClientError {
    fn from(e: std::io::Error) -> Self {
        ClientError::Io(e)
    }
}

impl std::fmt::Display for ClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ClientError::Connect(e) => write!(
                f,
                "cannot reach myceliumd socket ({}): {e}",
                crate::socket_path().display()
            ),
            ClientError::Io(e) => write!(f, "socket io: {e}"),
            ClientError::Protocol(e) => write!(f, "protocol error: {e}"),
            ClientError::Spawn(e) => write!(f, "could not spawn myceliumd: {e}"),
            ClientError::DaemonUnresponsive => {
                write!(
                    f,
                    "myceliumd did not come up within 5s (see ~/.mycelium/daemon.log)"
                )
            }
            ClientError::Rpc { message, kind } => write!(f, "[{kind}] {message}"),
        }
    }
}
