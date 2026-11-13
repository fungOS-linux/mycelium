//! Socket-activated ingress for the local `.myc` frontdoor.
//!
//! The service manager owns the privileged sockets. `https` moves raw bytes to
//! the TLS-terminating frontdoor and never sees a key; `http-redirect` answers
//! port 80 with a 301 and never proxies a request.
use std::{
    io::{self, BufRead, BufReader, Read, Write},
    net::{IpAddr, Shutdown, SocketAddr, TcpListener, TcpStream},
    os::fd::FromRawFd,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};

const CONNECTION_LIMIT: usize = 64;
const MAX_HEAD: usize = 16 * 1024;
const READ_TIMEOUT: Duration = Duration::from_secs(15);

fn target(value: &str) -> Result<SocketAddr, String> {
    let address: SocketAddr = value
        .parse()
        .map_err(|_| "target must be a literal socket address")?;
    if address.ip().is_unspecified() || address.ip().is_multicast() || address.port() == 443 {
        return Err("target must be an explicit local address on a non-443 port".into());
    }
    Ok(address)
}

#[cfg(target_os = "macos")]
fn activated(name: &str) -> io::Result<TcpListener> {
    use std::ffi::{c_char, c_int, c_void, CString};
    unsafe extern "C" {
        fn launch_activate_socket(
            name: *const c_char,
            descriptors: *mut *mut c_int,
            count: *mut usize,
        ) -> c_int;
        fn free(pointer: *mut c_void);
        fn close(fd: c_int) -> c_int;
    }
    let name = CString::new(name).map_err(|_| io::Error::other("socket name contains NUL"))?;
    let mut descriptors = std::ptr::null_mut();
    let mut count = 0;
    // SAFETY: static NUL-terminated name; writable out-pointers; launchd owns
    // allocation, caller frees the array and takes ownership of returned FDs.
    let error = unsafe { launch_activate_socket(name.as_ptr(), &mut descriptors, &mut count) };
    if error != 0 {
        return Err(io::Error::from_raw_os_error(error));
    }
    if descriptors.is_null() {
        return Err(io::Error::other("launchd returned no socket array"));
    }
    if count != 1 {
        // SAFETY: successful activation returns count initialized descriptors.
        unsafe {
            for &fd in std::slice::from_raw_parts(descriptors, count) {
                close(fd);
            }
            free(descriptors.cast());
        }
        return Err(io::Error::other(format!(
            "expected exactly one {name:?} socket"
        )));
    }
    // SAFETY: one valid returned descriptor; free only the array, not the FD.
    let fd = unsafe {
        let fd = *descriptors;
        free(descriptors.cast());
        fd
    };
    Ok(unsafe { TcpListener::from_raw_fd(fd) })
}

#[cfg(target_os = "linux")]
fn activated(_name: &str) -> io::Result<TcpListener> {
    let pid = std::env::var("LISTEN_PID")
        .ok()
        .and_then(|value| value.parse::<u32>().ok());
    if pid != Some(std::process::id()) || std::env::var("LISTEN_FDS").as_deref() != Ok("1") {
        return Err(io::Error::other(
            "expected one systemd socket for this process",
        ));
    }
    // SAFETY: systemd activation contract supplies the single owned FD at 3.
    Ok(unsafe { TcpListener::from_raw_fd(3) })
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn activated(_name: &str) -> io::Result<TcpListener> {
    Err(io::Error::other("unsupported socket activation platform"))
}

/// Bind one socket. `MYCELIUM_INGRESS_LISTEN` is the explicit local-testing
/// path; otherwise the socket must come from launchd or systemd.
fn listener(name: &str, port: u16) -> Result<(TcpListener, bool), String> {
    if let Ok(value) = std::env::var("MYCELIUM_INGRESS_LISTEN") {
        let address: SocketAddr = value
            .parse()
            .map_err(|_| "MYCELIUM_INGRESS_LISTEN must be a literal socket address")?;
        let listener = TcpListener::bind(address)
            .map_err(|error| format!("bind {address} for {name}: {error}"))?;
        return Ok((listener, false));
    }
    let listener =
        activated(name).map_err(|error| format!("activate the {name} socket: {error}"))?;
    let local = listener
        .local_addr()
        .map_err(|error| format!("inspect the {name} socket: {error}"))?;
    if local.port() != port {
        return Err(format!("{name} socket must bind port {port}, got {local}"));
    }
    Ok((listener, true))
}

fn forward(client: TcpStream, address: SocketAddr) -> io::Result<()> {
    let upstream = TcpStream::connect_timeout(&address, Duration::from_secs(3))?;
    for stream in [&client, &upstream] {
        stream.set_read_timeout(Some(READ_TIMEOUT))?;
        stream.set_write_timeout(Some(READ_TIMEOUT))?;
    }
    let mut client_read = client.try_clone()?;
    let mut upstream_write = upstream.try_clone()?;
    std::thread::scope(|scope| {
        let outbound = scope.spawn(move || {
            let result = io::copy(&mut client_read, &mut upstream_write);
            let _ = upstream_write.shutdown(Shutdown::Write);
            result
        });
        let mut upstream = upstream;
        let mut client = client;
        let inbound = io::copy(&mut upstream, &mut client);
        let _ = client.shutdown(Shutdown::Write);
        let outbound = outbound
            .join()
            .map_err(|_| io::Error::other("forwarding worker panicked"))?;
        inbound?;
        outbound?;
        Ok(())
    })
}

fn serve_https(listener: TcpListener, address: SocketAddr, activated: bool) -> Result<(), String> {
    let local = listener
        .local_addr()
        .map_err(|error| format!("inspect the HTTPS socket: {error}"))?;
    if activated
        && (local.port() != 443
            || local.ip().is_unspecified()
            || matches!(local.ip(), IpAddr::V4(ip) if ip.is_multicast()))
    {
        return Err("activated socket must bind an explicit local address on port 443".into());
    }
    if !address.ip().is_loopback() && address.ip() != local.ip() {
        return Err("target must be loopback or the activated local address; remote forwarding is forbidden".into());
    }
    listener
        .set_nonblocking(false)
        .map_err(|error| format!("configure HTTPS socket: {error}"))?;
    let active = Arc::new(AtomicUsize::new(0));
    for incoming in listener.incoming() {
        let client = incoming.map_err(|error| format!("accept HTTPS connection: {error}"))?;
        if active
            .try_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                (count < CONNECTION_LIMIT).then_some(count + 1)
            })
            .is_err()
        {
            eprintln!("HTTPS ingress connection limit reached");
            continue;
        }
        let active = active.clone();
        std::thread::spawn(move || {
            if let Err(error) = forward(client, address) {
                eprintln!("HTTPS ingress: {error}");
            }
            active.fetch_sub(1, Ordering::AcqRel);
        });
    }
    Ok(())
}

fn request_path(target: &str) -> Option<&str> {
    if target.starts_with('/') {
        return Some(target);
    }
    let rest = target.split_once("://")?.1;
    Some(match rest.find('/') {
        Some(index) => &rest[index..],
        None => "/",
    })
}

fn redirect_location(host: &str, path: &str) -> Option<String> {
    let host = host.trim().strip_suffix(":80").unwrap_or(host);
    if host.is_empty()
        || host.contains('/')
        || host.chars().any(|c| c.is_whitespace() || c.is_control())
    {
        return None;
    }
    if !path.starts_with('/') || path.chars().any(char::is_control) {
        return None;
    }
    Some(format!("https://{host}{path}"))
}

fn respond(
    stream: &mut TcpStream,
    status: u16,
    reason: &str,
    location: Option<&str>,
) -> io::Result<()> {
    let mut response =
        format!("HTTP/1.1 {status} {reason}\r\nContent-Length: 0\r\nConnection: close\r\n");
    if let Some(location) = location {
        response.push_str(&format!("Location: {location}\r\n"));
    }
    response.push_str("\r\n");
    stream.write_all(response.as_bytes())?;
    let _ = stream.shutdown(Shutdown::Both);
    Ok(())
}

fn handle_redirect(mut stream: TcpStream) -> io::Result<()> {
    stream.set_read_timeout(Some(READ_TIMEOUT))?;
    stream.set_write_timeout(Some(READ_TIMEOUT))?;
    // Bound the header read before allocating: a client that never sends a
    // newline must not be able to grow the buffer without limit.
    let mut reader = BufReader::new(stream.try_clone()?.take((MAX_HEAD + 1) as u64));
    let mut head = String::new();
    let mut total = 0usize;
    loop {
        let mut line = String::new();
        let read = reader.read_line(&mut line)?;
        if read == 0 {
            break;
        }
        total += read;
        if total > MAX_HEAD {
            return respond(&mut stream, 400, "Bad Request", None);
        }
        if line == "\r\n" || line == "\n" {
            break;
        }
        head.push_str(&line);
    }
    let mut lines = head.lines();
    let request = lines.next().unwrap_or_default();
    let mut parts = request.split_whitespace();
    let method = parts.next();
    let raw_target = parts.next();
    let version = parts.next();
    if method.is_none() || raw_target.is_none() || version.is_none() {
        return respond(&mut stream, 400, "Bad Request", None);
    }
    let host = lines.find_map(|line| {
        line.split_once(':')
            .filter(|(name, _)| name.eq_ignore_ascii_case("host"))
            .map(|(_, value)| value.trim())
    });
    let Some(location) = host
        .zip(raw_target.and_then(request_path))
        .and_then(|(host, path)| redirect_location(host, path))
    else {
        return respond(&mut stream, 400, "Bad Request", None);
    };
    respond(&mut stream, 301, "Moved Permanently", Some(&location))
}

fn serve_http(listener: TcpListener) -> Result<(), String> {
    listener
        .set_nonblocking(false)
        .map_err(|error| format!("configure HTTP socket: {error}"))?;
    let active = Arc::new(AtomicUsize::new(0));
    for incoming in listener.incoming() {
        let client = incoming.map_err(|error| format!("accept HTTP connection: {error}"))?;
        if active
            .try_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                (count < CONNECTION_LIMIT).then_some(count + 1)
            })
            .is_err()
        {
            eprintln!("HTTP ingress connection limit reached");
            continue;
        }
        let active = active.clone();
        std::thread::spawn(move || {
            if let Err(error) = handle_redirect(client) {
                eprintln!("HTTP ingress: {error}");
            }
            active.fetch_sub(1, Ordering::AcqRel);
        });
    }
    Ok(())
}

fn run() -> Result<(), String> {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    match args.as_slice() {
        [mode] if mode == "http-redirect" => {
            let (listener, _) = listener("HTTP", 80)?;
            serve_http(listener)
        }
        [mode, flag, value] if mode == "https" && flag == "--target" => {
            let address = target(value)?;
            let (listener, activated) = listener("HTTPS", 443)?;
            serve_https(listener, address, activated)
        }
        _ => Err("usage: mycelium-ingress https --target 127.0.0.1:8443 | mycelium-ingress http-redirect (socket activation required)".into()),
    }
}

fn main() {
    if let Err(error) = run() {
        eprintln!("mycelium-ingress: {error}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn https_target_is_strictly_local() {
        assert!(target("127.0.0.1:8443").is_ok());
        assert!(target("[::1]:8443").is_ok());
        for invalid in ["0.0.0.0:8443", "127.0.0.1:443", "localhost:8443"] {
            assert!(target(invalid).is_err());
        }
        assert!(target("127.0.0.1:9443").is_ok());
    }

    #[test]
    fn redirect_keeps_the_path_and_strips_the_default_port() {
        assert_eq!(
            redirect_location("ai.myc:80", "/v1/chat?q=1").as_deref(),
            Some("https://ai.myc/v1/chat?q=1")
        );
        assert_eq!(
            redirect_location("[::1]:80", "/").as_deref(),
            Some("https://[::1]/")
        );
    }

    #[test]
    fn redirect_rejects_a_missing_or_unsafe_host() {
        assert!(redirect_location("", "/").is_none());
        assert!(redirect_location("ai.myc/path", "/").is_none());
        assert!(redirect_location("ai.myc\r\nX: y", "/").is_none());
        assert!(redirect_location("ai.myc", "no-slash").is_none());
        assert!(redirect_location("ai.myc", "/\r\nX: y").is_none());
    }

    #[test]
    fn absolute_form_target_keeps_its_path() {
        assert_eq!(request_path("http://ai.myc/v1?q=1"), Some("/v1?q=1"));
        assert_eq!(request_path("http://ai.myc"), Some("/"));
        assert_eq!(request_path("/v1"), Some("/v1"));
    }

    #[test]
    fn transparent_bytes_round_trip() {
        let backend = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = backend.local_addr().unwrap();
        let front = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut client = TcpStream::connect(front.local_addr().unwrap()).unwrap();
        std::thread::scope(|scope| {
            scope.spawn(|| {
                let (mut stream, _) = backend.accept().unwrap();
                let mut bytes = [0; 4];
                stream.read_exact(&mut bytes).unwrap();
                assert_eq!(&bytes, b"tls!");
                stream.write_all(b"okay").unwrap();
            });
            scope.spawn(|| {
                let (stream, _) = front.accept().unwrap();
                forward(stream, address).unwrap();
            });
            client.write_all(b"tls!").unwrap();
            client.shutdown(Shutdown::Write).unwrap();
            let mut bytes = Vec::new();
            client.read_to_end(&mut bytes).unwrap();
            assert_eq!(&bytes, b"okay");
        });
    }

    #[test]
    fn redirect_answers_with_a_301() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let handle = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            handle_redirect(stream).unwrap();
        });
        let mut client = TcpStream::connect(address).unwrap();
        client
            .write_all(b"GET /hello?x=1 HTTP/1.1\r\nHost: ai.myc:80\r\n\r\n")
            .unwrap();
        let mut response = String::new();
        client.read_to_string(&mut response).unwrap();
        assert!(response.starts_with("HTTP/1.1 301"), "{response}");
        assert!(
            response.contains("Location: https://ai.myc/hello?x=1"),
            "{response}"
        );
        handle.join().unwrap();
    }

    #[test]
    fn redirect_rejects_an_oversized_head() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let handle = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            handle_redirect(stream).unwrap();
        });
        let mut client = TcpStream::connect(address).unwrap();
        let mut request = b"GET / HTTP/1.1\r\nHost: ai.myc\r\nX: ".to_vec();
        request.extend(std::iter::repeat(b'a').take(MAX_HEAD));
        request.extend_from_slice(b"\r\n\r\n");
        client.write_all(&request).unwrap();
        let mut response = String::new();
        client.read_to_string(&mut response).unwrap();
        assert!(response.starts_with("HTTP/1.1 400"), "{response}");
        handle.join().unwrap();
    }

    #[test]
    fn redirect_rejects_a_request_without_a_host() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let handle = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            handle_redirect(stream).unwrap();
        });
        let mut client = TcpStream::connect(address).unwrap();
        client.write_all(b"GET /hello HTTP/1.1\r\n\r\n").unwrap();
        let mut response = String::new();
        client.read_to_string(&mut response).unwrap();
        assert!(response.starts_with("HTTP/1.1 400"), "{response}");
        handle.join().unwrap();
    }
}
