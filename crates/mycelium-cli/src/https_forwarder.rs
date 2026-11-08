//! TLS-transparent, socket-activated ingress. The service manager owns port 443;
//! this process runs unprivileged, has no keys and cannot authorize requests.
use std::{
    io,
    net::{IpAddr, SocketAddr, TcpListener, TcpStream},
    os::fd::FromRawFd,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};

fn target(value: &str) -> Result<SocketAddr, String> {
    let address: SocketAddr = value
        .parse()
        .map_err(|_| "target must be a literal socket address")?;
    if address.ip().is_unspecified() || address.ip().is_multicast() || address.port() != 8443 {
        return Err("target must be an explicit local address on port 8443".into());
    }
    Ok(address)
}

#[cfg(target_os = "macos")]
fn listener() -> io::Result<TcpListener> {
    use std::ffi::{c_char, c_int, c_void};
    unsafe extern "C" {
        fn launch_activate_socket(
            name: *const c_char,
            descriptors: *mut *mut c_int,
            count: *mut usize,
        ) -> c_int;
        fn free(pointer: *mut c_void);
        fn close(fd: c_int) -> c_int;
    }
    let mut descriptors = std::ptr::null_mut();
    let mut count = 0;
    // SAFETY: static NUL-terminated name; writable out-pointers; launchd owns
    // allocation, caller frees the array and takes ownership of returned FDs.
    let error = unsafe { launch_activate_socket(c"HTTPS".as_ptr(), &mut descriptors, &mut count) };
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
        return Err(io::Error::other("expected exactly one HTTPS socket"));
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
fn listener() -> io::Result<TcpListener> {
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
fn listener() -> io::Result<TcpListener> {
    Err(io::Error::other("unsupported socket activation platform"))
}

fn forward(client: TcpStream, address: SocketAddr) -> io::Result<()> {
    let upstream = TcpStream::connect_timeout(&address, Duration::from_secs(3))?;
    for stream in [&client, &upstream] {
        stream.set_read_timeout(Some(Duration::from_secs(15)))?;
        stream.set_write_timeout(Some(Duration::from_secs(15)))?;
    }
    let mut client_read = client.try_clone()?;
    let mut upstream_write = upstream.try_clone()?;
    std::thread::scope(|scope| {
        let outbound = scope.spawn(move || {
            let result = io::copy(&mut client_read, &mut upstream_write);
            let _ = upstream_write.shutdown(std::net::Shutdown::Write);
            result
        });
        let mut upstream = upstream;
        let mut client = client;
        let inbound = io::copy(&mut upstream, &mut client);
        let _ = client.shutdown(std::net::Shutdown::Write);
        let outbound = outbound
            .join()
            .map_err(|_| io::Error::other("forwarding worker panicked"))?;
        inbound?;
        outbound?;
        Ok(())
    })
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    if args.len() != 2 || args[0] != "--target" {
        return Err(
            "usage: mycelium-https-forwarder --target 127.0.0.1:8443 (socket activation required)"
                .into(),
        );
    }
    let address = target(&args[1])?;
    let listener = listener()?;
    let local = listener.local_addr()?;
    if local.port() != 443
        || matches!(local.ip(), IpAddr::V4(ip) if ip.is_multicast())
        || local.ip().is_unspecified()
    {
        return Err("activated socket must bind an explicit local address on port 443".into());
    }
    if !address.ip().is_loopback() && address.ip() != local.ip() {
        return Err("target must be loopback or the activated local address; remote forwarding is forbidden".into());
    }
    listener.set_nonblocking(false)?;
    let active = Arc::new(AtomicUsize::new(0));
    for incoming in listener.incoming() {
        let client = incoming?;
        if active
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                (count < 64).then_some(count + 1)
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

fn main() {
    if let Err(error) = run() {
        eprintln!("mycelium-https-forwarder: {error}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn target_is_strictly_local() {
        assert!(target("127.0.0.1:8443").is_ok());
        assert!(target("[::1]:8443").is_ok());
        for invalid in ["0.0.0.0:8443", "127.0.0.1:443", "localhost:8443"] {
            assert!(target(invalid).is_err());
        }
    }
    #[test]
    fn transparent_bytes_round_trip() {
        use std::io::{Read, Write};
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
            client.shutdown(std::net::Shutdown::Write).unwrap();
            let mut bytes = Vec::new();
            client.read_to_end(&mut bytes).unwrap();
            assert_eq!(&bytes, b"okay");
        });
    }
}
