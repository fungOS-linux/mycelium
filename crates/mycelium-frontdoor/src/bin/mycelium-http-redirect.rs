//! Plain-HTTP redirect to the TLS `*.myc` frontdoor.
//!
//! The frontdoor is intentionally TLS-only. This listener exists so a browser or
//! a `curl http://ai.myc/...` lands on the same URL over HTTPS instead of a
//! connection refused. It never proxies a request: it only returns 301.
//!
//! Under launchd/systemd it receives the privileged `HTTP` socket from the
//! service manager, exactly like `mycelium-https-forwarder` receives `HTTPS`.
//! For local testing, `MYCELIUM_HTTP_REDIRECT_LISTEN` binds an explicit address.

use axum::body::Body;
use axum::http::{header, HeaderValue, Request, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use axum::Router;
use std::io;
use std::net::SocketAddr;
use tokio::net::TcpListener;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async move {
        let listener = listener()?;
        let app = Router::new().fallback(redirect);
        axum::serve(listener, app).await
    })?;
    Ok(())
}

async fn redirect(request: Request<Body>) -> Response {
    let host = request
        .headers()
        .get(header::HOST)
        .and_then(|value| value.to_str().ok());
    let Some(location) = redirect_target(host, request.uri()) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let Ok(location) = HeaderValue::from_str(&location) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let mut response = StatusCode::MOVED_PERMANENTLY.into_response();
    response.headers_mut().insert(header::LOCATION, location);
    response
}

fn redirect_target(host: Option<&str>, uri: &Uri) -> Option<String> {
    let host = host?.trim();
    let host = host.strip_suffix(":80").unwrap_or(host);
    if host.is_empty() || host.contains('/') || host.contains(char::is_whitespace) {
        return None;
    }
    let path = uri
        .path_and_query()
        .map(|value| value.as_str())
        .unwrap_or("/");
    Some(format!("https://{host}{path}"))
}

fn listener() -> io::Result<TcpListener> {
    if let Ok(value) = std::env::var("MYCELIUM_HTTP_REDIRECT_LISTEN") {
        let address: SocketAddr = value
            .parse()
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
        let listener = std::net::TcpListener::bind(address)?;
        listener.set_nonblocking(true)?;
        return TcpListener::from_std(listener);
    }
    #[cfg(target_os = "macos")]
    if let Some(listener) = activated("HTTP")? {
        return Ok(listener);
    }
    #[cfg(target_os = "linux")]
    if let Some(listener) = systemd_socket()? {
        return Ok(listener);
    }
    let listener = std::net::TcpListener::bind("127.0.0.1:8080")?;
    listener.set_nonblocking(true)?;
    TcpListener::from_std(listener)
}

#[cfg(target_os = "macos")]
fn activated(name: &str) -> io::Result<Option<TcpListener>> {
    use std::ffi::{c_char, c_int, c_void, CString};
    use std::os::fd::FromRawFd;

    unsafe extern "C" {
        fn launch_activate_socket(
            name: *const c_char,
            descriptors: *mut *mut c_int,
            count: *mut usize,
        ) -> c_int;
        fn free(pointer: *mut c_void);
        fn close(fd: c_int) -> c_int;
    }

    let name = CString::new(name).map_err(|_| io::Error::other("invalid socket name"))?;
    let mut descriptors = std::ptr::null_mut();
    let mut count = 0;
    // SAFETY: name is NUL-terminated; the out-pointers are writable; launchd
    // owns the returned array and the caller frees it after taking the FD.
    let error = unsafe { launch_activate_socket(name.as_ptr(), &mut descriptors, &mut count) };
    if error != 0 {
        let error = io::Error::from_raw_os_error(error);
        if error.kind() == io::ErrorKind::NotFound {
            return Ok(None);
        }
        return Err(error);
    }
    if descriptors.is_null() {
        return Err(io::Error::other("launchd returned no socket array"));
    }
    if count != 1 {
        // SAFETY: successful activation returns `count` initialized descriptors.
        unsafe {
            for &fd in std::slice::from_raw_parts(descriptors, count) {
                close(fd);
            }
            free(descriptors.cast());
        }
        return Err(io::Error::other("expected exactly one HTTP socket"));
    }
    // SAFETY: one valid returned descriptor; free only the array, not the FD.
    let fd = unsafe {
        let fd = *descriptors;
        free(descriptors.cast());
        fd
    };
    let listener = unsafe { std::net::TcpListener::from_raw_fd(fd) };
    listener.set_nonblocking(true)?;
    Ok(Some(TcpListener::from_std(listener)?))
}

#[cfg(target_os = "linux")]
fn systemd_socket() -> io::Result<Option<TcpListener>> {
    use std::os::fd::FromRawFd;

    let pid = std::env::var("LISTEN_PID")
        .ok()
        .and_then(|value| value.parse::<u32>().ok());
    if pid != Some(std::process::id()) || std::env::var("LISTEN_FDS").as_deref() != Ok("1") {
        return Ok(None);
    }
    // SAFETY: systemd's socket-activation contract supplies one owned FD at 3.
    let listener = unsafe { std::net::TcpListener::from_raw_fd(3) };
    listener.set_nonblocking(true)?;
    Ok(Some(TcpListener::from_std(listener)?))
}

#[cfg(test)]
mod tests {
    use super::{redirect, redirect_target};
    use axum::body::Body;
    use axum::http::{header, Request, StatusCode, Uri};

    #[test]
    fn keeps_the_path_and_query() {
        let uri: Uri = "/v1/models?limit=1".parse().unwrap();
        assert_eq!(
            redirect_target(Some("ai.myc"), &uri).as_deref(),
            Some("https://ai.myc/v1/models?limit=1")
        );
    }

    #[test]
    fn strips_the_default_http_port() {
        let uri: Uri = "/".parse().unwrap();
        assert_eq!(
            redirect_target(Some("ai.myc:80"), &uri).as_deref(),
            Some("https://ai.myc/")
        );
    }

    #[test]
    fn refuses_a_missing_host() {
        let uri: Uri = "/".parse().unwrap();
        assert_eq!(redirect_target(None, &uri), None);
    }

    #[tokio::test]
    async fn answers_with_a_301_and_a_location() {
        let request = Request::builder()
            .uri("/v1/models")
            .header(header::HOST, "ai.myc")
            .body(Body::empty())
            .unwrap();
        let response = redirect(request).await;
        assert_eq!(response.status(), StatusCode::MOVED_PERMANENTLY);
        assert_eq!(
            response.headers().get(header::LOCATION).unwrap(),
            "https://ai.myc/v1/models"
        );
    }
}
