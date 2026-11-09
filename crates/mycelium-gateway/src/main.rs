use std::net::SocketAddr;
use std::path::PathBuf;

fn main() {
    if let Err(error) = run_sync() {
        eprintln!("mycelium-gateway: {error}");
        std::process::exit(1);
    }
}

fn run_sync() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let config = args::parse(std::env::args().skip(1).collect())?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    runtime.block_on(mycelium_gateway::server::run_with_options(
        config.listen,
        config.routes,
        config.token_file,
        config.reload_secs,
        config.tls.map(|tls| (tls.cert, tls.key)),
        config.usage,
    ))
}

#[derive(Clone, Debug)]
struct Config {
    listen: SocketAddr,
    routes: Option<PathBuf>,
    token_file: Option<PathBuf>,
    reload_secs: u64,
    tls: Option<TlsFiles>,
    usage: Option<PathBuf>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct TlsFiles {
    cert: PathBuf,
    key: PathBuf,
}

mod args {
    use super::{Config, TlsFiles};
    use std::net::SocketAddr;
    use std::path::PathBuf;

    pub fn parse(argv: Vec<String>) -> Result<Config, Box<dyn std::error::Error + Send + Sync>> {
        let mut listen = "127.0.0.1:8080".parse::<SocketAddr>()?;
        let mut routes = None;
        let mut token_file = None;
        let mut reload_secs = 1;
        let mut tls_cert = None;
        let mut tls_key = None;
        let mut usage = None;
        let mut index = 0;

        while index < argv.len() {
            match argv[index].as_str() {
                "--listen" => {
                    index += 1;
                    let value = argv.get(index).ok_or("--listen requires an address")?;
                    listen = value
                        .parse()
                        .map_err(|error| format!("invalid listen address: {error}"))?;
                }
                "--routes" => {
                    index += 1;
                    routes = Some(PathBuf::from(
                        argv.get(index).ok_or("--routes requires a path")?,
                    ));
                }
                "--token-file" => {
                    index += 1;
                    token_file = Some(PathBuf::from(
                        argv.get(index).ok_or("--token-file requires a path")?,
                    ));
                }
                "--reload-secs" => {
                    index += 1;
                    reload_secs = argv
                        .get(index)
                        .ok_or("--reload-secs requires a number")?
                        .parse()
                        .map_err(|error| format!("invalid reload seconds: {error}"))?;
                }
                "--tls-cert" => {
                    index += 1;
                    tls_cert = Some(PathBuf::from(
                        argv.get(index).ok_or("--tls-cert requires a path")?,
                    ));
                }
                "--tls-key" => {
                    index += 1;
                    tls_key = Some(PathBuf::from(
                        argv.get(index).ok_or("--tls-key requires a path")?,
                    ));
                }
                "--usage" => {
                    index += 1;
                    usage = Some(PathBuf::from(
                        argv.get(index).ok_or("--usage requires a path")?,
                    ));
                }
                "--help" | "-h" => {
                    print_usage();
                    std::process::exit(0);
                }
                other => return Err(format!("unknown argument: {other}").into()),
            }
            index += 1;
        }

        Ok(Config {
            listen,
            routes,
            token_file,
            reload_secs,
            tls: match (tls_cert, tls_key) {
                (Some(cert), Some(key)) => Some(TlsFiles { cert, key }),
                (None, None) => None,
                _ => return Err("--tls-cert and --tls-key must be provided together".into()),
            },
            usage,
        })
    }

    fn print_usage() {
        println!(
            "mycelium-gateway --listen 127.0.0.1:8080 [--routes gateway.json] \
             [--token-file TOKEN] [--reload-secs 1] [--usage usage.json] \
             [--tls-cert CERT --tls-key KEY]"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(values: &[&str]) -> Result<Config, Box<dyn std::error::Error + Send + Sync>> {
        args::parse(values.iter().map(|value| value.to_string()).collect())
    }

    #[test]
    fn accepts_tls_only_as_a_pair() {
        let config = parse(&[
            "--listen",
            "127.0.0.1:8443",
            "--tls-cert",
            "server.pem",
            "--tls-key",
            "server-key.pem",
        ])
        .unwrap();
        assert_eq!(
            config.tls,
            Some(TlsFiles {
                cert: PathBuf::from("server.pem"),
                key: PathBuf::from("server-key.pem")
            })
        );
        assert!(parse(&["--listen", "127.0.0.1:8443", "--tls-cert", "server.pem"]).is_err());
        assert!(parse(&["--listen", "127.0.0.1:8443", "--tls-key", "server-key.pem"]).is_err());
    }

    #[test]
    fn defaults_to_loopback_http() {
        let config = parse(&[]).unwrap();
        assert_eq!(config.listen, "127.0.0.1:8080".parse().unwrap());
        assert_eq!(config.tls, None);
        assert_eq!(config.usage, None);
    }

    #[test]
    fn records_usage_only_when_asked() {
        let config = parse(&["--usage", "/home/u/.mycelium/gateway/usage.json"]).unwrap();
        assert_eq!(
            config.usage,
            Some(PathBuf::from("/home/u/.mycelium/gateway/usage.json"))
        );
        assert!(parse(&["--usage"]).is_err());
    }
}
