use std::path::{Path, PathBuf};


use mycelium_gateway::server::run;

fn main() {
    if let Err(error) = run_sync() {
        eprintln!("mycelium-gateway: {error}");
        std::process::exit(1);
    }
}

fn run_sync() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let config = args::parse(std::env::args().skip(1).collect())?;
    if let Some(generate_dir) = &config.generated_cert_dir {
        let cert_path = generate_dir.join("server.crt");
        let key_path = generate_dir.join("server.key");
        if config.tls_cert.is_some() || config.tls_key.is_some() {
            return Err("--generate-cert cannot be combined with --tls-cert/--tls-key".into());
        }
        generate_cert(&cert_path, &key_path)?;
    }

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    runtime.block_on(run(
        config.listen,
        config.routes,
        config.required_token_file.as_ref().and_then(|path| std::fs::read_to_string(path).ok()).map(|value| value.trim().to_owned()).filter(|value| !value.is_empty()),
        config.reload_secs,
    ))
}

#[derive(Clone, Debug)]
struct Config {
    listen: std::net::SocketAddr,
    routes: Option<PathBuf>,
    required_token_file: Option<PathBuf>,
    reload_secs: u64,
    tls_cert: Option<PathBuf>,
    tls_key: Option<PathBuf>,
    generated_cert_dir: Option<PathBuf>,
}

mod args {
    use super::Config;
    use std::net::SocketAddr;
    use std::path::PathBuf;

    pub fn parse(argv: Vec<String>) -> Result<Config, Box<dyn std::error::Error + Send + Sync>> {
        let mut listen = "127.0.0.1:8080".parse::<SocketAddr>()?;
        let mut routes = None;
        let mut required_token_file = None;
        let mut reload_secs = 1;
        let mut tls_cert = None;
        let mut tls_key = None;
        let mut generated_cert_dir = None;

        let mut index = 0;
        while index < argv.len() {
            match argv[index].as_str() {
                "--listen" => {
                    index += 1;
                    if index >= argv.len() {
                        return Err("--listen requires an address".into());
                    }
                    listen = argv[index]
                        .parse()
                        .map_err(|error| format!("invalid listen address: {error}"))?;
                }
                "--routes" => {
                    index += 1;
                    if index >= argv.len() {
                        return Err("--routes requires a path".into());
                    }
                    routes = Some(PathBuf::from(&argv[index]));
                }
                "--token-file" => {
                    index += 1;
                    if index >= argv.len() {
                        return Err("--token-file requires a path".into());
                    }
                    required_token_file = Some(PathBuf::from(&argv[index]));
                }
                "--reload-secs" => {
                    index += 1;
                    if index >= argv.len() {
                        return Err("--reload-secs requires a number".into());
                    }
                    reload_secs = argv[index]
                        .parse()
                        .map_err(|error| format!("invalid reload seconds: {error}"))?;
                }
                "--tls-cert" => {
                    index += 1;
                    if index >= argv.len() {
                        return Err("--tls-cert requires a path".into());
                    }
                    tls_cert = Some(PathBuf::from(&argv[index]));
                }
                "--tls-key" => {
                    index += 1;
                    if index >= argv.len() {
                        return Err("--tls-key requires a path".into());
                    }
                    tls_key = Some(PathBuf::from(&argv[index]));
                }
                "--generate-cert" => {
                    index += 1;
                    if index >= argv.len() {
                        return Err("--generate-cert requires a directory".into());
                    }
                    generated_cert_dir = Some(PathBuf::from(&argv[index]));
                }
                "--help" | "-h" => {
                    print_usage();
                    std::process::exit(0);
                }
                other => {
                    return Err(format!("unknown argument: {other}").into());
                }
            }
            index += 1;
        }

        if generated_cert_dir.is_some() && tls_cert.is_some() {
            generated_cert_dir = None;
        }
        Ok(Config {
            listen,
            routes,
            required_token_file,
            reload_secs,
            tls_cert,
            tls_key,
            generated_cert_dir,
        })
    }

    fn print_usage() {
        println!(
            "mycelium-gateway --listen 127.0.0.1:8080 [--routes gateway.json] \
             [--token-file TOKEN] [--reload-secs 1] [--tls-cert CERT --tls-key KEY] \
             [--generate-cert DIR]"
        );
    }
}

fn generate_cert(cert_path: &Path, key_path: &Path) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use rcgen::{generate_simple_self_signed, CertifiedKey};
    let subject_alternative_names = vec![
        "localhost".to_owned(),
        "ai.myc".to_owned(),
        "mcp.myc".to_owned(),
        "home.myc".to_owned(),
        "webhook.myc".to_owned(),
        "*.myc".to_owned(),
    ];
    let CertifiedKey { cert, key_pair } = generate_simple_self_signed(subject_alternative_names)
        .map_err(|error| format!("generate self-signed certificate: {error}"))?;
    std::fs::create_dir_all(cert_path.parent().unwrap_or_else(|| Path::new(".")))?;
    std::fs::create_dir_all(key_path.parent().unwrap_or_else(|| Path::new(".")))?;
    std::fs::write(cert_path, cert.pem())?;
    std::fs::write(key_path, key_pair.serialize_pem())?;
    Ok(())
}
