use mycelium_gateway::server::run;
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
    runtime.block_on(run(
        config.listen,
        config.routes,
        config.token_file,
        config.reload_secs,
    ))
}

#[derive(Clone, Debug)]
struct Config {
    listen: SocketAddr,
    routes: Option<PathBuf>,
    token_file: Option<PathBuf>,
    reload_secs: u64,
}

mod args {
    use super::Config;
    use std::net::SocketAddr;
    use std::path::PathBuf;

    pub fn parse(argv: Vec<String>) -> Result<Config, Box<dyn std::error::Error + Send + Sync>> {
        let mut listen = "127.0.0.1:8080".parse::<SocketAddr>()?;
        let mut routes = None;
        let mut token_file = None;
        let mut reload_secs = 1;
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
        })
    }

    fn print_usage() {
        println!(
            "mycelium-gateway --listen 127.0.0.1:8080 [--routes gateway.json] \
             [--token-file TOKEN] [--reload-secs 1]"
        );
    }
}
