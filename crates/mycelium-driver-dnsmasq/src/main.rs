#[tokio::main]
async fn main() {
    match mycelium_driver_dnsmasq::command(&std::env::args().skip(1).collect::<Vec<_>>()).await {
        Ok(value) => println!("{value}"),
        Err(error) => {
            eprintln!("mycelium DNS resolver: {error}");
            std::process::exit(1);
        }
    }
}
