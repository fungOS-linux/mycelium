//! mycelium CLI: a thin, scriptable client over myceliumd's Unix socket.
//!
//! Argument parsing is hand-rolled (tenet #11: no clap until its weight is
//! earned). `--json` on every read command for pipelines; mutations need
//! explicit `--write`, and `--dry-run` always shows the plan instead of
//! applying it.

mod completions;
mod dns;
mod doctor;
mod enroll;
mod gateway;
mod host_access;
mod host_supervisor;
mod invite;
mod node;
mod oidc;
mod oidc_gateway;
mod pair;
mod packaged;
#[cfg(feature = "iroh-sync")]
mod pair_iroh;
mod setup;
mod skills;
mod ssh_access;
mod stun;
mod sync;
mod wireguard;

use mycelium_core::{
    ActionPlan, ActionRisk, AllocationReceipt, BootReachability, DiscoveryProtocol,
    InspectionCandidate, InspectionDepth, InspectionIntent, LogicalNetwork, NbdePlan,
    NetworkDriftReport, Topology, ID_SWITCH_OBSERVE,
};
use mycelium_driver_netgear_fastpath::{FastpathConfig, FastpathIntent, SnmpSwitchState};
use myceliumd::client::{Client, ClientError};
use myceliumd::protocol::Request;
use myceliumd::siem::SinkConfig;
use std::io::Write;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    // PAM account checks are synchronous, offline and do not need Tokio's
    // per-core thread pool or package/daemon startup configuration.
    if args.get(0).is_some_and(|v|v=="access") && args.get(1).is_some_and(|v|v=="host") && args.get(2).is_some_and(|v|v=="pam-check") {
        if let Err(error)=host_access::pam_check(&args[2..]) {eprintln!("mycelium: PAM account denied: {error}");std::process::exit(2);}
        return;
    }
    if let Err(error) = packaged::configure_cli() {
        eprintln!("mycelium: {error}");
        std::process::exit(1);
    }
    let result = match args.first().map(|a| a.as_str()) {
        Some("_serve") => {
            // hidden: run the daemon in this process (used by autostart)
            let rt = tokio::runtime::Runtime::new().expect("runtime");
            rt.block_on(myceliumd::rpc::serve())
                .map(|_| Vec::new())
                .map_err(ClientError::Io)
        }
        Some("_self-check") => Ok(vec![self_check()]),
        Some("completions") => completions::command(&args[1..], USAGE),
        Some(other) => rt_block(run(other, &args[1..])),
        None => Ok(usage()),
    };
    match result {
        Ok(lines) => {
            for line in lines {
                println!("{line}");
            }
        }
        Err(e) => {
            eprintln!("mycelium: {e}");
            std::process::exit(if matches!(e, ClientError::Rpc { .. }) {
                2
            } else {
                1
            });
        }
    }
}

fn self_check() -> String {
    format!("mycelium {} protocol {} iroh-sync={}", env!("CARGO_PKG_VERSION"),
        mycelium_peer_protocol::PROTOCOL_VERSION, cfg!(feature = "iroh-sync"))
}

fn rt_block<'a, F>(fut: F) -> Result<Vec<String>, ClientError>
where
    F: std::future::Future<Output = Result<Vec<String>, ClientError>> + 'a,
{
    let rt = tokio::runtime::Runtime::new().expect("runtime");
    rt.block_on(fut)
}

fn usage() -> Vec<String> {
    USAGE.lines().map(str::to_owned).collect()
}

const USAGE: &str = "\
mycelium — control plane for your network appliances

usage:
  mycelium completions zsh|bash|fish
  mycelium sync enable --write | export [--qr] | join <rendezvous.json> --write
  mycelium sync relays enable|disable --write
  mycelium pair --kind peer --iroh --qr --name NAME --site SITE [--public-relays] [--ttl 15m]
  mycelium setup [--gateway HTTPS-URL] [--claim CODE|--claim-file PATH] [--system-service] [--local-gateway] [--trust-cert] [--ttl 8h] [--key PATH] [--certificate PATH]
  mycelium setup --repair [--site SITE] [--path MYCELIUM-HOME] [--system-service] [--local-gateway] [--trust-cert]
  mycelium setup --packaged --claim-file PATH | --packaged --repair
  mycelium gateway status [--json]
  mycelium gateway usage [--json] [--fleet]
  mycelium gateway install [--write|--dry-run] [--trust-cert] [--routes PATH] [--cert PATH --key PATH] [--gateway-bin PATH] [--forwarder-bin PATH] [--path MYCELIUM-HOME]
  mycelium gateway uninstall [--write|--dry-run]
  mycelium doctor [--json] [--fix] [--trust-cert]
  mycelium pair --kind access --name NAME --unix-user USER... [--role ROLE]... [--listen ADDR] [--advertise URL] [--ca PATH] [--ttl 15m] [--credential-ttl 8h]
  mycelium pair --kind peer --name NAME --site SITE --peer HOST:PORT... [--unix-user USER --role ROLE]... [--ca PATH] [--enrollment-ca DIR] [--listen ADDR] [--advertise URL] [--ttl 15m]
  mycelium invite create --kind access|peer --name NAME [--unix-user USER]... [--role ROLE]... [--site SITE] [--peer HOST:PORT]... [--ttl 15m] [--credential-ttl 8h] [--uses 1] --write
  mycelium daemon status|start|stop
  mycelium skills list [--json]
  mycelium skills install [NAME] [--target codex|agents|claude] [--path DIR] --write [--dry-run] [--json]
  mycelium skills sync [--target codex|agents|claude] [--path DIR] --write [--dry-run] [--json]
  mycelium drivers
  mycelium add <host[:port]> [--name NAME] [--driver NAME] [--user U] [--credential-ref REF | --password-env VAR | --key PATH]
  mycelium targets [--json]
  mycelium credentials map list [--json]
  mycelium credentials map set NAME [--driver DRIVER] [--address IP]... [--cidr CIDR]... [--site SITE]... --user USER (--credential-ref REF | --password-env ENV | --key PATH) --write
  mycelium credentials map remove NAME --write
  mycelium describe <id> [--json]
  mycelium call <id> <capability> [--param k=v ...] [--write] [--dry-run]
  mycelium plan switch <id> --desired <startup-config> [--json]
  mycelium executions [--json]
  mycelium scan
  mycelium topology [--json]
  mycelium topology watch [--since SEQUENCE] [--once]
  mycelium discovery scopes [--json]
  mycelium discovery scope set <observer> --protocol ssdp|mdns --segment ID... --write [--dry-run]
  mycelium discovery scope remove <observer> --write [--dry-run]
  mycelium allocations list [--json]
  mycelium allocations import --site SITE --write [--dry-run] [--json]
  mycelium allocations record --site SITE (--subnet CIDR [--gateway IP] | --vlan ID) --source ID --write [--dry-run] [--json]
  mycelium networks list [--json]
  mycelium networks adopt NAME --site SITE --subnet CIDR [--vlan ID] --write [--dry-run]
  mycelium networks drift [NAME] [--json]
  mycelium networks plan [NAME] [--json]
  mycelium networks apply --plan PATH --write [--dry-run] [--json]
  mycelium networks bindings [NAME] [--json]
  mycelium networks bind NAME --device ID --port PORT [--tagged] --write [--dry-run]
  mycelium networks dhcp list [NAME] [--json]
  mycelium networks dhcp set NAME --device ID --pool NAME --range START-END [--dns IP]... --write [--dry-run]
  mycelium peers [--json]
  mycelium resources [show ID | watch [--once]] [--kind KIND] [--node NODE] [--json]
  mycelium services [show ID | watch [--once]] [--kind KIND] [--node NODE] [--json]
  mycelium debug hardware [PEER] [--json]
  mycelium releases list [--json]
  mycelium releases keygen --path PATH --write [--json]
  mycelium releases publish --binary PATH --signing-key PATH --version VERSION --channel CHANNEL [--target TRIPLE] --write [--dry-run] [--json]
  mycelium releases publish-set --manifest PATH --signing-key PATH --write [--dry-run] [--json]
  mycelium releases seed --binary PATH --digest SHA256 --write [--dry-run] [--json]
  mycelium packages list [--json]
  mycelium packages publish --name NAME --binary PATH --signing-key PATH --version VERSION --channel CHANNEL [--target TRIPLE] --write [--dry-run] [--json]
  mycelium software plan POLICY.json [--json]
  mycelium software policy set POLICY.json --write [--dry-run] [--json]
  mycelium software activate NAME [--channel CHANNEL] --write [--dry-run] [--json]
  mycelium software status [--json]
  mycelium software reconcile (--write | --dry-run) [--json]
  mycelium software auto-run [--json]
  mycelium software apt plan PACKAGE VERSION /usr/bin/EXECUTABLE
  mycelium software apt apply PLAN.json DIGEST --write
  mycelium software apt recover --write
  mycelium software apt health PACKAGE /usr/bin/EXECUTABLE
  mycelium node status [--json]
  mycelium node plan INTENT.json [--json]
  mycelium node apply --plan PLAN.json (--write | --dry-run) [--json]
  mycelium access list [--json]
  mycelium access host plan --policy /etc/mycelium/access.json
  mycelium access host apply --policy /etc/mycelium/access.json (--write | --dry-run)
  mycelium access host install-timer --policy /etc/mycelium/access.json --daemon-home /home/USER/.mycelium [--updates /etc/mycelium/access-updates.json] --write
  mycelium access host supervise --policy /etc/mycelium/access.json --updates /etc/mycelium/access-updates.json --write
  mycelium access keygen --path PATH --write [--json]
  mycelium access publish --statement PATH --signing-key PATH --write [--dry-run] [--json]
  mycelium authority list [--json]
  mycelium authority delegate --statement PATH --signing-key PATH --write [--dry-run] [--json]
  mycelium authority revoke --statement PATH --signing-key PATH --write [--dry-run] [--json]
  mycelium authority explain access.publish|release.publish SIGNER [--json]
  mycelium authority explain package.promote SIGNER --name PACKAGE [--channel CHANNEL] [--target TRIPLE] [--json]
  mycelium access ssh ca-init --path PRIVATE-KEY --write [--json]
  mycelium access ssh issue --grant ID --public-key PATH --ca PRIVATE-KEY --path CERT --ttl 8h --write [--json]
  mycelium access ssh krl --ca-public PATH --path KRL --write [--json]
  mycelium access ssh host-bundle --ca-public PATH --krl PATH (--allow USER=ROLE... | --from-access --role ROLE...) --path DIR --write [--json]
  mycelium access ssh client-config --host ALIAS --hostname HOST --user USER --identity PATH --certificate PATH --path FILE --write [--json]
  mycelium access ssh host-apply --bundle DIR --write
  mycelium access ssh host-rollout --bundle DIR --target SSH-HOST... [--remote-bin PATH] --write
  mycelium access ssh renewal-authorize --grant ID --node NODE-ID [--authorization-ttl 90d] [--credential-ttl 8h] [--signing-key PATH] --write
  mycelium access ssh profile show
  mycelium access ssh profile set --principal ID --unix-user USER [--allow-user USER]... [--role ROLE]... --write
  mycelium access ssh host-policy set --role ROLE... --ca-public PATH --write
  mycelium access ssh host-policy status
  mycelium access ssh host-policy reconcile (--dry-run | --write)
  mycelium access ssh host-policy install-timer --write
  mycelium access oidc verify --issuer URL --audience ID --token-env VAR [--json]
  mycelium access oidc ssh-issue --issuer URL --audience ID --token-env VAR --public-key PATH --ca PRIVATE-KEY --path CERT [--grant ID] [--ttl 8h] --write [--json]
  mycelium access oidc gateway --listen 127.0.0.1:8787 --issuer URL --audience ID --client-id ID --client-secret-env VAR --callback-url HTTPS-URL --ca PRIVATE-KEY [--invite-store PATH] --write
  mycelium access oidc join --gateway HTTPS-URL --public-key PATH --certificate PATH [--grant ID] [--ttl 8h] --write
    [--provider NAME] [--providers PATH]
  mycelium update status [--channel CHANNEL] [--fleet] [--json]
  mycelium update report [--channel CHANNEL] [--json] [--fail-on-updates]
  mycelium update apply [--channel CHANNEL] [--path INSTALLED-BINARY] --write
  mycelium update policy status [--json]
  mycelium update policy enable [--channel CHANNEL] [--minimum-age 15m] [--rollout-window 30m] [--retry-backoff 1h] --write
  mycelium update policy disable --write
  mycelium fleet status [--site SITE] [--platform linux|darwin] [--json]
  mycelium fleet exec [--site SITE] [--platform linux|darwin] [--user USER] -- COMMAND...
  mycelium wireguard plan LEFT RIGHT [--left-subnet CIDR...] [--right-subnet CIDR...] [--left-translation none|source-nat] [--right-translation none|source-nat]
    [--left-endpoint HOST:PORT] [--right-endpoint HOST:PORT]
    [--left-key PUBLIC-KEY] [--right-key PUBLIC-KEY] [--interface NAME] [--json]
  mycelium wireguard init --subnet CIDR... [--endpoint HOST:PORT]
    [--probe-server HOST:PORT... --bind IP] [--listen-port PORT] --write [--dry-run] [--json]
  mycelium wireguard bindings [--json]
  mycelium egress list [--json]
  mycelium egress probe --server HOST:PORT... [--bind IP] [--port PORT] [--json]
  mycelium dns zone [--suffix DOMAIN] [--json]
  mycelium dns service-address --prefix CIDR [--json]
  mycelium dns plan --site SITE [--suffix DOMAIN] [--delegations FILE] [--json|--dnsmasq]
  mycelium dns resolver init --config FILE --site SITE --suffix DOMAIN --reachable CIDR... --write [--service-address CIDR]
  mycelium dns resolver plan|status --config FILE
  mycelium dns resolver apply|run|system-install|system-remove --config FILE --write [--dry-run]
  mycelium dns blocklist plan --source FILE... [--allow DOMAIN]... [--action sinkhole|nxdomain] [--json|--dnsmasq]
  mycelium dns blocklist check NAME --source FILE... [--allow DOMAIN]... [--json]
  mycelium security status|events [--json]
  mycelium security scan [--stig-content PATH --stig-profile ID] [--remediation-plan] [--json]
  mycelium security sinks list [--json]
  mycelium security sinks add jsonl NAME ABSOLUTE_PATH --write [--dry-run]
  mycelium security sinks add loki NAME URL [--token-env ENV] [--tenant ID] --write [--dry-run]
  mycelium security sinks add mqtt NAME HOST [--port PORT] [--topic TOPIC] [--client-id ID] [--tls] [--username-env ENV --password-env ENV] --write [--dry-run]
  mycelium security export status [--json]
  mycelium security export run [--sink NAME] --write [--dry-run] [--json]
  mycelium security inspection plan --network NAME... --candidates FILE [--depth host-flows|packet-metadata|deep-packets] [--redundancy N] [--json]
  mycelium security remediation list [--json]
  mycelium security remediation apply DIGEST --write [--json]
  mycelium security remediation verify DIGEST [--json]
  mycelium enroll init [--path CA-DIR] --write
  mycelium enroll issue NAME --site SITE --address DNS-OR-IP [--san DNS-OR-IP]... --binary PATH --target TRIPLE [--peer HOST:PORT]... [--ca CA-DIR] [--path OUTPUT-DIR] --write
  mycelium enroll install --bundle DIR [--path MYCELIUM-HOME] --write
  mycelium map [--json]
  mycelium annotate <node> [--name NAME] [--kind KIND] --write [--dry-run]
  mycelium boot-path <device> --target <IP-or-URL>... [--json]
  mycelium nbde plan <device> --tang <IP-or-URL>... --threshold N [--json]
  mycelium tunnel <target>:<port> [--via DEVICE] [--local-port N] [--write] [--json]
  mycelium ssh <device> [--user USER] [--key PATH] [--certificate PATH] [--port N] [--json] [-- COMMAND...]
  mycelium exec <device> [--user USER] [--key PATH] [--certificate PATH] [--port N] [--json] -- COMMAND...
  mycelium scp SOURCE DEST [--user USER] [--key PATH] [--certificate PATH] [--port N] [--recursive] [--preserve] [--json]
  mycelium console <device> [--json]
  mycelium remove <id>

environment:
  MYCELIUM_HOME     state dir (default ~/.mycelium)
  MYCELIUM_SOCKET   override socket path
  MYCELIUM_NO_AUTOSTART=1  never spawn the daemon implicitly
";

struct Flags {
    json: bool,
    fleet: bool,
    write: bool,
    dry_run: bool,
    driver: Option<String>,
    user: Option<String>,
    password_env: Option<String>,
    credential_ref: Option<String>,
    key: Option<String>,
    params: Vec<(String, String)>,
    targets: Vec<String>,
    tang: Vec<String>,
    threshold: Option<usize>,
    via: Option<String>,
    local_port: Option<u16>,
    name: Option<String>,
    kind: Option<String>,
    desired: Option<String>,
    protocols: Vec<String>,
    segments: Vec<String>,
    site: Option<String>,
    vlan: Option<u16>,
    subnet: Option<String>,
    gateway: Option<String>,
    source: Option<String>,
    path: Option<String>,
    binary: Option<String>,
    bundle: Option<String>,
    manifest: Option<String>,
    digest: Option<String>,
    statement: Option<String>,
    signing_key: Option<String>,
    version: Option<String>,
    channel: Option<String>,
    address: Option<String>,
    sans: Vec<String>,
    ca: Option<String>,
    peers: Vec<String>,
    rest: Vec<String>,
}

fn parse_flags(args: &[String]) -> Flags {
    let mut f = Flags {
        json: false,
        fleet: false,
        write: false,
        dry_run: false,
        driver: None,
        user: None,
        password_env: None,
        credential_ref: None,
        key: None,
        params: Vec::new(),
        targets: Vec::new(),
        tang: Vec::new(),
        threshold: None,
        via: None,
        local_port: None,
        name: None,
        kind: None,
        desired: None,
        protocols: Vec::new(),
        segments: Vec::new(),
        site: None,
        vlan: None,
        subnet: None,
        gateway: None,
        source: None,
        path: None,
        binary: None,
        bundle: None,
        manifest: None,
        digest: None,
        statement: None,
        signing_key: None,
        version: None,
        channel: None,
        address: None,
        sans: Vec::new(),
        ca: None,
        peers: Vec::new(),
        rest: Vec::new(),
    };
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--json" => f.json = true,
            "--fleet" => f.fleet = true,
            "--write" => f.write = true,
            "--dry-run" => f.dry_run = true,
            "--driver" => {
                i += 1;
                f.driver = args.get(i).cloned();
            }
            "--user" => {
                i += 1;
                f.user = args.get(i).cloned();
            }
            "--password-env" => {
                i += 1;
                f.password_env = args.get(i).cloned();
            }
            "--credential-ref" => {
                i += 1;
                f.credential_ref = args.get(i).cloned();
            }
            "--key" => {
                i += 1;
                f.key = args.get(i).cloned();
            }
            "--param" => {
                i += 1;
                if let Some(kv) = args.get(i) {
                    if let Some((k, v)) = kv.split_once('=') {
                        f.params.push((k.to_owned(), v.to_owned()));
                    } else {
                        eprintln!("mycelium: --param expects k=v, got {kv}");
                    }
                }
            }
            "--target" => {
                i += 1;
                if let Some(target) = args.get(i) {
                    f.targets.push(target.clone());
                }
            }
            "--tang" => {
                i += 1;
                if let Some(endpoint) = args.get(i) {
                    f.tang.push(endpoint.clone());
                }
            }
            "--threshold" => {
                i += 1;
                f.threshold = args.get(i).and_then(|value| value.parse().ok());
            }
            "--via" => {
                i += 1;
                f.via = args.get(i).cloned();
            }
            "--local-port" => {
                i += 1;
                f.local_port = args.get(i).and_then(|value| value.parse().ok());
            }
            "--name" => {
                i += 1;
                f.name = args.get(i).cloned();
            }
            "--kind" => {
                i += 1;
                f.kind = args.get(i).cloned();
            }
            "--desired" => {
                i += 1;
                f.desired = args.get(i).cloned();
            }
            "--protocol" => {
                i += 1;
                if let Some(protocol) = args.get(i) {
                    f.protocols.push(protocol.clone());
                }
            }
            "--segment" => {
                i += 1;
                if let Some(segment) = args.get(i) {
                    f.segments.push(segment.clone());
                }
            }
            "--site" => {
                i += 1;
                f.site = args.get(i).cloned();
            }
            "--vlan" => {
                i += 1;
                f.vlan = args.get(i).and_then(|value| value.parse().ok());
            }
            "--subnet" => {
                i += 1;
                f.subnet = args.get(i).cloned();
            }
            "--gateway" => {
                i += 1;
                f.gateway = args.get(i).cloned();
            }
            "--source" => {
                i += 1;
                f.source = args.get(i).cloned();
            }
            "--path" => {
                i += 1;
                f.path = args.get(i).cloned();
            }
            "--binary" => {
                i += 1;
                f.binary = args.get(i).cloned();
            }
            "--bundle" => {
                i += 1;
                f.bundle = args.get(i).cloned();
            }
            "--manifest" => {
                i += 1;
                f.manifest = args.get(i).cloned();
            }
            "--digest" => {
                i += 1;
                f.digest = args.get(i).cloned();
            }
            "--statement" => {
                i += 1;
                f.statement = args.get(i).cloned();
            }
            "--signing-key" => {
                i += 1;
                f.signing_key = args.get(i).cloned();
            }
            "--version" => {
                i += 1;
                f.version = args.get(i).cloned();
            }
            "--channel" => {
                i += 1;
                f.channel = args.get(i).cloned();
            }
            "--address" => {
                i += 1;
                f.address = args.get(i).cloned();
            }
            "--san" => {
                i += 1;
                if let Some(address) = args.get(i) {
                    f.sans.push(address.clone());
                }
            }
            "--ca" => {
                i += 1;
                f.ca = args.get(i).cloned();
            }
            "--peer" => {
                i += 1;
                if let Some(peer) = args.get(i) {
                    f.peers.push(peer.clone());
                }
            }
            other => f.rest.push(other.to_owned()),
        }
        i += 1;
    }
    f
}

async fn run(cmd: &str, args: &[String]) -> Result<Vec<String>, ClientError> {
    match cmd {
        "setup" => setup::run(args).await.map_err(access_error),
        "gateway" => gateway::run(args).await.map_err(access_error),
        "doctor" => doctor::run(args).await.map_err(access_error),
        "pair" => pair::run(args).await.map_err(access_error),
        "sync" => sync::run(args).map_err(access_error),
        "invite" => invite::run(args).map_err(access_error),
        "daemon" => daemon(args).await,
        "skills" => skills::run(args),
        "help" | "--help" | "-h" => Ok(usage()),
        "drivers" => {
            let mut c = connect().await?;
            let v = c.call(&Request::Drivers).await?;
            if parse_flags(args).json {
                return Ok(vec![v.to_string()]);
            }
            Ok(vec!["drivers:".into()]
                .into_iter()
                .chain(
                    v.as_array()
                        .unwrap_or(&vec![])
                        .iter()
                        .map(|d| format!("  {}", d.as_str().unwrap_or("?"))),
                )
                .collect())
        }
        "add" => {
            let f = parse_flags(args);
            let target = f.rest.first().ok_or(err_usage("add needs a host"))?;
            let mut c = connect().await?;
            let v = c
                .call(&Request::DeviceAdd {
                    target: target.clone(),
                    name: f.name,
                    driver: f.driver,
                    username: f.user,
                    credential_ref: f
                        .credential_ref
                        .map(mycelium_core::CredentialRef::parse)
                        .transpose()
                        .map_err(|error| err_usage(&error))?,
                    password_env: f.password_env,
                    key_path: f.key,
                })
                .await?;
            Ok(render_added(&v))
        }
        "targets" | "devices" => {
            if cmd == "devices" {
                eprintln!("mycelium: `devices` means managed driver targets; use `targets`");
            }
            let f = parse_flags(args);
            let mut c = connect().await?;
            let v = c.call(&Request::DeviceList).await?;
            if f.json {
                return Ok(vec![v.to_string()]);
            }
            Ok(render_devices(&v))
        }
        "credentials" => credential_map(args).await,
        "describe" => {
            let f = parse_flags(args);
            let id = f.rest.first().ok_or(err_usage("describe needs an id"))?;
            let mut c = connect().await?;
            let v = c.call(&Request::DeviceDescribe { id: id.clone() }).await?;
            if f.json {
                return Ok(vec![v.to_string()]);
            }
            Ok(render_describe(id, &v))
        }
        "call" => {
            let f = parse_flags(args);
            let mut it = f.rest.iter();
            let id = it.next().ok_or(err_usage("call needs <id> <capability>"))?;
            let cap = it.next().ok_or(err_usage("call needs <id> <capability>"))?;
            let mut params = serde_json::Map::new();
            for (k, v) in &f.params {
                params.insert(k.clone(), coerce(v));
            }
            let mut c = connect().await?;
            let v = c
                .call(&Request::DeviceCall {
                    id: id.clone(),
                    capability: cap.clone(),
                    params,
                    write: f.write,
                    dry_run: f.dry_run,
                })
                .await?;
            Ok(render_call(&v))
        }
        "plan" => plan(args).await,
        "executions" => {
            let flags = parse_flags(args);
            let mut client = connect().await?;
            let value = client.call(&Request::ExecutionReceiptList).await?;
            if flags.json {
                return Ok(vec![value.to_string()]);
            }
            let mut lines = vec!["Execution receipts:".into()];
            for receipt in value.as_array().into_iter().flatten() {
                lines.push(format!(
                    "  {} state={} mode={} scope={}",
                    receipt
                        .get("plan_digest")
                        .or_else(|| receipt.get("change_digest"))
                        .and_then(|value| value.as_str())
                        .unwrap_or("?"),
                    receipt["state"].as_str().unwrap_or("?"),
                    receipt["mode"].as_str().unwrap_or("?"),
                    receipt["scope"].as_str().unwrap_or("?")
                ));
            }
            Ok(lines)
        }
        "ssh" => ssh(args, false).await,
        "exec" => ssh(args, true).await,
        "fleet" => fleet(args).await,
        "scp" => scp(args).await,
        "scan" => {
            let f = parse_flags(args);
            let mut c = connect().await?;
            let v = c.call(&Request::Scan).await?;
            if f.json {
                return Ok(vec![v.to_string()]);
            }
            Ok(render_scan(&v))
        }
        "topology" if args.first().is_some_and(|argument| argument == "watch") => {
            topology_watch(&args[1..]).await
        }
        "topology" | "map" => {
            let f = parse_flags(args);
            let mut c = connect().await?;
            let v = c.call(&Request::Topology).await?;
            if f.json {
                return Ok(vec![v.to_string()]);
            }
            let topo: Topology = serde_json::from_value(v)
                .map_err(|e| err_usage(&format!("bad topology json: {e}")))?;
            Ok(render_topology(&topo))
        }
        "discovery" => discovery(args).await,
        "allocations" => allocations(args).await,
        "networks" => networks(args).await,
        "peers" => {
            let flags = parse_flags(args);
            let mut client = connect().await?;
            let value = client.call(&Request::PeerList).await?;
            if flags.json {
                Ok(vec![value.to_string()])
            } else {
                Ok(render_peers(&value))
            }
        }
        "resources" => resources(args).await,
        "services" => services(args).await,
        "debug" if args.first().is_some_and(|argument| argument == "hardware") => {
            hardware(&args[1..]).await
        }
        "hardware" => {
            eprintln!("mycelium: `hardware` is diagnostic; use `debug hardware`");
            hardware(args).await
        }
        "releases" => releases(args).await,
        "packages" => packages(args).await,
        "software" => software(args).await,
        "node" => node::run(args).await.map_err(access_error),
        "access" => access(args).await,
        "authority" => authority(args).await,
        "update" => update(args).await,
        "wireguard" => wireguard_command(args).await,
        "egress" => egress_command(args).await,
        "dns" => dns_command(args).await,
        "security" => security_command(args).await,
        "enroll" => enroll_command(args).await,
        "annotate" => {
            let f = parse_flags(args);
            let selector = f
                .rest
                .first()
                .ok_or(err_usage("annotate needs a node selector"))?;
            let mut client = connect().await?;
            let value = client
                .call(&Request::TopologyAnnotate {
                    selector: selector.clone(),
                    name: f.name,
                    kind: f.kind,
                    write: f.write,
                    dry_run: f.dry_run,
                })
                .await?;
            if f.json {
                Ok(vec![value.to_string()])
            } else if value["dry_run"].as_bool() == Some(true) {
                Ok(vec![format!("DRY RUN: {value}")])
            } else {
                Ok(vec![format!(
                    "annotated {} name={} kind={}",
                    value["node"].as_str().unwrap_or("?"),
                    value["name"].as_str().unwrap_or("-"),
                    value["kind"].as_str().unwrap_or("-")
                )])
            }
        }
        "boot-path" => {
            let f = parse_flags(args);
            let device = f
                .rest
                .first()
                .ok_or(err_usage("boot-path needs a device"))?;
            if f.targets.is_empty() {
                return Err(err_usage("boot-path needs at least one --target"));
            }
            let topo = fetch_topology().await?;
            let path = topo
                .boot_path(device, &f.targets)
                .map_err(|error| err_usage(&error.to_string()))?;
            if f.json {
                Ok(vec![
                    serde_json::to_string(&path).map_err(|e| err_usage(&e.to_string()))?
                ])
            } else {
                Ok(render_boot_path(&path))
            }
        }
        "nbde" => nbde(args).await,
        "tunnel" => tunnel(args).await,
        "console" => console(args).await,
        "remove" => {
            let f = parse_flags(args);
            let id = f.rest.first().ok_or(err_usage("remove needs an id"))?;
            let mut c = connect().await?;
            c.call(&Request::DeviceRemove { id: id.clone() }).await?;
            Ok(vec![format!("removed {id}")])
        }
        other => Err(err_usage(&format!(
            "unknown command `{other}` (see `mycelium`)"
        ))),
    }
}

async fn topology_watch(args: &[String]) -> Result<Vec<String>, ClientError> {
    let mut since = 0;
    let mut once = false;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--once" => once = true,
            "--since" => {
                index += 1;
                since = args
                    .get(index)
                    .ok_or_else(|| err_usage("topology watch --since needs a sequence"))?
                    .parse::<u64>()
                    .map_err(|_| err_usage("topology watch --since needs an unsigned sequence"))?;
            }
            argument => {
                return Err(err_usage(&format!(
                    "unknown topology watch argument `{argument}`"
                )));
            }
        }
        index += 1;
    }
    let mut client = connect().await?;
    loop {
        let value = client
            .call(&Request::TopologyWatch { since, limit: 32 })
            .await?;
        let read: myceliumd::topology_feed::TopologyFeedRead = serde_json::from_value(value)
            .map_err(|error| err_usage(&format!("bad topology watch response: {error}")))?;
        if read.missed > 0 {
            eprintln!(
                "mycelium: topology watch resumed after a retention gap of {} generation(s)",
                read.missed
            );
        }
        for event in read.events {
            println!(
                "{}",
                serde_json::to_string(&event)
                    .map_err(|error| err_usage(&format!("encode topology generation: {error}")))?
            );
        }
        std::io::stdout().flush().map_err(ClientError::Io)?;
        since = read.position;
        if once {
            return Ok(Vec::new());
        }
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
}

async fn fleet(args: &[String]) -> Result<Vec<String>, ClientError> {
    let action = args.first().map(String::as_str).unwrap_or("status");
    let value_after = |flag: &str| {
        args.windows(2)
            .find(|pair| pair[0] == flag)
            .map(|pair| pair[1].clone())
    };
    let site = value_after("--site");
    let platform = value_after("--platform");
    let user = value_after("--user");
    let json = args.iter().any(|arg| arg == "--json");
    let mut client = connect().await?;
    let peers = client.call(&Request::PeerList).await?;
    let mut selected = peers
        .as_array()
        .into_iter()
        .flatten()
        .filter(|peer| {
            site.as_deref()
                .is_none_or(|expected| peer["hello"]["site"].as_str() == Some(expected))
                && platform.as_deref().is_none_or(|expected| {
                    peer["hello"]["platform"]
                        .as_str()
                        .is_some_and(|actual| actual.eq_ignore_ascii_case(expected))
                })
        })
        .cloned()
        .collect::<Vec<_>>();
    selected.sort_by(|left, right| {
        left["hello"]["hostname"]
            .as_str()
            .cmp(&right["hello"]["hostname"].as_str())
    });
    match action {
        "status" => {
            let rows = selected
                .into_iter()
                .map(|peer| {
                    let health = &peer["health"];
                    serde_json::json!({
                        "node_id": peer["hello"]["node_id"],
                        "hostname": peer["hello"]["hostname"],
                        "site": peer["hello"]["site"],
                        "platform": peer["hello"]["platform"],
                        "architecture": peer["hello"]["architecture"],
                        "daemon_version": peer["hello"]["daemon_version"],
                        "last_seen": peer["last_seen"],
                        "load_average": health["load_average"],
                        "ssh_listening": health["ssh_listening"],
                        "update_state": health["platform_metrics"]["mycelium_update.activation_state"],
                        "release_version": health["platform_metrics"]["mycelium_update.release_version"],
                    })
                })
                .collect::<Vec<_>>();
            if json {
                return Ok(vec![serde_json::Value::Array(rows).to_string()]);
            }
            let mut lines = vec!["Fleet status:".into()];
            for row in rows {
                lines.push(format!(
                    "  {} site={} platform={}/{} ssh={} daemon={} update={}",
                    row["hostname"].as_str().unwrap_or("?"),
                    row["site"].as_str().unwrap_or("?"),
                    row["platform"].as_str().unwrap_or("?"),
                    row["architecture"].as_str().unwrap_or("?"),
                    row["ssh_listening"]
                        .as_bool()
                        .map_or("unknown", |up| if up { "up" } else { "down" }),
                    row["daemon_version"].as_str().unwrap_or("?"),
                    row["release_version"].as_str().unwrap_or("unrecorded"),
                ));
            }
            Ok(lines)
        }
        "exec" => {
            let separator = args
                .iter()
                .position(|arg| arg == "--")
                .ok_or_else(|| err_usage("fleet exec needs a command after --"))?;
            let command = &args[separator + 1..];
            if command.is_empty() {
                return Err(err_usage("fleet exec needs a command after --"));
            }
            if selected.is_empty() {
                return Err(err_usage("fleet selector matched no peers"));
            }
            let mut lines = Vec::new();
            for peer in selected {
                let hostname = peer["hello"]["hostname"]
                    .as_str()
                    .ok_or_else(|| err_usage("peer has no hostname"))?;
                lines.push(format!("==> {hostname}"));
                let mut ssh_args = vec![hostname.to_owned()];
                if let Some(user) = &user {
                    ssh_args.extend(["--user".into(), user.clone()]);
                }
                ssh_args.push("--".into());
                ssh_args.extend(command.iter().cloned());
                ssh(&ssh_args, true).await?;
            }
            Ok(lines)
        }
        other => Err(err_usage(&format!("unknown fleet action `{other}`"))),
    }
}

async fn access(args: &[String]) -> Result<Vec<String>, ClientError> {
    if args.first().is_some_and(|value| value == "host") {
        if args.get(1).is_some_and(|v|v=="pam-check") {return host_access::pam_check(&args[1..]).map_err(access_error);}
        if args.get(1).is_some_and(|v|v=="install-timer") && args.iter().any(|a|a=="--updates") {
            if args.iter().any(|a|a=="--dry-run") {return Err(access_error("timer installation does not support --dry-run; inspect access host plan instead".into()));}
            if !args.iter().any(|a|a=="--write") {return Err(access_error("timer installation requires --write".into()));}
            ssh_access::require_root("root host cache subscription").map_err(access_error)?;
            let source=host_supervisor::placement_hint(&args[1..]).map_err(access_error)?;
            let mut client=connect().await?;
            client.call(&Request::SoftwarePolicySet {policy:source.to_string_lossy().into_owned(),write:true,dry_run:false}).await?;
        }
        if args.get(1).is_some_and(|value| value == "supervise") {
            let snapshot = async {
                let mut client = connect().await?;
                let access = client.call(&Request::AccessList).await?;
                let authority = client.call(&Request::AuthorityList).await?;
                let packages = client.call(&Request::PackageList).await?;
                Ok::<_,ClientError>((access,authority,packages))
            }.await;
            let (access,authority,packages) = match snapshot {
                Ok(values) => values,
                Err(error) => {eprintln!("mycelium: package carrier unavailable ({error}); enforcing cached access without updating binaries");(serde_json::Value::Null,serde_json::Value::Null,serde_json::Value::Null)}
            };
            return host_supervisor::run(&args[1..],&access,&authority,&packages).map_err(access_error);
        }
        let snapshot = async {
            let mut client = connect().await?;
            let access = client.call(&Request::AccessList).await?;
            let authority = client.call(&Request::AuthorityList).await?;
            Ok::<_, ClientError>((access, authority))
        }.await;
        return match snapshot {
            Ok((access, authority)) => host_access::run(&args[1..], &access, &authority),
            Err(error) => {
                eprintln!("mycelium: access carrier unavailable ({error}); enforcing retained signed evidence only");
                host_access::run(&args[1..], &serde_json::Value::Null, &serde_json::Value::Null)
            }
        }.map_err(access_error);
    }
    if args.first().is_some_and(|value| value == "ssh") {
        if args.get(1).is_some_and(|value| value == "renewal-authorize") {
            let mut client = connect().await?;
            let state = client.call(&Request::AccessList).await?;
            let (statement, key) = ssh_access::renewal_statement(&args[1..],&state).map_err(access_error)?;
            let directory = myceliumd::home_dir().join("ssh");
            std::fs::create_dir_all(&directory).map_err(|e| access_error(e.to_string()))?;
            let path = directory.join(format!("renewal-authorization-{}.json",std::process::id()));
            std::fs::write(&path,serde_json::to_vec(&statement).map_err(|e| access_error(e.to_string()))?).map_err(|e| access_error(e.to_string()))?;
            let result = client.call(&Request::AccessPublish {statement:path.to_string_lossy().into_owned(),signing_key:key.to_string_lossy().into_owned(),write:true,dry_run:false}).await;
            let _ = std::fs::remove_file(path);
            return result.map(|value| vec![value.to_string()]);
        }
        let state = if args.get(1).is_some_and(|value| value == "host-apply") {
            serde_json::json!({})
        } else {
            let mut client = connect().await?;
            client.call(&Request::AccessList).await?
        };
        return ssh_access::run(&args[1..], &state).map_err(access_error);
    }
    if args.first().is_some_and(|value| value == "oidc") {
        let state = if args.get(1).is_some_and(|value| value == "ssh-issue") {
            let mut client = connect().await?;
            Some(client.call(&Request::AccessList).await?)
        } else {
            None
        };
        return oidc::run(&args[1..], state.as_ref())
            .await
            .map_err(access_error);
    }
    let flags = parse_flags(args);
    let action = flags.rest.first().map(String::as_str).unwrap_or("list");
    let request = match action {
        "list" => Request::AccessList,
        "keygen" => Request::AccessKeygen {
            path: flags.path.ok_or(err_usage("access keygen needs --path"))?,
            write: flags.write,
        },
        "publish" => Request::AccessPublish {
            statement: flags
                .statement
                .ok_or(err_usage("access publish needs --statement"))?,
            signing_key: flags
                .signing_key
                .ok_or(err_usage("access publish needs --signing-key"))?,
            write: flags.write,
            dry_run: flags.dry_run,
        },
        other => return Err(err_usage(&format!("unknown access action `{other}`"))),
    };
    let mut client = connect().await?;
    let value = client.call(&request).await?;
    if flags.json || action != "list" {
        return Ok(vec![if flags.json {
            value.to_string()
        } else {
            serde_json::to_string_pretty(&value).unwrap_or_else(|_| value.to_string())
        }]);
    }
    let mut lines = vec!["access records:".into()];
    for grant in value["grants"].as_array().into_iter().flatten() {
        let statement = &grant["record"]["statement"];
        let kind = statement["kind"].as_str().unwrap_or("unknown");
        let id = statement["grant_id"]
            .as_str()
            .or_else(|| statement["revocation_id"].as_str())
            .unwrap_or("?");
        let principal = statement["principal"].as_str().unwrap_or("-");
        let state = if grant["active"].as_bool().unwrap_or(false) {
            "active"
        } else if grant["revoked_by"]
            .as_array()
            .is_some_and(|v| !v.is_empty())
        {
            "revoked"
        } else {
            "inactive"
        };
        lines.push(format!(
            "  {kind} id={id} principal={principal} state={state}"
        ));
    }
    for record in value["revocations"].as_array().into_iter().flatten() {
        let statement = &record["statement"];
        lines.push(format!(
            "  revoke id={} principal={}",
            statement["revocation_id"].as_str().unwrap_or("?"),
            statement["principal"].as_str().unwrap_or("-"),
        ));
    }
    Ok(lines)
}

async fn authority(args: &[String]) -> Result<Vec<String>, ClientError> {
    let flags = parse_flags(args);
    let action = flags.rest.first().map(String::as_str).unwrap_or("list");
    let request = match action {
        "list" => Request::AuthorityList,
        "delegate" | "revoke" | "publish" => Request::AuthorityPublish {
            statement: flags
                .statement
                .ok_or(err_usage("authority publication needs --statement"))?,
            signing_key: flags
                .signing_key
                .ok_or(err_usage("authority publication needs --signing-key"))?,
            write: flags.write,
            dry_run: flags.dry_run,
        },
        "explain" => {
            let operation = flags
                .rest
                .get(1)
                .ok_or(err_usage("authority explain needs an action"))?;
            let signer = flags
                .rest
                .get(2)
                .ok_or(err_usage("authority explain needs a signer"))?;
            Request::AuthorityExplain {
                action: operation.clone(),
                signer: signer.clone(),
                package: flags.name,
                channel: flags.channel,
                target: flags.targets.first().cloned(),
            }
        }
        other => return Err(err_usage(&format!("unknown authority action `{other}`"))),
    };
    let mut client = connect().await?;
    let value = client.call(&request).await?;
    if flags.json {
        Ok(vec![value.to_string()])
    } else {
        Ok(vec![
            serde_json::to_string_pretty(&value).unwrap_or_else(|_| value.to_string())
        ])
    }
}

fn access_error(message: String) -> ClientError {
    ClientError::Rpc {
        message,
        kind: "access".into(),
    }
}

async fn enroll_command(args: &[String]) -> Result<Vec<String>, ClientError> {
    let flags = parse_flags(args);
    if !flags.write {
        return Err(ClientError::Rpc {
            message: "enrollment changes require --write".into(),
            kind: "writes_not_permitted".into(),
        });
    }
    let action = flags.rest.first().map(String::as_str).unwrap_or("init");
    match action {
        "init" => enroll::init(
            flags
                .path
                .as_deref()
                .map(std::path::Path::new)
                .unwrap_or(&enroll::default_ca()),
        ),
        "issue" => {
            let name = flags
                .rest
                .get(1)
                .ok_or(err_usage("enroll issue needs NAME"))?;
            let site = flags.site.ok_or(err_usage("enroll issue needs --site"))?;
            let address = flags
                .address
                .ok_or(err_usage("enroll issue needs --address"))?;
            let target = flags
                .targets
                .first()
                .ok_or(err_usage("enroll issue needs --target"))?;
            let binary = flags
                .binary
                .as_deref()
                .ok_or(err_usage("enroll issue needs --binary"))?;
            let output = flags
                .path
                .map(std::path::PathBuf::from)
                .unwrap_or_else(|| myceliumd::home_dir().join("enrollments").join(name));
            let ca = flags
                .ca
                .map(std::path::PathBuf::from)
                .unwrap_or_else(enroll::default_ca);
            enroll::issue(
                &ca,
                enroll::Issue {
                    name,
                    site: &site,
                    address: &address,
                    additional_addresses: &flags.sans,
                    target,
                    binary: std::path::Path::new(binary),
                    peers: &flags.peers,
                    output: &output,
                },
            )
        }
        "install" => {
            let bundle = flags
                .bundle
                .as_deref()
                .or_else(|| flags.rest.get(1).map(String::as_str))
                .ok_or(err_usage("enroll install needs --bundle DIR"))?;
            let home = match flags.path {
                Some(path) => std::path::PathBuf::from(path),
                None if packaged::current().map_err(|error| err_usage(&error))? => std::path::PathBuf::from(packaged::HOME),
                None => myceliumd::home_dir(),
            };
            let mut lines = enroll::install(std::path::Path::new(bundle), &home)?;
            // A fresh node has no daemon socket yet, so this reports a skip
            // until `setup --repair` completes the resolver.
            match dns::ensure(&home).await {
                Ok(dns) => lines.extend(dns),
                Err(error) => lines.push(format!("DNS resolver not applied: {error}")),
            }
            Ok(lines)
        }
        other => Err(err_usage(&format!("unknown enroll action `{other}`"))),
    }
}

async fn releases(args: &[String]) -> Result<Vec<String>, ClientError> {
    let flags = parse_flags(args);
    let action = flags.rest.first().map(String::as_str).unwrap_or("list");
    let request = match action {
        "list" => Request::ReleaseList,
        "keygen" => Request::ReleaseKeygen {
            path: flags
                .path
                .ok_or(err_usage("releases keygen needs --path"))?,
            write: flags.write,
        },
        "publish" => Request::ReleasePublish {
            binary: flags
                .binary
                .ok_or(err_usage("releases publish needs --binary"))?,
            signing_key: flags
                .signing_key
                .ok_or(err_usage("releases publish needs --signing-key"))?,
            version: flags
                .version
                .ok_or(err_usage("releases publish needs --version"))?,
            channel: flags
                .channel
                .ok_or(err_usage("releases publish needs --channel"))?,
            target: flags.targets.first().cloned(),
            write: flags.write,
            dry_run: flags.dry_run,
        },
        "publish-set" => Request::ReleasePublishSet {
            manifest: flags
                .manifest
                .ok_or(err_usage("releases publish-set needs --manifest"))?,
            signing_key: flags
                .signing_key
                .ok_or(err_usage("releases publish-set needs --signing-key"))?,
            write: flags.write,
            dry_run: flags.dry_run,
        },
        "seed" => Request::ReleaseSeed {
            binary: flags
                .binary
                .ok_or(err_usage("releases seed needs --binary"))?,
            digest: flags
                .digest
                .ok_or(err_usage("releases seed needs --digest"))?,
            write: flags.write,
            dry_run: flags.dry_run,
        },
        other => return Err(err_usage(&format!("unknown releases action `{other}`"))),
    };
    let mut client = connect().await?;
    let value = client.call(&request).await?;
    if flags.json {
        Ok(vec![value.to_string()])
    } else if action == "list" {
        let mut lines = vec!["releases:".into()];
        for release in value.as_array().into_iter().flatten() {
            lines.push(format!(
                "  {} channel={} target={} digest={} size={}",
                release["version"].as_str().unwrap_or("?"),
                release["channel"].as_str().unwrap_or("?"),
                release["target"].as_str().unwrap_or("?"),
                release["artifact_digest"].as_str().unwrap_or("?"),
                release["artifact_size"].as_u64().unwrap_or(0),
            ));
        }
        Ok(lines)
    } else {
        Ok(vec![
            serde_json::to_string_pretty(&value).unwrap_or_else(|_| value.to_string())
        ])
    }
}

async fn packages(args: &[String]) -> Result<Vec<String>, ClientError> {
    let flags = parse_flags(args);
    let action = flags.rest.first().map(String::as_str).unwrap_or("list");
    let request = match action {
        "list" => Request::PackageList,
        "publish" => Request::PackagePublish {
            name: flags
                .name
                .ok_or(err_usage("packages publish needs --name"))?,
            binary: flags
                .binary
                .ok_or(err_usage("packages publish needs --binary"))?,
            signing_key: flags
                .signing_key
                .ok_or(err_usage("packages publish needs --signing-key"))?,
            version: flags
                .version
                .ok_or(err_usage("packages publish needs --version"))?,
            channel: flags
                .channel
                .ok_or(err_usage("packages publish needs --channel"))?,
            target: flags.targets.first().cloned(),
            write: flags.write,
            dry_run: flags.dry_run,
        },
        other => return Err(err_usage(&format!("unknown packages action `{other}`"))),
    };
    let mut client = connect().await?;
    let value = client.call(&request).await?;
    if flags.json || action != "list" {
        return Ok(vec![value.to_string()]);
    }
    let mut lines = vec!["packages:".into()];
    for package in value.as_array().into_iter().flatten() {
        lines.push(format!(
            "  {} {} channel={} target={} digest={}",
            package["name"].as_str().unwrap_or("?"),
            package["version"].as_str().unwrap_or("?"),
            package["channel"].as_str().unwrap_or("?"),
            package["target"].as_str().unwrap_or("?"),
            package["artifact_digest"].as_str().unwrap_or("?")
        ));
    }
    Ok(lines)
}

async fn software(args: &[String]) -> Result<Vec<String>, ClientError> {
    if args.first().map(String::as_str) == Some("apt") {
        return software_apt(&args[1..]);
    }
    let flags = parse_flags(args);
    let action = flags.rest.first().map(String::as_str).unwrap_or("plan");
    if action == "auto-run" {
        match std::fs::metadata(myceliumd::software_policy_path()) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(vec!["no software policy configured".into()])
            }
            Err(error) => return Err(ClientError::Io(error)),
            Ok(_) => {}
        }
    }
    let request = match action {
        "plan" => Request::SoftwarePlan {
            policy: flags
                .rest
                .get(1)
                .cloned()
                .ok_or(err_usage("software plan needs POLICY.json"))?,
        },
        "activate" => Request::SoftwareActivate {
            name: flags
                .rest
                .get(1)
                .cloned()
                .ok_or(err_usage("software activate needs NAME"))?,
            channel: flags.channel.unwrap_or_else(|| "stable".into()),
            write: flags.write,
            dry_run: flags.dry_run,
        },
        "status" => Request::SoftwareStatus,
        "reconcile" => Request::SoftwareReconcile {
            write: flags.write,
            dry_run: flags.dry_run,
        },
        "auto-run" => Request::SoftwareAutoRun,
        "policy" if flags.rest.get(1).map(String::as_str) == Some("set") => {
            Request::SoftwarePolicySet {
                policy: flags
                    .rest
                    .get(2)
                    .cloned()
                    .ok_or(err_usage("software policy set needs POLICY.json"))?,
                write: flags.write,
                dry_run: flags.dry_run,
            }
        }
        other => return Err(err_usage(&format!("unknown software action `{other}`"))),
    };
    let mut client = connect().await?;
    let value = client.call(&request).await?;
    if matches!(
        request,
        Request::SoftwarePolicySet {
            write: true,
            dry_run: false,
            ..
        }
    ) {
        let policy: myceliumd::software::SoftwarePolicy =
            serde_json::from_value(value.clone()).map_err(|error| err_usage(&error.to_string()))?;
        if policy
            .rules
            .iter()
            .flat_map(|rule| &rule.packages)
            .any(|package| {
                matches!(
                    package.updates.as_ref().unwrap_or(&policy.defaults.updates),
                    myceliumd::software::UpdatePolicy::Automatic { .. }
                )
            })
        {
            if !cfg!(target_os = "linux") {
                return Err(err_usage(
                    "native automatic package service activation currently requires Linux systemd",
                ));
            }
            install_update_scheduler()?;
        }
    }
    if flags.json || action != "plan" {
        return Ok(vec![
            serde_json::to_string_pretty(&value).unwrap_or_else(|_| value.to_string())
        ]);
    }
    let mut lines = vec!["software plan:".into()];
    for item in value.as_array().into_iter().flatten() {
        lines.push(format!(
            "  {}: {} channel={} rules={}",
            item["hostname"].as_str().unwrap_or("?"),
            item["package"].as_str().unwrap_or("?"),
            item["channel"].as_str().unwrap_or("?"),
            item["rules"]
                .as_array()
                .map(|rules| rules
                    .iter()
                    .filter_map(|v| v.as_str())
                    .collect::<Vec<_>>()
                    .join(","))
                .unwrap_or_default()
        ));
    }
    Ok(lines)
}

fn software_apt(args: &[String]) -> Result<Vec<String>, ClientError> {
    let fail = |error: Box<dyn std::error::Error + Send + Sync>| err_usage(&error.to_string());
    match args.first().map(String::as_str) {
        Some("health") if args.len() == 3 => {
            myceliumd::software_apt::health(&args[1], std::path::Path::new(&args[2])).map_err(fail)?;
            Ok(vec!["Debian-owned executable and application health verified (not fresh repository admission)".into()])
        }
        Some("plan") if args.len() == 4 => {
            let plan = myceliumd::software_apt::plan(&args[1], &args[2], std::path::Path::new(&args[3])).map_err(fail)?;
            let digest = myceliumd::software_apt::digest(&plan).map_err(fail)?;
            Ok(vec![serde_json::to_string_pretty(&serde_json::json!({"digest":digest,"plan":plan})).map_err(|e| err_usage(&e.to_string()))?])
        }
        Some("apply") if args.len() == 4 && args[3] == "--write" => {
            let bytes = std::fs::read(&args[1]).map_err(ClientError::Io)?;
            let value: serde_json::Value = serde_json::from_slice(&bytes).map_err(|e| err_usage(&e.to_string()))?;
            let plan: myceliumd::software_apt::AptPlan = serde_json::from_value(value.get("plan").cloned().ok_or(err_usage("missing APT plan"))?).map_err(|e| err_usage(&e.to_string()))?;
            myceliumd::software_apt::apply(&plan, &args[2]).map_err(fail)?;
            Ok(vec!["APT candidate installed and local service health verified".into()])
        }
        Some("recover") if args.len() == 2 && args[1] == "--write" => {
            myceliumd::software_apt::recover().map_err(fail)?;
            Ok(vec!["APT previous package restored and health verified".into()])
        }
        _ => Err(err_usage("software apt plan PACKAGE VERSION /usr/bin/EXECUTABLE | apply PLAN.json DIGEST --write | recover --write")),
    }
}

async fn egress_command(args: &[String]) -> Result<Vec<String>, ClientError> {
    if args.first().map(String::as_str) == Some("list") {
        let mut client = connect().await?;
        let value = client.call(&Request::EgressList).await?;
        return Ok(vec![if args.iter().any(|arg| arg == "--json") {
            value.to_string()
        } else {
            serde_json::to_string_pretty(&value).unwrap_or_else(|_| value.to_string())
        }]);
    }
    if args.first().map(String::as_str) != Some("probe") {
        return Err(err_usage("egress supports `list` and `probe`"));
    }
    let servers = args
        .windows(2)
        .filter(|pair| pair[0] == "--server")
        .map(|pair| pair[1].clone())
        .collect::<Vec<_>>();
    if servers.is_empty() {
        return Err(err_usage(
            "egress probe needs at least one configurable --server HOST:PORT",
        ));
    }
    let bind = args
        .windows(2)
        .find(|pair| pair[0] == "--bind")
        .map(|pair| {
            pair[1]
                .parse::<std::net::IpAddr>()
                .map_err(|_| err_usage(&format!("invalid bind address `{}`", pair[1])))
        })
        .transpose()?;
    let source_port = args
        .windows(2)
        .find(|pair| pair[0] == "--port")
        .map(|pair| pair[1].parse::<u16>())
        .transpose()
        .map_err(|_| err_usage("--port must be a valid UDP port"))?
        .unwrap_or(0);
    let report = stun::probe_many(&servers, bind, source_port).await;
    if report.results.is_empty() {
        return Err(err_usage(&format!(
            "every STUN probe failed: {}",
            report.failures.join("; ")
        )));
    }
    let mut latencies = report
        .results
        .iter()
        .map(|result| result.latency_ms as u64)
        .collect::<Vec<_>>();
    latencies.sort_unstable();
    let hostname = std::process::Command::new("hostname")
        .arg("-s")
        .output()
        .map_err(ClientError::Io)?;
    let hostname = String::from_utf8_lossy(&hostname.stdout).trim().to_owned();
    let mut client = connect().await?;
    let peers = client.call(&Request::PeerList).await?;
    let hello = peers
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|peer| peer.get("hello"))
        .find(|hello| hello["hostname"].as_str() == Some(&hostname))
        .ok_or_else(|| err_usage("local peer identity is not published yet"))?;
    let observation = mycelium_peer_protocol::EgressObservation {
        node_id: hello["node_id"].as_str().unwrap_or_default().into(),
        hostname: hostname.clone(),
        site: hello["site"].as_str().unwrap_or_default().into(),
        observed_at: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
        mapped_endpoints: report
            .results
            .iter()
            .map(|result| result.mapped.to_string())
            .collect(),
        public_ip_stable: report.public_ip_stable,
        mapping_varies_by_destination: report.mapping_varies_by_destination,
        median_latency_ms: latencies.get(latencies.len() / 2).copied().unwrap_or(0),
    };
    client.call(&Request::EgressPublish { observation }).await?;
    let report = serde_json::to_value(report)
        .map_err(|error| err_usage(&format!("serialize STUN report: {error}")))?;
    if args.iter().any(|arg| arg == "--json") {
        return Ok(vec![report.to_string()]);
    }
    let mut lines = vec![format!(
        "egress: public_ip_stable={} mapping_varies_by_destination={}",
        report["public_ip_stable"].as_bool().unwrap_or(false),
        report["mapping_varies_by_destination"]
            .as_bool()
            .unwrap_or(false)
    )];
    for result in report["results"].as_array().into_iter().flatten() {
        lines.push(format!(
            "  {} source={} mapped={} latency={}ms",
            result["server"].as_str().unwrap_or("?"),
            result["source"].as_str().unwrap_or("?"),
            result["mapped"].as_str().unwrap_or("?"),
            result["latency_ms"].as_u64().unwrap_or(0),
        ));
    }
    for failure in report["failures"].as_array().into_iter().flatten() {
        lines.push(format!(
            "  warning: {}",
            failure.as_str().unwrap_or("unknown STUN failure")
        ));
    }
    Ok(lines)
}

async fn dns_command(args: &[String]) -> Result<Vec<String>, ClientError> {
    let action = args.first().map(String::as_str).unwrap_or("");
    if action == "resolver" {
        return mycelium_driver_dnsmasq::command(&args[1..])
            .await
            .map(|output| vec![output])
            .map_err(|error| err_usage(&error));
    }
    if action == "blocklist" {
        return dns::blocklist(&args[1..]).map_err(|error| err_usage(&error));
    }
    if action == "service-address" {
        let mut prefix = None;
        let mut json = false;
        let mut rest = args[1..].iter();
        while let Some(flag) = rest.next() {
            match flag.as_str() {
                "--prefix" => {
                    prefix = Some(
                        rest.next()
                            .ok_or_else(|| err_usage("--prefix needs an IPv6 ULA CIDR"))?,
                    )
                }
                "--json" => json = true,
                _ => return Err(err_usage("unknown DNS service-address option")),
            }
        }
        let service = mycelium_dns_policy::FleetDnsAddress::parse(
            prefix.ok_or_else(|| err_usage("dns service-address needs --prefix"))?,
        )
        .map_err(|error| err_usage(&error))?;
        if json {
            return Ok(vec![
                serde_json::to_string(&serde_json::json!({
                    "prefix": service.to_string(),
                    "address": service.address().to_string(),
                }))
                .map_err(|error| err_usage(&error.to_string()))?,
            ]);
        }
        return Ok(vec![
            service.address().to_string(),
            format!("fleet DNS service address for {service}"),
        ]);
    }
    if !matches!(action, "zone" | "plan") {
        return Err(err_usage(
            "dns supports `zone`, read-only `plan`, `resolver` and `blocklist`",
        ));
    }
    let mut suffix = "mycelium";
    let mut site = None;
    let mut delegation_file = None;
    let mut json = false;
    let mut dnsmasq = false;
    let mut options = std::collections::BTreeSet::new();
    let mut rest = args[1..].iter();
    while let Some(flag) = rest.next() {
        if !options.insert(flag.as_str()) {
            return Err(err_usage("duplicate DNS option"));
        }
        match flag.as_str() {
            "--json" => json = true,
            "--dnsmasq" if action == "plan" => dnsmasq = true,
            "--suffix" => {
                suffix = rest
                    .next()
                    .ok_or_else(|| err_usage("--suffix needs a domain"))?
            }
            "--site" if action == "plan" => {
                site = Some(
                    rest.next()
                        .ok_or_else(|| err_usage("--site needs a site"))?
                        .as_str(),
                )
            }
            "--delegations" if action == "plan" => {
                delegation_file = Some(
                    rest.next()
                        .ok_or_else(|| err_usage("--delegations needs a file"))?,
                )
            }
            _ => return Err(err_usage("unknown DNS option; no writes are supported")),
        }
    }
    if json && dnsmasq {
        return Err(err_usage("choose --json or --dnsmasq"));
    }
    if action == "plan" && site.is_none() {
        return Err(err_usage("dns plan requires --site"));
    }
    dns::canonical_domain(suffix).map_err(|e| err_usage(&e))?;
    let delegations: Vec<dns::Delegation> = if let Some(path) = delegation_file {
        use std::io::Read;
        let mut bytes = Vec::new();
        std::fs::File::open(path)
            .and_then(|file| file.take(65537).read_to_end(&mut bytes))
            .map_err(|e| err_usage(&format!("read DNS delegations: {e}")))?;
        if bytes.len() > 65536 {
            return Err(err_usage("DNS delegation file exceeds 64 KiB"));
        }
        serde_json::from_slice(&bytes).map_err(|_| err_usage("invalid DNS delegation document"))?
    } else {
        Vec::new()
    };
    if let Some(site) = site {
        dns::plan(site, suffix, Vec::new(), delegations.clone()).map_err(|e| err_usage(&e))?;
    }
    let mut client = connect().await?;
    let topology: Topology = serde_json::from_value(client.call(&Request::Topology).await?)
        .map_err(|error| err_usage(&format!("invalid topology response: {error}")))?;
    let mut bindings: Vec<mycelium_peer_protocol::WireGuardBinding> =
        serde_json::from_value(client.call(&Request::WireGuardBindingList).await?)
            .map_err(|error| err_usage(&format!("invalid WireGuard bindings: {error}")))?;
    if let Some(site) = site {
        bindings.retain(|binding| binding.site == site);
    }
    let records =
        dns::derive_records(&topology, &bindings, suffix).map_err(|error| err_usage(&error))?;
    if action == "plan" {
        let plan =
            dns::plan(site.unwrap(), suffix, records, delegations).map_err(|e| err_usage(&e))?;
        if dnsmasq {
            return Ok(vec![plan.dnsmasq]);
        }
        if json {
            return Ok(vec![
                serde_json::to_string(&plan).map_err(|e| err_usage(&e.to_string()))?
            ]);
        }
        let mut lines = vec![
            format!("DNS plan for {} (read-only; apply unsupported)", plan.site),
            plan.dnsmasq,
        ];
        lines.extend(
            plan.verification_required
                .iter()
                .map(|check| format!("verify: {check}")),
        );
        return Ok(lines);
    }
    if json {
        return Ok(vec![serde_json::to_string(&records).map_err(|error| {
            err_usage(&format!("serialize DNS records: {error}"))
        })?]);
    }
    let mut lines = vec![format!("# Mycelium-derived hosts for {suffix}")];
    lines.extend(
        records
            .iter()
            .map(|record| format!("{} {}", record.address, record.name)),
    );
    Ok(lines)
}

async fn security_command(args: &[String]) -> Result<Vec<String>, ClientError> {
    let action = args.first().map(String::as_str).unwrap_or("status");
    let value = |flag: &str| {
        args.windows(2)
            .find(|pair| pair[0] == flag)
            .map(|pair| pair[1].clone())
    };
    let request = match action {
        "status" => Request::SecurityPostureList,
        "events" => Request::SecurityEventList,
        "scan" => Request::SecurityScan {
            stig_content: value("--stig-content"),
            stig_profile: value("--stig-profile"),
            remediation_plan: args.iter().any(|arg| arg == "--remediation-plan"),
        },
        "remediation" => {
            match args.get(1).map(String::as_str).unwrap_or("list") {
                "list" => Request::SecurityRemediationList,
                "apply" => Request::SecurityRemediationApply {
                    digest: args.get(2).cloned().ok_or_else(|| {
                        err_usage("security remediation apply needs a plan digest")
                    })?,
                    write: args.iter().any(|arg| arg == "--write"),
                },
                "verify" => Request::SecurityRemediationVerify {
                    digest: args.get(2).cloned().ok_or_else(|| {
                        err_usage("security remediation verify needs a plan digest")
                    })?,
                },
                other => return Err(err_usage(&format!("unknown remediation action `{other}`"))),
            }
        }
        "sinks" => match args.get(1).map(String::as_str).unwrap_or("list") {
            "list" => Request::SecuritySinkList,
            "add" => {
                let kind = args
                    .get(2)
                    .map(String::as_str)
                    .ok_or_else(|| err_usage("security sinks add needs jsonl or loki"))?;
                let name = args
                    .get(3)
                    .cloned()
                    .ok_or_else(|| err_usage("security sinks add needs NAME"))?;
                let target = args
                    .get(4)
                    .cloned()
                    .ok_or_else(|| err_usage("security sinks add needs PATH or URL"))?;
                let config = match kind {
                    "jsonl" => SinkConfig::Jsonl {
                        name,
                        path: target.into(),
                    },
                    "loki" => SinkConfig::Loki {
                        name,
                        url: target,
                        token_env: value("--token-env"),
                        tenant: value("--tenant"),
                    },
                    "mqtt" => SinkConfig::Mqtt {
                        name,
                        host: target,
                        port: value("--port")
                            .map(|port| port.parse::<u16>())
                            .transpose()
                            .map_err(|_| err_usage("--port must be an integer from 1 to 65535"))?
                            .unwrap_or(1883),
                        topic: value("--topic")
                            .unwrap_or_else(|| "mycelium/security/events/v1".into()),
                        client_id: value("--client-id")
                            .unwrap_or_else(|| format!("mycelium-{}", std::process::id())),
                        tls: args.iter().any(|arg| arg == "--tls"),
                        username_env: value("--username-env"),
                        password_env: value("--password-env"),
                    },
                    other => return Err(err_usage(&format!("unknown SIEM sink kind `{other}`"))),
                };
                Request::SecuritySinkAdd {
                    config,
                    write: args.iter().any(|arg| arg == "--write"),
                    dry_run: args.iter().any(|arg| arg == "--dry-run"),
                }
            }
            other => return Err(err_usage(&format!("unknown sinks action `{other}`"))),
        },
        "export" => match args.get(1).map(String::as_str).unwrap_or("status") {
            "status" => Request::SecurityExportStatus,
            "run" => Request::SecurityExportRun {
                sink: value("--sink"),
                write: args.iter().any(|arg| arg == "--write"),
                dry_run: args.iter().any(|arg| arg == "--dry-run"),
            },
            other => return Err(err_usage(&format!("unknown export action `{other}`"))),
        },
        "inspection" => match args.get(1).map(String::as_str).unwrap_or("plan") {
            "plan" => {
                let networks = args
                    .windows(2)
                    .filter(|pair| pair[0] == "--network")
                    .map(|pair| pair[1].clone())
                    .collect();
                let depth = match value("--depth").as_deref().unwrap_or("host-flows") {
                    "host-flows" => InspectionDepth::HostFlows,
                    "packet-metadata" => InspectionDepth::PacketMetadata,
                    "deep-packets" => InspectionDepth::DeepPackets,
                    other => return Err(err_usage(&format!("unknown inspection depth `{other}`"))),
                };
                let redundancy = value("--redundancy")
                    .map(|value| value.parse::<u8>())
                    .transpose()
                    .map_err(|_| err_usage("--redundancy must be an integer from 1 to 255"))?
                    .unwrap_or(1);
                let intent = InspectionIntent::new(networks, depth, redundancy)
                    .map_err(|error| err_usage(&error))?;
                let path = value("--candidates").ok_or_else(|| {
                    err_usage("inspection plan currently requires --candidates FILE")
                })?;
                let candidates: Vec<InspectionCandidate> =
                    serde_json::from_slice(&std::fs::read(&path)?).map_err(|error| {
                        err_usage(&format!("invalid inspection candidates `{path}`: {error}"))
                    })?;
                Request::SecurityInspectionPlan { intent, candidates }
            }
            other => return Err(err_usage(&format!("unknown inspection action `{other}`"))),
        },
        _ => return Err(err_usage(
            "security supports `status`, `scan`, `events`, `remediation`, `sinks`, and `export`",
        )),
    };
    let mut client = connect().await?;
    let value = client.call(&request).await?;
    if args.iter().any(|arg| arg == "--json") {
        return Ok(vec![value.to_string()]);
    }
    if action == "scan" {
        return render_security_postures(&serde_json::Value::Array(vec![value]));
    }
    if action == "remediation" {
        let values = value.as_array().cloned().unwrap_or_else(|| vec![value]);
        let mut lines = vec!["Security remediation:".into()];
        for plan in values {
            lines.push(format!(
                "  {} state={} profile={} error={}",
                plan["digest"].as_str().unwrap_or("?"),
                plan["state"].as_str().unwrap_or("?"),
                plan["profile"].as_str().unwrap_or("?"),
                plan["error"].as_str().unwrap_or("none"),
            ));
        }
        return Ok(lines);
    }
    if action == "events" {
        let mut lines = vec!["Security events:".into()];
        for batch in value.as_array().into_iter().flatten() {
            let host = batch["hostname"].as_str().unwrap_or("unknown");
            for event in batch["events"].as_array().into_iter().flatten() {
                lines.push(format!(
                    "  {host} {:<13} {:<10} {}",
                    event["severity"].as_str().unwrap_or("unknown"),
                    event["category"].as_str().unwrap_or("unknown"),
                    event["message"].as_str().unwrap_or("unknown event")
                ));
            }
        }
        return Ok(lines);
    }
    if action == "sinks" || action == "export" {
        let values = value.as_array().cloned().unwrap_or_else(|| vec![value]);
        let mut lines = vec![format!("Security {action}:")];
        for item in values {
            lines.push(format!(
                "  {}",
                serde_json::to_string(&item).map_err(|error| err_usage(&error.to_string()))?
            ));
        }
        return Ok(lines);
    }
    if action == "inspection" {
        let plan: mycelium_core::InspectionPlan = serde_json::from_value(value)
            .map_err(|error| err_usage(&format!("invalid inspection plan: {error}")))?;
        let mut lines = vec![format!(
            "Inspection placements (depth={:?}, redundancy={}):",
            plan.intent.depth, plan.intent.redundancy
        )];
        for placement in plan.placements {
            lines.push(format!(
                "  {} method={:?} score={} networks={}",
                placement.hostname,
                placement.method,
                placement.score,
                placement.networks.into_iter().collect::<Vec<_>>().join(",")
            ));
        }
        for (network, missing) in plan.blind_spots {
            lines.push(format!(
                "  BLIND SPOT network={network} missing_copies={missing}"
            ));
        }
        return Ok(lines);
    }
    render_security_postures(&value)
}

fn render_security_postures(value: &serde_json::Value) -> Result<Vec<String>, ClientError> {
    let postures = value
        .as_array()
        .ok_or_else(|| err_usage("invalid security posture response"))?;
    let mut lines = vec!["Security posture:".into()];
    for posture in postures {
        let findings = posture["findings"].as_array().map_or(0, Vec::len);
        let failed = posture["compliance"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|profile| profile["failed"].as_u64())
            .sum::<u64>();
        lines.push(format!(
            "  {:<20} site={:<14} updates={} findings={} stig_failed={} reboot={}",
            posture["hostname"].as_str().unwrap_or("unknown"),
            posture["site"].as_str().unwrap_or("unknown"),
            posture["security_updates_available"].as_u64().unwrap_or(0),
            findings,
            failed,
            posture["reboot_required"].as_bool().unwrap_or(false),
        ));
        if let Some(scanners) = posture["scanners"].as_object() {
            lines.push(format!(
                "    scanners: {}",
                scanners
                    .iter()
                    .map(|(name, state)| format!("{name}={}", state.as_str().unwrap_or("unknown")))
                    .collect::<Vec<_>>()
                    .join(" ")
            ));
        }
    }
    Ok(lines)
}

fn observed_string(binding: Option<&serde_json::Value>, field: &str) -> Option<String> {
    binding?
        .get(field)?
        .as_str()
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}

fn observed_prefixes(
    binding: Option<&serde_json::Value>,
) -> Result<Vec<wireguard::Prefix>, ClientError> {
    binding
        .and_then(|binding| binding["advertised_prefixes"].as_array())
        .into_iter()
        .flatten()
        .filter_map(serde_json::Value::as_str)
        .map(|prefix| wireguard::parse_prefix(prefix).map_err(|error| err_usage(&error)))
        .collect()
}

async fn wireguard_command(args: &[String]) -> Result<Vec<String>, ClientError> {
    let action = args.first().map(String::as_str).unwrap_or("bindings");
    if action == "bindings" {
        let mut client = connect().await?;
        let bindings = client.call(&Request::WireGuardBindingList).await?;
        if args.iter().any(|arg| arg == "--json") {
            return Ok(vec![bindings.to_string()]);
        }
        let mut lines = vec!["WireGuard bindings:".into()];
        for binding in bindings.as_array().into_iter().flatten() {
            lines.push(format!(
                "  {} site={} endpoint={} prefixes={}",
                binding["hostname"].as_str().unwrap_or("?"),
                binding["site"].as_str().unwrap_or("?"),
                binding["endpoint"].as_str().unwrap_or("unobserved"),
                binding["advertised_prefixes"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(serde_json::Value::as_str)
                    .collect::<Vec<_>>()
                    .join(","),
            ));
        }
        return Ok(lines);
    }
    if action == "init" {
        let prefixes = args
            .windows(2)
            .filter(|pair| pair[0] == "--subnet")
            .map(|pair| pair[1].clone())
            .collect::<Vec<_>>();
        let mut endpoint = args
            .windows(2)
            .find(|pair| pair[0] == "--endpoint")
            .map(|pair| pair[1].clone());
        let probe_servers = args
            .windows(2)
            .filter(|pair| pair[0] == "--probe-server")
            .map(|pair| pair[1].clone())
            .collect::<Vec<_>>();
        if endpoint.is_none() && !probe_servers.is_empty() {
            let bind = args
                .windows(2)
                .find(|pair| pair[0] == "--bind")
                .ok_or_else(|| err_usage("endpoint probing requires --bind IP"))?[1]
                .parse::<std::net::IpAddr>()
                .map_err(|_| err_usage("invalid --bind IP"))?;
            let listen_port = args
                .windows(2)
                .find(|pair| pair[0] == "--listen-port")
                .map(|pair| pair[1].parse::<u16>())
                .transpose()
                .map_err(|_| err_usage("--listen-port must be a valid UDP port"))?
                .unwrap_or(51820);
            let report = stun::probe_many(&probe_servers, Some(bind), listen_port).await;
            if report.results.is_empty() {
                return Err(err_usage(&format!(
                    "WireGuard endpoint probing failed: {}",
                    report.failures.join("; ")
                )));
            }
            if !report.public_ip_stable || report.mapping_varies_by_destination {
                return Err(err_usage(
                    "WireGuard endpoint mapping is not stable across STUN destinations",
                ));
            }
            endpoint = report
                .results
                .first()
                .map(|result| result.mapped.to_string());
        }
        let request = Request::WireGuardBindingInit {
            advertised_prefixes: prefixes,
            endpoint,
            write: args.iter().any(|arg| arg == "--write"),
            dry_run: args.iter().any(|arg| arg == "--dry-run"),
        };
        let mut client = connect().await?;
        let result = client.call(&request).await?;
        return if args.iter().any(|arg| arg == "--json") {
            Ok(vec![result.to_string()])
        } else {
            Ok(vec![
                serde_json::to_string_pretty(&result).unwrap_or_else(|_| result.to_string())
            ])
        };
    }
    if action != "plan" {
        return Err(err_usage(
            "wireguard supports `bindings`, `init`, and `plan`",
        ));
    }
    let left_selector = args
        .get(1)
        .filter(|value| !value.starts_with('-'))
        .ok_or_else(|| err_usage("wireguard plan needs LEFT and RIGHT gateway selectors"))?;
    let right_selector = args
        .get(2)
        .filter(|value| !value.starts_with('-'))
        .ok_or_else(|| err_usage("wireguard plan needs LEFT and RIGHT gateway selectors"))?;
    let values = |flag: &str| -> Vec<String> {
        args.windows(2)
            .filter(|pair| pair[0] == flag)
            .map(|pair| pair[1].clone())
            .collect()
    };
    let value = |flag: &str| values(flag).into_iter().last();
    let translation = |flag: &str| -> Result<wireguard::PrefixTranslation, ClientError> {
        match value(flag).as_deref().unwrap_or("none") {
            "none" => Ok(wireguard::PrefixTranslation::None),
            "source-nat" => Ok(wireguard::PrefixTranslation::SourceNat),
            other => Err(err_usage(&format!(
                "{flag} must be `none` or `source-nat`, got `{other}`"
            ))),
        }
    };
    let prefixes = |flag: &str| -> Result<Vec<wireguard::Prefix>, ClientError> {
        values(flag)
            .iter()
            .map(|prefix| wireguard::parse_prefix(prefix).map_err(|error| err_usage(&error)))
            .collect()
    };
    let mut left_prefixes = prefixes("--left-subnet")?;
    let mut right_prefixes = prefixes("--right-subnet")?;
    let mut client = connect().await?;
    let peers = client.call(&Request::PeerList).await?;
    let bindings = client.call(&Request::WireGuardBindingList).await?;
    let egress = client.call(&Request::EgressList).await?;
    let resolve = |selector: &str| -> Result<wireguard::GatewayIdentity, ClientError> {
        let matching = peers
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|peer| peer.get("hello"))
            .filter(|hello| {
                hello["hostname"].as_str() == Some(selector)
                    || hello["node_id"]
                        .as_str()
                        .is_some_and(|node_id| node_id.starts_with(selector))
            })
            .collect::<Vec<_>>();
        if matching.len() != 1 {
            return Err(err_usage(&format!(
                "gateway selector `{selector}` matched {} peer identities",
                matching.len()
            )));
        }
        let hello = matching[0];
        Ok(wireguard::GatewayIdentity {
            node_id: hello["node_id"].as_str().unwrap_or_default().into(),
            hostname: hello["hostname"].as_str().unwrap_or_default().into(),
            site: hello["site"].as_str().unwrap_or_default().into(),
        })
    };
    let left_identity = resolve(left_selector)?;
    let right_identity = resolve(right_selector)?;
    let binding_for = |node_id: &str| {
        bindings
            .as_array()
            .into_iter()
            .flatten()
            .find(|binding| binding["node_id"].as_str() == Some(node_id))
    };
    let egress_for = |node_id: &str| {
        egress
            .as_array()
            .into_iter()
            .flatten()
            .find(|observation| observation["node_id"].as_str() == Some(node_id))
            .map(|observation| wireguard::EgressFacts {
                observed_at: observation["observed_at"].as_u64().unwrap_or(0),
                public_ip_stable: observation["public_ip_stable"].as_bool().unwrap_or(false),
                mapping_varies_by_destination: observation["mapping_varies_by_destination"]
                    .as_bool()
                    .unwrap_or(true),
                mapped_endpoints: observation["mapped_endpoints"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(|value| value.as_str().map(str::to_owned))
                    .collect(),
            })
    };
    let left_observed = binding_for(&left_identity.node_id);
    let right_observed = binding_for(&right_identity.node_id);
    let left_egress = egress_for(&left_identity.node_id);
    let right_egress = egress_for(&right_identity.node_id);
    if left_prefixes.is_empty() {
        left_prefixes = observed_prefixes(left_observed)?;
    }
    if right_prefixes.is_empty() {
        right_prefixes = observed_prefixes(right_observed)?;
    }
    if left_prefixes.is_empty() || right_prefixes.is_empty() {
        let topology: Topology = serde_json::from_value(client.call(&Request::Topology).await?)
            .map_err(|error| err_usage(&format!("invalid topology response: {error}")))?;
        if left_prefixes.is_empty() {
            left_prefixes = wireguard::derive_physical_prefixes(&topology, &left_identity.hostname);
        }
        if right_prefixes.is_empty() {
            right_prefixes =
                wireguard::derive_physical_prefixes(&topology, &right_identity.hostname);
        }
    }
    let plan = wireguard::plan_link(
        value("--interface").unwrap_or_else(|| "mycelium0".into()),
        wireguard::GatewayBinding {
            identity: left_identity,
            public_key: value("--left-key")
                .or_else(|| observed_string(left_observed, "public_key")),
            endpoint: value("--left-endpoint")
                .or_else(|| observed_string(left_observed, "endpoint")),
            advertised_prefixes: left_prefixes,
            translation: translation("--left-translation")?,
            egress: left_egress,
        },
        wireguard::GatewayBinding {
            identity: right_identity,
            public_key: value("--right-key")
                .or_else(|| observed_string(right_observed, "public_key")),
            endpoint: value("--right-endpoint")
                .or_else(|| observed_string(right_observed, "endpoint")),
            advertised_prefixes: right_prefixes,
            translation: translation("--right-translation")?,
            egress: right_egress,
        },
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
    )
    .map_err(|error| err_usage(&error))?;
    if args.iter().any(|arg| arg == "--json") {
        return Ok(vec![serde_json::to_string(&plan).map_err(|error| {
            err_usage(&format!("serialize WireGuard plan: {error}"))
        })?]);
    }
    let mut lines = vec![format!(
        "WireGuard link {}: {} ({}) <-> {} ({})",
        plan.interface,
        plan.left.local.hostname,
        plan.left.local.site,
        plan.right.local.hostname,
        plan.right.local.site
    )];
    lines.push(format!(
        "  status: {}",
        if plan.ready { "ready" } else { "blocked" }
    ));
    lines.push(format!("  path: {:?}", plan.path).to_lowercase());
    lines.push(format!("  reason: {}", plan.path_reason));
    for export in &plan.prefix_exports {
        lines.push(
            format!(
                "  export: {} {}/{} via {} translation={:?}",
                export.site,
                export.prefix.address,
                export.prefix.length,
                export.gateway,
                export.translation
            )
            .to_lowercase(),
        );
    }
    for blocker in &plan.blockers {
        lines.push(format!("  blocker: {blocker}"));
    }
    lines.push(format!(
        "  topology: {} planned WireGuard bindings",
        plan.topology_bindings.len()
    ));
    Ok(lines)
}

async fn update(args: &[String]) -> Result<Vec<String>, ClientError> {
    if args.first().map(String::as_str) == Some("policy") {
        return update_policy_command(&args[1..]);
    }
    if args.first().map(String::as_str) == Some("auto-run") {
        return update_auto_run().await;
    }
    let flags = parse_flags(args);
    let action = flags.rest.first().map(String::as_str).unwrap_or("status");
    let fail_on_updates = args.iter().any(|arg| arg == "--fail-on-updates");
    if action == "apply" {
        let executable = std::env::current_exe().map_err(ClientError::Io)?;
        myceliumd::software_apt::require_native_executable(&executable).map_err(|error| err_usage(&error.to_string()))?;
        if let Some(path) = flags.path.as_deref() {
            myceliumd::software_apt::require_native_executable(std::path::Path::new(path)).map_err(|error| err_usage(&error.to_string()))?;
        }
    }
    let channel = flags.channel.unwrap_or_else(myceliumd::updates::channel);
    let targets = mycelium_peer_protocol::local_compatible_targets();
    let mut client = connect().await?;
    if action == "report" {
        let peers = client.call(&Request::PeerList).await?;
        let releases = client.call(&Request::ReleaseList).await?;
        let report = build_update_report(&peers, &releases, &channel, &targets, flags.json);
        if fail_on_updates && report.update_available > 0 {
            for line in &report.lines {
                println!("{line}");
            }
            let _ = std::io::stdout().flush();
            std::process::exit(1);
        }
        return Ok(report.lines);
    }
    if action == "status" && flags.fleet {
        let peers = client.call(&Request::PeerList).await?;
        let releases = client.call(&Request::ReleaseList).await?;
        return render_fleet_update_status(&peers, &releases, &channel, flags.json);
    }
    let value = client.call(&Request::ReleaseList).await?;
    let releases = myceliumd::updates::parse_releases(&value);
    let release = myceliumd::updates::select_release(&releases, &channel, &targets).cloned();
    let Some(release) = release else {
        return Err(err_usage(&format!(
            "no `{channel}` release for compatible targets {}",
            targets.join(", ")
        )));
    };
    release
        .verify()
        .map_err(|error| err_usage(&format!("release signature: {error}")))?;
    let artifact = myceliumd::artifacts_dir().join(&release.artifact_digest);
    let available = artifact.is_file();
    if action == "status" {
        let state = myceliumd::read_update_state();
        let installed_digest = std::env::current_exe()
            .ok()
            .and_then(|path| std::fs::read(path).ok())
            .map(|bytes| mycelium_peer_protocol::sha256_hex(&bytes));
        let status = serde_json::json!({
            "release": release,
            "artifact": artifact,
            "available": available,
            "installed_digest": installed_digest,
            "activation": state,
        });
        return if flags.json {
            Ok(vec![status.to_string()])
        } else {
            Ok(vec![
                format!(
                    "release {} channel={} target={} artifact={}",
                    status["release"]["version"].as_str().unwrap_or("?"),
                    channel,
                    status["release"]["target"].as_str().unwrap_or("?"),
                    if available { "ready" } else { "downloading" },
                ),
                format!(
                    "installed={} activation={} error={}",
                    status["installed_digest"].as_str().unwrap_or("unknown"),
                    status["activation"]["activation_state"]
                        .as_str()
                        .filter(|v| !v.is_empty())
                        .unwrap_or("unrecorded"),
                    status["activation"]["last_error"]
                        .as_str()
                        .unwrap_or("none"),
                ),
            ])
        };
    }
    if action != "apply" {
        return Err(err_usage(&format!("unknown update action `{action}`")));
    }
    if !flags.write {
        return Err(ClientError::Rpc {
            message: "update activation requires --write".into(),
            kind: "writes_not_permitted".into(),
        });
    }
    if !available {
        return Err(err_usage("release artifact has not finished downloading"));
    }
    let bytes = std::fs::read(&artifact).map_err(ClientError::Io)?;
    if bytes.len() as u64 != release.artifact_size
        || mycelium_peer_protocol::sha256_hex(&bytes) != release.artifact_digest
    {
        return Err(err_usage(
            "release artifact failed final size/digest verification",
        ));
    }
    let destination = match flags.path {
        Some(path) => std::path::PathBuf::from(path),
        None => std::env::current_exe().map_err(ClientError::Io)?,
    };
    let activation = activate_update(&mut client, &artifact, &destination).await;
    let mut state = myceliumd::UpdateState {
        release_version: Some(release.version.clone()),
        release_digest: Some(release.artifact_digest.clone()),
        release_target: Some(release.target.clone()),
        activation_state: if activation.is_ok() {
            "active"
        } else {
            "failed"
        }
        .into(),
        activated_at: activation.is_ok().then(unix_now),
        last_error: activation.as_ref().err().map(ToString::to_string),
        staged_digest: Some(release.artifact_digest.clone()),
        staged_since: Some(unix_now()),
        last_attempt_at: Some(unix_now()),
    };
    if let Err(error) = myceliumd::write_update_state(&state) {
        state.last_error = Some(format!("could not persist update state: {error}"));
        return Err(ClientError::Io(error));
    }
    activation?;
    Ok(vec![format!(
        "activated {} for {} from {}",
        release.version,
        release.target,
        artifact.display()
    )])
}

fn update_policy_command(args: &[String]) -> Result<Vec<String>, ClientError> {
    let action = args.first().map(String::as_str).unwrap_or("status");
    if action == "status" {
        let policy = myceliumd::read_update_policy();
        if args.iter().any(|argument| argument == "--json") {
            return Ok(vec![
                serde_json::to_string(&policy).map_err(|error| err_usage(&error.to_string()))?
            ]);
        }
        return Ok(vec![format!(
            "automatic updates: {} channel={} minimum_age={}s rollout_window={}s retry_backoff={}s",
            if policy.enabled {
                "enabled"
            } else {
                "disabled"
            },
            policy.channel,
            policy.minimum_age_secs,
            policy.rollout_window_secs,
            policy.retry_backoff_secs
        )]);
    }
    if !args.iter().any(|argument| argument == "--write") {
        return Err(ClientError::Rpc {
            message: "update policy changes require --write".into(),
            kind: "writes_not_permitted".into(),
        });
    }
    let mut policy = myceliumd::read_update_policy();
    match action {
        "enable" => {
            myceliumd::software_apt::require_native_executable(&std::env::current_exe().map_err(ClientError::Io)?).map_err(|error| err_usage(&error.to_string()))?;
            policy.enabled = true;
            if let Some(channel) = update_arg(args, "--channel") {
                policy.channel = channel.to_owned();
            }
            if let Some(value) = update_arg(args, "--minimum-age") {
                policy.minimum_age_secs = parse_update_duration(value)?;
            }
            if let Some(value) = update_arg(args, "--retry-backoff") {
                policy.retry_backoff_secs = parse_update_duration(value)?;
            }
            if let Some(value) = update_arg(args, "--rollout-window") {
                policy.rollout_window_secs = parse_update_duration(value)?;
            }
        }
        "disable" => policy.enabled = false,
        other => {
            return Err(err_usage(&format!(
                "unknown update policy action `{other}`"
            )))
        }
    }
    policy.validate().map_err(|error| err_usage(&error))?;
    myceliumd::write_update_policy(&policy).map_err(ClientError::Io)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(
            myceliumd::update_policy_path(),
            std::fs::Permissions::from_mode(0o600),
        )
        .map_err(ClientError::Io)?;
    }
    if policy.enabled {
        install_update_scheduler()?;
    }
    Ok(vec![format!(
        "automatic updates {} for channel {}",
        if policy.enabled {
            "enabled"
        } else {
            "disabled"
        },
        policy.channel
    )])
}

async fn update_auto_run() -> Result<Vec<String>, ClientError> {
    myceliumd::software_apt::require_native_executable(&std::env::current_exe().map_err(ClientError::Io)?).map_err(|error| err_usage(&error.to_string()))?;
    let policy = myceliumd::read_update_policy();
    policy.validate().map_err(|error| err_usage(&error))?;
    if !policy.enabled {
        return Ok(vec!["automatic updates disabled".into()]);
    }
    let mut client = connect().await?;
    let release_list = client.call(&Request::ReleaseList).await?;
    let releases = myceliumd::updates::parse_releases(&release_list);
    let targets = mycelium_peer_protocol::local_compatible_targets();
    let Some(release) =
        myceliumd::updates::select_release(&releases, &policy.channel, &targets).cloned()
    else {
        return Ok(vec![format!(
            "no compatible signed release on channel {}",
            policy.channel
        )]);
    };
    release
        .verify()
        .map_err(|error| err_usage(&format!("release signature: {error}")))?;
    let artifact = myceliumd::artifacts_dir().join(&release.artifact_digest);
    if !artifact.is_file() {
        return Ok(vec![format!(
            "release {} is still downloading",
            release.version
        )]);
    }
    // `running_release` is the single source of truth for what is executing:
    // it prefers a published release whose digest matches the binary, then the
    // recorded state, and reports whether that identity was verified.
    let running = myceliumd::updates::running_release(&releases);
    if running.digest.as_deref() == Some(release.artifact_digest.as_str()) {
        return Ok(vec![format!(
            "release {} is already active",
            release.version
        )]);
    }

    let now = unix_now();
    let mut state = myceliumd::read_update_state();
    match automatic_upgrade_allowed(&running, &release.version) {
        Err(reason) => return Ok(vec![reason]),
        // A host running a local build is not a downgrade target: record why
        // the signed release is being installed over it, then continue.
        Ok(Some(note)) => eprintln!("mycelium: {note}"),
        Ok(None) => {}
    }
    if state.staged_digest.as_deref() != Some(&release.artifact_digest) {
        state.staged_digest = Some(release.artifact_digest.clone());
        state.staged_since = Some(now);
        state.activation_state = "staged".into();
        state.last_error = None;
        myceliumd::write_update_state(&state).map_err(ClientError::Io)?;
        return Ok(vec![format!(
            "staged {}; minimum age starts now",
            release.version
        )]);
    }
    let eligible_at = state
        .staged_since
        .unwrap_or(now)
        .saturating_add(policy.minimum_age_secs)
        .saturating_add(node_rollout_offset(policy.rollout_window_secs));
    if now < eligible_at {
        return Ok(vec![format!(
            "release {} waits {}s for minimum age",
            release.version,
            eligible_at - now
        )]);
    }
    if state.last_error.is_some()
        && state
            .last_attempt_at
            .is_some_and(|attempt| now < attempt.saturating_add(policy.retry_backoff_secs))
    {
        return Ok(vec![format!(
            "release {} is in retry backoff",
            release.version
        )]);
    }
    state.activation_state = "activating".into();
    state.last_attempt_at = Some(now);
    myceliumd::write_update_state(&state).map_err(ClientError::Io)?;
    drop(client);
    let apply = vec![
        "apply".to_owned(),
        "--channel".to_owned(),
        policy.channel,
        "--write".to_owned(),
    ];
    Box::pin(update(&apply)).await
}

fn update_arg<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    args.iter()
        .position(|argument| argument == name)
        .and_then(|index| args.get(index + 1))
        .map(String::as_str)
}

fn parse_update_duration(value: &str) -> Result<u64, ClientError> {
    let split = value
        .find(|character: char| !character.is_ascii_digit())
        .ok_or_else(|| err_usage("duration needs an explicit s, m, h, or d suffix"))?;
    let amount = value[..split]
        .parse::<u64>()
        .map_err(|_| err_usage("invalid duration"))?;
    let multiplier = match &value[split..] {
        "s" => 1,
        "m" => 60,
        "h" => 3600,
        "d" => 86_400,
        _ => return Err(err_usage("duration needs an explicit s, m, h, or d suffix")),
    };
    amount
        .checked_mul(multiplier)
        .ok_or_else(|| err_usage("duration is too large"))
}

fn node_rollout_offset(window_secs: u64) -> u64 {
    if window_secs == 0 {
        return 0;
    }
    let identity = std::fs::read(myceliumd::home_dir().join("pki/node.pem"))
        .unwrap_or_else(|_| myceliumd::home_dir().to_string_lossy().as_bytes().to_vec());
    let digest = mycelium_peer_protocol::sha256_hex(&identity);
    u64::from_str_radix(&digest[..16], 16).unwrap_or_default() % window_secs
}

/// May the updater replace what is running with `candidate`, automatically?
///
/// A verified release is a floor: the updater never steps a host back from a
/// release it is actually running. A recorded release that no longer matches the
/// bytes on disk is *not* a floor, because keeping it would freeze the host the
/// moment a local build replaced a newer release — the channel may never publish
/// anything above that recorded version again. Such a host converges to the
/// channel's newest signed release, with a note explaining why.
fn automatic_upgrade_allowed(
    running: &myceliumd::updates::RunningRelease,
    candidate: &str,
) -> Result<Option<String>, String> {
    let Some(active) = running.version.as_deref() else {
        return Err(format!(
            "release {candidate} requires one manual signed bootstrap activation"
        ));
    };
    let candidate_version = semver::Version::parse(candidate)
        .map_err(|error| format!("candidate release version `{candidate}` is invalid: {error}"))?;
    if !running.digest_matches {
        return Ok(Some(format!(
            "running binary is a local build, not the recorded release {active}; installing signed {candidate} to return to the release channel"
        )));
    }
    let active_version = semver::Version::parse(active)
        .map_err(|error| format!("active release version `{active}` is invalid: {error}"))?;
    if candidate_version <= active_version {
        return Err(format!(
            "refusing automatic non-upgrade: active={active} candidate={candidate}"
        ));
    }
    Ok(None)
}

fn install_update_scheduler() -> Result<(), ClientError> {
    let executable = std::env::current_exe().map_err(ClientError::Io)?;
    if cfg!(target_os = "macos") {
        let home = std::env::var_os("HOME")
            .map(std::path::PathBuf::from)
            .ok_or_else(|| err_usage("HOME is not set"))?;
        let path = home.join("Library/LaunchAgents/dev.fpl.mycelium-updater.plist");
        let log = myceliumd::home_dir().join("update.log");
        let plist = format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\"><dict>\n<key>Label</key><string>dev.fpl.mycelium-updater</string>\n<key>ProgramArguments</key><array><string>{}</string><string>update</string><string>auto-run</string></array>\n<key>EnvironmentVariables</key><dict><key>MYCELIUM_NO_AUTOSTART</key><string>1</string></dict>\n<key>StartInterval</key><integer>300</integer><key>RunAtLoad</key><true/>\n<key>StandardOutPath</key><string>{}</string><key>StandardErrorPath</key><string>{}</string>\n</dict></plist>\n",
            xml_update(&executable.to_string_lossy()),
            xml_update(&log.to_string_lossy()),
            xml_update(&log.to_string_lossy())
        );
        std::fs::write(&path, plist).map_err(ClientError::Io)?;
        let domain = format!("gui/{}", uid()?);
        let _ = std::process::Command::new("launchctl")
            .args(["bootout", &format!("{domain}/dev.fpl.mycelium-updater")])
            .status();
        let status = std::process::Command::new("launchctl")
            .args(["bootstrap", &domain, &path.to_string_lossy()])
            .status()
            .map_err(ClientError::Io)?;
        if !status.success() {
            return Err(err_usage("could not install automatic update LaunchAgent"));
        }
        return Ok(());
    }
    if cfg!(target_os = "linux") {
        let system = matches!(active_supervisor(), Some(Supervisor::SystemdSystem));
        let dir = if system {
            std::path::PathBuf::from("/etc/systemd/system")
        } else {
            std::env::var_os("HOME")
                .map(std::path::PathBuf::from)
                .ok_or_else(|| err_usage("HOME is not set"))?
                .join(".config/systemd/user")
        };
        if executable.to_string_lossy().contains(char::is_whitespace) {
            return Err(err_usage(
                "automatic updater binary path may not contain whitespace",
            ));
        }
        std::fs::create_dir_all(&dir).map_err(ClientError::Io)?;
        std::fs::write(
            dir.join("mycelium-update.service"),
            systemd_update_service(&executable, &myceliumd::home_dir())?,
        )
        .map_err(ClientError::Io)?;
        std::fs::write(
            dir.join("mycelium-update.timer"),
            "[Unit]\nDescription=Check for Mycelium updates\n\n[Timer]\nOnBootSec=2m\nOnUnitActiveSec=5m\nPersistent=true\n\n[Install]\nWantedBy=timers.target\n",
        )
        .map_err(ClientError::Io)?;
        let mut reload = std::process::Command::new("systemctl");
        if !system {
            reload.arg("--user");
        }
        let status = reload
            .arg("daemon-reload")
            .status()
            .map_err(ClientError::Io)?;
        if !status.success() {
            return Err(err_usage("systemd daemon-reload failed"));
        }
        let mut enable = std::process::Command::new("systemctl");
        if !system {
            enable.arg("--user");
        }
        let status = enable
            .args(["enable", "--now", "mycelium-update.timer"])
            .status()
            .map_err(ClientError::Io)?;
        if !status.success() {
            return Err(err_usage("could not enable Mycelium update timer"));
        }
        return Ok(());
    }
    Err(err_usage(
        "automatic updates are unsupported on this platform",
    ))
}

fn systemd_update_service(
    executable: &std::path::Path,
    home: &std::path::Path,
) -> Result<String, ClientError> {
    let executable = executable
        .to_str()
        .ok_or_else(|| err_usage("updater path is not UTF-8"))?;
    let home = home
        .to_str()
        .ok_or_else(|| err_usage("Mycelium home is not UTF-8"))?;
    if [executable, home]
        .iter()
        .any(|path| path.contains(char::is_whitespace) || path.contains(['%', '"', '\\']))
    {
        return Err(err_usage(
            "updater paths must not contain whitespace or systemd escape characters",
        ));
    }
    Ok(format!("[Unit]\nDescription=Mycelium safe automatic update\nAfter=mycelium.service\n\n[Service]\nType=oneshot\nEnvironment=MYCELIUM_NO_AUTOSTART=1\nEnvironment=MYCELIUM_HOME={home}\nEnvironmentFile={home}/node.env\nExecStart={executable} update auto-run\nExecStart={executable} software auto-run\n"))
}

fn xml_update(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}


struct UpdateReport {
    lines: Vec<String>,
    update_available: usize,
}

fn fleet_update_rows(
    peers: &serde_json::Value,
    releases: &[mycelium_peer_protocol::ReleaseManifest],
    channel: &str,
) -> Vec<serde_json::Value> {
    let local_targets = mycelium_peer_protocol::local_compatible_targets();
    peers
        .as_array()
        .into_iter()
        .flatten()
        .map(|peer| {
            let metrics = &peer["health"]["platform_metrics"];
            let target = metrics["mycelium_update.release_target"]
                .as_str()
                .filter(|value| !value.is_empty());
            let targets = target
                .map(|target| vec![target.to_owned()])
                .unwrap_or_else(|| local_targets.clone());
            let latest = myceliumd::updates::select_release(releases, channel, &targets);
            let installed = metrics["mycelium_update.release_version"]
                .as_str()
                .filter(|value| !value.is_empty());
            let verdict = latest.map(|release| {
                myceliumd::updates::version_verdict(installed, &release.version)
            });
            let (verdict, needs_update) = match verdict {
                Some(myceliumd::updates::VersionVerdict::Current) => ("current", Some(false)),
                Some(myceliumd::updates::VersionVerdict::UpdateAvailable) => {
                    ("update-available", Some(true))
                }
                Some(myceliumd::updates::VersionVerdict::Ahead) => ("ahead", Some(false)),
                Some(myceliumd::updates::VersionVerdict::Unknown) | None => ("unknown", None),
            };
            serde_json::json!({
                "node_id": peer["hello"]["node_id"],
                "hostname": peer["hello"]["hostname"],
                "daemon_version": peer["hello"]["daemon_version"],
                "last_seen": peer["last_seen"],
                "installed_digest": metrics["mycelium_update.installed_digest"],
                "staged_digest": metrics["mycelium_update.staged_digest"],
                "staged_version": metrics["mycelium_update.staged_version"],
                "staged_state": metrics["mycelium_update.staged_state"],
                "release_version": metrics["mycelium_update.release_version"],
                "release_target": metrics["mycelium_update.release_target"],
                "latest_version": latest.map(|release| release.version.clone()),
                "latest_target": latest.map(|release| release.target.clone()),
                "verdict": verdict,
                "needs_update": needs_update,
                "activation_state": metrics["mycelium_update.activation_state"],
                "last_error": metrics["mycelium_update.last_error"],
            })
        })
        .collect()
}

fn render_fleet_update_status(
    peers: &serde_json::Value,
    releases: &serde_json::Value,
    channel: &str,
    json: bool,
) -> Result<Vec<String>, ClientError> {
    let releases = myceliumd::updates::parse_releases(releases);
    let rows = fleet_update_rows(peers, &releases, channel);
    if json {
        return Ok(vec![serde_json::Value::Array(rows).to_string()]);
    }
    let mut lines = vec![format!("fleet update status (channel={channel}):")];
    for row in rows {
        let update = match row["verdict"].as_str() {
            Some("update-available") => "available",
            Some("current") => "current",
            Some("ahead") => "ahead",
            _ => "unknown",
        };
        lines.push(format!(
            "  {} daemon={} installed={} latest={} update={} state={} staged={} staged_state={} digest={} error={}",
            row["hostname"].as_str().unwrap_or("?"),
            row["daemon_version"].as_str().unwrap_or("?"),
            row["release_version"].as_str().unwrap_or("unrecorded"),
            row["latest_version"].as_str().unwrap_or("unknown"),
            update,
            row["activation_state"].as_str().unwrap_or("unrecorded"),
            row["staged_version"].as_str().unwrap_or("none"),
            row["staged_state"].as_str().unwrap_or("unknown"),
            row["installed_digest"].as_str().unwrap_or("unknown"),
            row["last_error"].as_str().unwrap_or("none"),
        ));
    }
    Ok(lines)
}

fn build_update_report(
    peers: &serde_json::Value,
    releases_value: &serde_json::Value,
    channel: &str,
    targets: &[String],
    json: bool,
) -> UpdateReport {
    let releases = myceliumd::updates::parse_releases(releases_value);
    let rows = fleet_update_rows(peers, &releases, channel);
    let count = |verdict: &str| {
        rows.iter()
            .filter(|row| row["verdict"] == verdict)
            .count()
    };
    let current = count("current");
    let update_available = count("update-available");
    let ahead = count("ahead");
    let unknown = count("unknown");
    let total = rows.len();

    let running = myceliumd::updates::running_release(&releases);
    let latest = myceliumd::updates::select_release(&releases, channel, targets);
    let local_verdict = match latest {
        Some(latest) if running.digest_matches => {
            match myceliumd::updates::version_verdict(
                running.version.as_deref(),
                &latest.version,
            ) {
                myceliumd::updates::VersionVerdict::Current => "current",
                myceliumd::updates::VersionVerdict::UpdateAvailable => "update-available",
                myceliumd::updates::VersionVerdict::Ahead => "ahead",
                myceliumd::updates::VersionVerdict::Unknown => "unknown",
            }
        }
        Some(_) => "unverified",
        None => "unknown",
    };
    let local_needs_update = local_verdict == "update-available";
    let local = serde_json::json!({
        "version": running.version,
        "source": running.source,
        "digest": running.digest,
        "digest_matches": running.digest_matches,
        "latest_version": latest.map(|release| release.version.clone()),
        "latest_target": latest.map(|release| release.target.clone()),
        "verdict": local_verdict,
    });
    let spores = serde_json::json!({
        "supported": false,
        "reason": "Spore Store is not implemented; see mycelium-6sm2"
    });
    if json {
        return UpdateReport {
            lines: vec![serde_json::json!({
                "channel": channel,
                "local": local,
                "summary": {
                    "total": total,
                    "current": current,
                    "update_available": update_available,
                    "ahead": ahead,
                    "unknown": unknown,
                },
                "hosts": rows,
                "spores": spores,
            })
            .to_string()],
            update_available: update_available + usize::from(local_needs_update),
        };
    }

    let local_version = local["version"].as_str().unwrap_or("unrecorded");
    let local_source = local["source"].as_str().unwrap_or("unrecorded");
    let local_latest = local["latest_version"].as_str().unwrap_or("unknown");
    let local_target = local["latest_target"].as_str().unwrap_or("unknown");
    let mut lines = vec![format!("update report (channel={channel}):")];
    lines.push(format!(
        "  local: {local_version} ({local_source}), latest={local_latest} target={local_target} verdict={local_verdict}"
    ));
    lines.push(format!(
        "  hosts: {total} total, {current} current, {update_available} need update, {ahead} ahead, {unknown} unknown"
    ));
    let needed = rows
        .iter()
        .filter(|row| row["verdict"] == "update-available")
        .collect::<Vec<_>>();
    if needed.is_empty() {
        lines.push("  need update: none".into());
    } else {
        lines.push("  need update:".into());
        for row in needed {
            lines.push(format!(
                "    {} {} -> {}",
                row["hostname"].as_str().unwrap_or("?"),
                row["release_version"].as_str().unwrap_or("unrecorded"),
                row["latest_version"].as_str().unwrap_or("unknown"),
            ));
        }
    }
    if unknown > 0 {
        lines.push("  unknown:".into());
        for row in rows.iter().filter(|row| row["verdict"] == "unknown") {
            lines.push(format!(
                "    {} (release unrecorded)",
                row["hostname"].as_str().unwrap_or("?")
            ));
        }
    }
    lines.push(format!(
        "  spores: no catalog ({})",
        spores["reason"].as_str().unwrap_or("unavailable")
    ));
    UpdateReport {
        lines,
        update_available: update_available + usize::from(local_needs_update),
    }
}

async fn activate_update(
    client: &mut Client,
    artifact: &std::path::Path,
    destination: &std::path::Path,
) -> Result<(), ClientError> {
    myceliumd::software_apt::require_native_executable(destination).map_err(|error| err_usage(&error.to_string()))?;
    use std::os::unix::fs::PermissionsExt;
    let parent = destination
        .parent()
        .ok_or_else(|| err_usage("installed binary has no parent directory"))?;
    let name = destination
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| err_usage("installed binary name is not UTF-8"))?;
    let candidate = parent.join(format!(".{name}.candidate"));
    let previous = parent.join(format!(".{name}.previous"));
    let failed = parent.join(format!(".{name}.failed"));
    std::fs::copy(artifact, &candidate).map_err(ClientError::Io)?;
    let mode = std::fs::metadata(destination)
        .map_err(ClientError::Io)?
        .permissions()
        .mode();
    std::fs::set_permissions(&candidate, std::fs::Permissions::from_mode(mode))
        .map_err(ClientError::Io)?;
    let check = std::process::Command::new(&candidate)
        .arg("_self-check")
        .output()
        .map_err(ClientError::Io)?;
    if !check.status.success() {
        return Err(err_usage("candidate binary failed self-check"));
    }
    let supervisor = active_supervisor();
    if let Some(supervisor) = supervisor {
        if let Some(pid) = supervisor.systemd_pid()? {
            if !supervised_peer_matches(pid, client.peer_pid()?) {
                return Err(err_usage("socket daemon is not owned by the Mycelium supervisor; reconcile the service before updating"));
            }
        }
    }
    if let Some(supervisor) = supervisor {
        supervisor.stop()?;
    } else {
        let _ = client.request(&Request::Shutdown).await;
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    }
    if previous.exists() {
        std::fs::remove_file(&previous).map_err(ClientError::Io)?;
    }
    std::fs::rename(destination, &previous).map_err(ClientError::Io)?;
    if let Err(error) = std::fs::rename(&candidate, destination) {
        let _ = std::fs::rename(&previous, destination);
        return Err(ClientError::Io(error));
    }
    start_daemon(supervisor, destination)?;
    if wait_for_daemon(supervisor).await.is_ok() {
        return Ok(());
    }

    if let Some(supervisor) = supervisor {
        let _ = supervisor.stop();
    }
    let _ = std::fs::rename(destination, &failed);
    std::fs::rename(&previous, destination).map_err(ClientError::Io)?;
    start_daemon(supervisor, destination)?;
    wait_for_daemon(supervisor).await.map_err(|_| {
        ClientError::Protocol(
            "candidate failed health check; rollback daemon also failed to start".into(),
        )
    })?;
    Err(ClientError::Protocol(
        "candidate failed health check and was rolled back".into(),
    ))
}

#[derive(Clone, Copy)]
enum Supervisor {
    Systemd,
    SystemdSystem,
    Launchd,
}

impl Supervisor {
    fn systemd_pid(self) -> Result<Option<u32>, ClientError> {
        let system = match self {
            Self::Systemd => false,
            Self::SystemdSystem => true,
            Self::Launchd => return Ok(None),
        };
        let mut command = std::process::Command::new("systemctl");
        if !system {
            command.arg("--user");
        }
        let output = command
            .args(["show", "mycelium", "--property=MainPID", "--value"])
            .output()
            .map_err(ClientError::Io)?;
        if !output.status.success() {
            return Err(err_usage("cannot inspect supervised Mycelium PID"));
        }
        let pid = String::from_utf8_lossy(&output.stdout)
            .trim()
            .parse::<u32>()
            .map_err(|_| err_usage("invalid supervised Mycelium PID"))?;
        Ok(Some(pid))
    }

    fn stop(self) -> Result<(), ClientError> {
        let status = match self {
            Self::Systemd => std::process::Command::new("systemctl")
                .args(["--user", "stop", "mycelium"])
                .status(),
            Self::SystemdSystem => std::process::Command::new("systemctl")
                .args(["stop", "mycelium"])
                .status(),
            Self::Launchd => std::process::Command::new("launchctl")
                .args(["bootout", &format!("gui/{}/dev.fpl.mycelium", uid()?)])
                .status(),
        }
        .map_err(ClientError::Io)?;
        if status.success() {
            Ok(())
        } else {
            Err(err_usage("failed to stop the Mycelium service supervisor"))
        }
    }

    fn start(self) -> Result<(), ClientError> {
        let status = match self {
            Self::Systemd => std::process::Command::new("systemctl")
                .args(["--user", "start", "mycelium"])
                .status(),
            Self::SystemdSystem => std::process::Command::new("systemctl")
                .args(["start", "mycelium"])
                .status(),
            Self::Launchd => std::process::Command::new("launchctl")
                .args([
                    "bootstrap",
                    &format!("gui/{}", uid()?),
                    &display_path(
                        &std::env::var_os("HOME")
                            .map(std::path::PathBuf::from)
                            .ok_or_else(|| err_usage("HOME is not set"))?
                            .join("Library/LaunchAgents/dev.fpl.mycelium.plist"),
                    )?,
                ])
                .status(),
        }
        .map_err(ClientError::Io)?;
        if status.success() {
            Ok(())
        } else {
            Err(err_usage("failed to start the Mycelium service supervisor"))
        }
    }
}

fn active_supervisor() -> Option<Supervisor> {
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
            .is_ok_and(|output| {
                output.status.success()
                    && String::from_utf8_lossy(&output.stdout).trim() == "loaded"
            });
        if loaded {
            return Some(Supervisor::Systemd);
        }
        // fungOS enrollment installs a system unit, not a login-session unit.
        // Only select it when it manages this installation's executable.
        let binary = myceliumd::home_dir().join("bin/mycelium");
        let system_unit = std::process::Command::new("systemctl")
            .args(["show", "mycelium", "--property=ExecStart", "--value"])
            .output();
        if system_unit.is_ok_and(|output| {
            output.status.success()
                && system_unit_matches_binary(&String::from_utf8_lossy(&output.stdout), &binary)
        }) {
            return Some(Supervisor::SystemdSystem);
        }
    }
    let uid = uid().ok()?;
    if cfg!(target_os = "macos")
        && std::process::Command::new("launchctl")
            .args(["print", &format!("gui/{uid}/dev.fpl.mycelium")])
            .status()
            .is_ok_and(|status| status.success())
    {
        return Some(Supervisor::Launchd);
    }
    None
}

fn system_unit_matches_binary(exec_start: &str, binary: &std::path::Path) -> bool {
    myceliumd::software_service::exec_start_matches(exec_start, binary)
}

fn uid() -> Result<String, ClientError> {
    let output = std::process::Command::new("id")
        .arg("-u")
        .output()
        .map_err(ClientError::Io)?;
    if !output.status.success() {
        return Err(err_usage("failed to determine the current user id"));
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

fn start_daemon(
    supervisor: Option<Supervisor>,
    binary: &std::path::Path,
) -> Result<(), ClientError> {
    match supervisor {
        Some(supervisor) => supervisor.start(),
        None => spawn_daemon_from(binary),
    }
}

fn display_path(path: &std::path::Path) -> Result<String, ClientError> {
    path.to_str()
        .map(str::to_owned)
        .ok_or_else(|| err_usage("service path is not UTF-8"))
}

fn spawn_daemon_from(binary: &std::path::Path) -> Result<(), ClientError> {
    let home = myceliumd::home_dir();
    let log = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(home.join("daemon.log"))
        .map_err(ClientError::Io)?;
    let stderr = log.try_clone().map_err(ClientError::Io)?;
    use std::os::unix::process::CommandExt;
    std::process::Command::new(binary)
        .arg("_serve")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::from(log))
        .stderr(std::process::Stdio::from(stderr))
        .process_group(0)
        .spawn()
        .map_err(|error| ClientError::Spawn(error.to_string()))?;
    Ok(())
}

fn supervised_peer_matches(supervised_pid: u32, peer_pid: Option<u32>) -> bool {
    supervised_pid != 0 && peer_pid == Some(supervised_pid)
}

async fn wait_for_daemon(supervisor: Option<Supervisor>) -> Result<(), ClientError> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        match Client::try_connect().await {
            Ok(mut client) => {
                if let Some(supervisor) = supervisor {
                    if let Some(pid) = supervisor.systemd_pid()? {
                        if !supervised_peer_matches(pid, client.peer_pid()?) {
                            if std::time::Instant::now() >= deadline {
                                return Err(ClientError::DaemonUnresponsive);
                            }
                            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                            continue;
                        }
                    }
                }
                client.call(&Request::PeerList).await?;
                return Ok(());
            }
            Err(_) if std::time::Instant::now() >= deadline => {
                return Err(ClientError::DaemonUnresponsive)
            }
            Err(_) => tokio::time::sleep(std::time::Duration::from_millis(100)).await,
        }
    }
}

fn render_peers(value: &serde_json::Value) -> Vec<String> {
    let mut lines = vec!["peers:".into()];
    for peer in value.as_array().into_iter().flatten() {
        let hello = &peer["hello"];
        let health = &peer["health"];
        let hostname = hello["hostname"].as_str().unwrap_or("unknown");
        let site = hello["site"].as_str().unwrap_or("unknown");
        let platform = hello["platform"].as_str().unwrap_or("unknown");
        let age = unix_now().saturating_sub(peer["last_seen"].as_u64().unwrap_or(0));
        let load = health["load_average"]
            .as_array()
            .and_then(|values| values.first())
            .and_then(|value| value.as_f64())
            .map(|value| format!("{value:.2}"))
            .unwrap_or_else(|| "-".into());
        let ssh = health["ssh_listening"]
            .as_bool()
            .map(|up| if up { "up" } else { "down" })
            .unwrap_or("-");
        lines.push(format!(
            "  {hostname} site={site} platform={platform} age={age}s load={load} ssh={ssh}"
        ));
    }
    lines
}

async fn resources(args: &[String]) -> Result<Vec<String>, ClientError> {
    let action = args.first().map(String::as_str).unwrap_or("list");
    if action == "watch" {
        return resources_watch(&args[1..]).await;
    }
    let show = if action == "show" {
        Some(
            args.get(1)
                .ok_or_else(|| err_usage("resources show needs a resource ID"))?,
        )
    } else {
        None
    };
    let mut kind = None;
    let mut node = None;
    let mut json = false;
    let start = if action == "show" { 2 } else { 0 };
    let mut index = start;
    while index < args.len() {
        match args[index].as_str() {
            "--kind" => {
                index += 1;
                kind = Some(
                    args.get(index)
                        .ok_or_else(|| err_usage("resources --kind needs a value"))?
                        .clone(),
                );
            }
            "--node" => {
                index += 1;
                node = Some(
                    args.get(index)
                        .ok_or_else(|| err_usage("resources --node needs a value"))?
                        .clone(),
                );
            }
            "--json" => json = true,
            "list" if index == 0 => {}
            argument => {
                return Err(err_usage(&format!(
                    "unknown resources argument `{argument}`"
                )))
            }
        }
        index += 1;
    }
    let mut client = connect().await?;
    let value = client.call(&Request::Resources).await?;
    let catalog: fpl_resource_observation::ResourceCatalog = serde_json::from_value(value)
        .map_err(|error| err_usage(&format!("bad resource catalog: {error}")))?;
    let catalog = filter_resources(
        catalog,
        show.map(String::as_str),
        kind.as_deref(),
        node.as_deref(),
    );
    if show.is_some() && catalog.observations.is_empty() {
        return Err(err_usage("unknown resource"));
    }
    if json {
        return Ok(vec![
            serde_json::to_string(&catalog).map_err(|error| err_usage(&error.to_string()))?
        ]);
    }
    Ok(render_resources(&catalog))
}

async fn services(args: &[String]) -> Result<Vec<String>, ClientError> {
    let action = args.first().map(String::as_str).unwrap_or("list");
    if action == "watch" {
        return catalog_watch(Request::Services, &args[1..], "services").await;
    }
    let show = if action == "show" {
        Some(
            args.get(1)
                .ok_or_else(|| err_usage("services show needs a service ID"))?,
        )
    } else {
        None
    };
    let mut kind = None;
    let mut node = None;
    let mut json = false;
    let mut index = if action == "show" { 2 } else { 0 };
    while index < args.len() {
        match args[index].as_str() {
            "--kind" | "--node" => {
                let flag = args[index].clone();
                index += 1;
                let value = args
                    .get(index)
                    .ok_or_else(|| err_usage(&format!("services {flag} needs a value")))?
                    .clone();
                if flag == "--kind" {
                    kind = Some(value);
                } else {
                    node = Some(value);
                }
            }
            "--json" => json = true,
            "list" if index == 0 => {}
            argument => {
                return Err(err_usage(&format!(
                    "unknown services argument `{argument}`"
                )))
            }
        }
        index += 1;
    }
    let mut client = connect().await?;
    let value = client.call(&Request::Services).await?;
    let mut catalog: fpl_resource_observation::ServiceCatalog = serde_json::from_value(value)
        .map_err(|error| err_usage(&format!("bad service catalog: {error}")))?;
    catalog.observations.retain(|observation| {
        show.is_none_or(|id| observation.service_id.0 == *id)
            && kind
                .as_deref()
                .is_none_or(|kind| observation.value.kind == kind)
            && node.as_deref().is_none_or(|node| {
                observation
                    .value
                    .attributes
                    .get("node_id")
                    .is_some_and(|id| id.starts_with(node))
                    || observation
                        .value
                        .attributes
                        .get("node_label")
                        .is_some_and(|label| label == node)
            })
    });
    if show.is_some() && catalog.observations.is_empty() {
        return Err(err_usage("unknown service"));
    }
    if json {
        return Ok(vec![
            serde_json::to_string(&catalog).map_err(|error| err_usage(&error.to_string()))?
        ]);
    }
    Ok(render_service_catalog(&catalog))
}

fn render_service_catalog(catalog: &fpl_resource_observation::ServiceCatalog) -> Vec<String> {
    let now = unix_now();
    let mut lines = vec!["services:".into()];
    for observation in &catalog.observations {
        let state = if observation.is_fresh_at(now) {
            "available"
        } else {
            "expired"
        };
        let node = observation
            .value
            .attributes
            .get("node_label")
            .or_else(|| observation.value.attributes.get("node_id"))
            .map(String::as_str)
            .unwrap_or("unknown");
        lines.push(format!(
            "  {} kind={} node={} state={} confidence={:?}",
            observation.service_id.0, observation.value.kind, node, state, observation.confidence
        ));
        for endpoint in &observation.value.endpoints {
            lines.push(format!("    {endpoint}"));
        }
    }
    lines
}

async fn credential_map(args: &[String]) -> Result<Vec<String>, ClientError> {
    if args.first().map(String::as_str) != Some("map") {
        return Err(err_usage("credentials needs `map list|set|remove`"));
    }
    let action = args.get(1).map(String::as_str).unwrap_or("list");
    match action {
        "list" => {
            let mut client = connect().await?;
            let value = client.call(&Request::CredentialMapList).await?;
            if args.iter().any(|argument| argument == "--json") {
                return Ok(vec![value.to_string()]);
            }
            let mut lines = vec!["credential mappings:".into()];
            for rule in value.as_array().into_iter().flatten() {
                let selectors = rule["addresses"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .chain(rule["cidrs"].as_array().into_iter().flatten())
                    .filter_map(serde_json::Value::as_str)
                    .collect::<Vec<_>>()
                    .join(",");
                lines.push(format!(
                    "  {} driver={} selectors={} sites={} user={} secret={}",
                    rule["name"].as_str().unwrap_or("?"),
                    rule["driver"].as_str().unwrap_or("auto"),
                    selectors,
                    rule["sites"]
                        .as_array()
                        .into_iter()
                        .flatten()
                        .filter_map(serde_json::Value::as_str)
                        .collect::<Vec<_>>()
                        .join(","),
                    rule["username"].as_str().unwrap_or("?"),
                    rule["credential_ref"]
                        .as_str()
                        .map(str::to_owned)
                        .or_else(|| {
                            rule["password_env"]
                                .as_str()
                                .map(|name| format!("env:{name}"))
                        })
                        .or_else(|| rule["key_path"].as_str().map(|_| "key".into()))
                        .unwrap_or_else(|| "missing".into())
                ));
            }
            Ok(lines)
        }
        "set" => {
            let name = args
                .get(2)
                .ok_or_else(|| err_usage("credentials map set needs NAME"))?
                .clone();
            let mut driver = None;
            let mut addresses = Vec::new();
            let mut cidrs = Vec::new();
            let mut sites = Vec::new();
            let mut username = None;
            let mut password_env = None;
            let mut key_path = None;
            let mut credential_ref = None;
            let mut write = false;
            let mut index = 3;
            while index < args.len() {
                let value = |index: usize, flag: &str| {
                    args.get(index + 1)
                        .cloned()
                        .ok_or_else(|| err_usage(&format!("{flag} needs a value")))
                };
                match args[index].as_str() {
                    "--driver" => driver = Some(value(index, "--driver")?),
                    "--address" => addresses.push(
                        value(index, "--address")?
                            .parse()
                            .map_err(|_| err_usage("--address needs an IP address"))?,
                    ),
                    "--cidr" => cidrs.push(value(index, "--cidr")?),
                    "--site" => sites.push(value(index, "--site")?),
                    "--user" => username = Some(value(index, "--user")?),
                    "--password-env" => password_env = Some(value(index, "--password-env")?),
                    "--key" => key_path = Some(value(index, "--key")?),
                    "--credential-ref" => {
                        credential_ref = Some(
                            mycelium_core::CredentialRef::parse(value(index, "--credential-ref")?)
                                .map_err(|error| err_usage(&error))?,
                        )
                    }
                    "--write" => {
                        write = true;
                        index += 1;
                        continue;
                    }
                    argument => {
                        return Err(err_usage(&format!(
                            "unknown credential map argument `{argument}`"
                        )))
                    }
                }
                index += 2;
            }
            let rule = myceliumd::credential_map::CredentialRule {
                name,
                driver,
                addresses,
                cidrs,
                sites,
                username: username.ok_or_else(|| err_usage("credential map needs --user"))?,
                credential_ref,
                password_env,
                key_path,
            };
            let mut client = connect().await?;
            let value = client
                .call(&Request::CredentialMapSet { rule, write })
                .await?;
            Ok(vec![format!(
                "saved credential mapping {}",
                value["name"].as_str().unwrap_or("?")
            )])
        }
        "remove" => {
            let name = args
                .get(2)
                .ok_or_else(|| err_usage("credentials map remove needs NAME"))?
                .clone();
            let write = args.iter().any(|argument| argument == "--write");
            let mut client = connect().await?;
            let value = client
                .call(&Request::CredentialMapRemove { name, write })
                .await?;
            Ok(vec![format!(
                "credential mapping {} removed={}",
                value["name"].as_str().unwrap_or("?"),
                value["removed"].as_bool().unwrap_or(false)
            )])
        }
        _ => Err(err_usage("credentials map needs list, set, or remove")),
    }
}

fn filter_resources(
    mut catalog: fpl_resource_observation::ResourceCatalog,
    resource_id: Option<&str>,
    kind: Option<&str>,
    node: Option<&str>,
) -> fpl_resource_observation::ResourceCatalog {
    let attachment_ids = catalog
        .attachments
        .iter()
        .filter(|attachment| {
            node.is_none_or(|node| {
                attachment.value.host.id.starts_with(node) || attachment.value.host.label == node
            })
        })
        .map(|attachment| attachment.resource_id.clone())
        .collect::<std::collections::BTreeSet<_>>();
    catalog.observations.retain(|observation| {
        resource_id.is_none_or(|id| observation.resource_id.0 == id)
            && kind.is_none_or(|kind| observation.value.kind().as_str() == kind)
            && node.is_none_or(|_| attachment_ids.contains(&observation.resource_id))
    });
    let retained = catalog
        .observations
        .iter()
        .map(|observation| observation.resource_id.clone())
        .collect::<std::collections::BTreeSet<_>>();
    catalog
        .attachments
        .retain(|attachment| retained.contains(&attachment.resource_id));
    catalog
}

fn render_resources(catalog: &fpl_resource_observation::ResourceCatalog) -> Vec<String> {
    let now = unix_now();
    let attachments = catalog
        .attachments
        .iter()
        .map(|attachment| (&attachment.resource_id, attachment))
        .collect::<std::collections::BTreeMap<_, _>>();
    let mut lines = vec!["resources:".into()];
    for observation in &catalog.observations {
        let attachment = attachments.get(&observation.resource_id);
        let host = attachment
            .map(|attachment| attachment.value.host.label.as_str())
            .unwrap_or("unattached");
        let state = if observation.is_fresh_at(now) {
            "available"
        } else {
            "expired"
        };
        lines.push(format!(
            "  {} kind={} node={} state={} confidence={:?}",
            observation.resource_id.0,
            observation.value.kind().as_str(),
            host,
            state,
            observation.confidence
        ));
        lines.push(format!("    {}", observation.value.label));
    }
    lines
}

async fn resources_watch(args: &[String]) -> Result<Vec<String>, ClientError> {
    catalog_watch(Request::Resources, args, "resources").await
}

async fn catalog_watch(
    request: Request,
    args: &[String],
    name: &str,
) -> Result<Vec<String>, ClientError> {
    let once = args.iter().any(|argument| argument == "--once");
    if args.iter().any(|argument| argument != "--once") {
        return Err(err_usage(&format!("{name} watch accepts only --once")));
    }
    let mut client = connect().await?;
    let mut previous = None;
    loop {
        let value = client.call(&request).await?;
        let encoded = serde_json::to_string(&value)
            .map_err(|error| err_usage(&format!("encode resource catalog: {error}")))?;
        if previous.as_ref() != Some(&encoded) {
            println!("{encoded}");
            std::io::stdout().flush().map_err(ClientError::Io)?;
            previous = Some(encoded);
        }
        if once {
            return Ok(Vec::new());
        }
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
}

async fn hardware(args: &[String]) -> Result<Vec<String>, ClientError> {
    let flags = parse_flags(args);
    let selector = flags.rest.first().map(String::as_str);
    let mut client = connect().await?;
    let peers = client.call(&Request::PeerList).await?;
    let mut snapshots = peers
        .as_array()
        .into_iter()
        .flatten()
        .filter(|peer| {
            selector.is_none_or(|selector| {
                peer["origin"]
                    .as_str()
                    .is_some_and(|origin| origin.starts_with(selector))
                    || peer["hello"]["hostname"].as_str() == Some(selector)
            })
        })
        .filter_map(|peer| {
            peer.get("hardware")
                .filter(|value| !value.is_null())
                .cloned()
        })
        .collect::<Vec<_>>();
    snapshots.sort_by(|left, right| left["hostname"].as_str().cmp(&right["hostname"].as_str()));
    if selector.is_some() && snapshots.is_empty() {
        return Err(err_usage("peer has no hardware snapshot or is unknown"));
    }
    if flags.json {
        return Ok(vec![serde_json::Value::Array(snapshots).to_string()]);
    }
    let mut lines = vec!["hardware:".into()];
    for snapshot in snapshots {
        let hostname = snapshot["hostname"].as_str().unwrap_or("unknown");
        let devices = snapshot["devices"].as_array().cloned().unwrap_or_default();
        lines.push(format!("  {hostname} devices={}", devices.len()));
        for device in devices {
            let kind = device["kind"].as_str().unwrap_or("unknown");
            let bus = device["bus"].as_str().unwrap_or("unknown");
            let locator = device["locator"].as_str().unwrap_or("?");
            let model = device["model"].as_str().unwrap_or("unknown");
            let capabilities = device["capabilities"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(serde_json::Value::as_str)
                .collect::<Vec<_>>()
                .join(",");
            let suffix = if capabilities.is_empty() {
                String::new()
            } else {
                format!(" capabilities={capabilities}")
            };
            lines.push(format!(
                "    {kind} bus={bus} locator={locator} model={model}{suffix}"
            ));
        }
    }
    Ok(lines)
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

async fn ssh(args: &[String], command_required: bool) -> Result<Vec<String>, ClientError> {
    let options = SshOptions::parse(args)?;
    if command_required && options.extra.is_empty() {
        return Err(err_usage("exec needs a command after --"));
    }
    let resolved = resolve_ssh(
        &options.device,
        options.user,
        options.identity,
        options.certificate,
        options.port,
    )
    .await?;
    let argv = ssh_argv(
        &resolved.host,
        &resolved.username,
        resolved.port,
        resolved.jump.as_deref(),
        &resolved.identity,
        &resolved.certificate,
        command_required,
        &options.extra,
    );
    if options.json {
        return Ok(vec![resolved.json_with_argv(&argv).to_string()]);
    }
    let status = std::process::Command::new("ssh")
        .args(&argv)
        .status()
        .map_err(|error| err_usage(&format!("could not run SSH: {error}")))?;
    if !status.success() {
        return Err(err_usage(&format!("SSH exited with {status}")));
    }
    Ok(Vec::new())
}

#[derive(Debug)]
struct ResolvedSsh {
    device: String,
    host: String,
    username: String,
    port: u16,
    jump: Option<String>,
    identity: String,
    certificate: String,
}

impl ResolvedSsh {
    fn json_with_argv(&self, argv: &[String]) -> serde_json::Value {
        serde_json::json!({
            "device": self.device,
            "host": self.host,
            "username": self.username,
            "port": self.port,
            "jump": self.jump,
            "identity": self.identity,
            "certificate": self.certificate,
            "argv": argv,
        })
    }
}

async fn resolve_ssh(
    selector: &str,
    user: Option<String>,
    identity: Option<String>,
    certificate: Option<String>,
    port: Option<u16>,
) -> Result<ResolvedSsh, ClientError> {
    let user = match user {
        Some(user) => Some(user),
        None => crate::ssh_access::preferred_unix_user().map_err(|error| err_usage(&error))?,
    };
    let mut client = connect().await?;
    let plan = client
        .call(&Request::SshPlan {
            selector: selector.to_owned(),
            username: user,
        })
        .await?;
    let identity = identity
        .or_else(|| plan["identity"].as_str().map(expand_home))
        .or_else(|| std::env::var("MYCELIUM_SSH_IDENTITY").ok().map(expand_home))
        .unwrap_or_else(|| expand_home("~/.ssh/id_ed25519"));
    let device = plan["device"]
        .as_str()
        .ok_or(err_usage("SSH plan has no device"))?;
    let device_certificate = myceliumd::home_dir().join(format!("ssh/{device}-cert.pub"));
    let personal_certificate = myceliumd::home_dir().join("ssh/user-cert.pub");
    let certificate = select_ssh_certificate(
        certificate,
        std::env::var("MYCELIUM_SSH_CERTIFICATE")
            .ok()
            .map(expand_home),
        &personal_certificate,
        &device_certificate,
    );
    require_readable("SSH identity", &identity)?;
    require_readable("Mycelium SSH certificate", &certificate)?;
    let host = plan["host"]
        .as_str()
        .ok_or(err_usage("SSH plan has no host"))?;
    let username = plan["username"]
        .as_str()
        .ok_or(err_usage("SSH plan has no username"))?;
    Ok(ResolvedSsh {
        device: device.to_owned(),
        host: host.to_owned(),
        username: username.to_owned(),
        port: port.unwrap_or_else(|| plan["port"].as_u64().unwrap_or(22) as u16),
        jump: plan["jump"].as_str().map(str::to_owned),
        identity,
        certificate,
    })
}

fn select_ssh_certificate(
    explicit: Option<String>,
    environment: Option<String>,
    personal: &std::path::Path,
    device: &std::path::Path,
) -> String {
    explicit
        .or(environment)
        .or_else(|| {
            personal
                .is_file()
                .then(|| personal.to_string_lossy().into())
        })
        .or_else(|| device.is_file().then(|| device.to_string_lossy().into()))
        .unwrap_or_else(|| personal.to_string_lossy().into())
}

#[derive(Debug, PartialEq)]
struct SshOptions {
    device: String,
    user: Option<String>,
    identity: Option<String>,
    certificate: Option<String>,
    port: Option<u16>,
    json: bool,
    extra: Vec<String>,
}

impl SshOptions {
    fn parse(args: &[String]) -> Result<Self, ClientError> {
        let device = args
            .first()
            .filter(|value| !value.starts_with('-'))
            .cloned()
            .ok_or(err_usage("ssh needs a device"))?;
        let mut parsed = Self {
            device,
            user: None,
            identity: None,
            certificate: None,
            port: None,
            json: false,
            extra: Vec::new(),
        };
        let mut index = 1;
        while index < args.len() {
            let flag = &args[index];
            if flag == "--" {
                parsed.extra.extend_from_slice(&args[index + 1..]);
                break;
            }
            let take = |index: &mut usize, name: &str| -> Result<String, ClientError> {
                *index += 1;
                args.get(*index)
                    .cloned()
                    .ok_or(err_usage(&format!("ssh needs a value for {name}")))
            };
            match flag.as_str() {
                "--user" => parsed.user = Some(take(&mut index, flag)?),
                "--key" => parsed.identity = Some(expand_home(&take(&mut index, flag)?)),
                "--certificate" => parsed.certificate = Some(expand_home(&take(&mut index, flag)?)),
                "--port" => {
                    let value = take(&mut index, flag)?;
                    let port = value
                        .parse::<u16>()
                        .map_err(|_| err_usage("SSH port must be an integer from 1 to 65535"))?;
                    if port == 0 {
                        return Err(err_usage("SSH port must be an integer from 1 to 65535"));
                    }
                    parsed.port = Some(port);
                }
                "--json" => parsed.json = true,
                other => {
                    return Err(err_usage(&format!(
                        "unknown ssh option `{other}`; pass a remote command after --"
                    )))
                }
            }
            index += 1;
        }
        Ok(parsed)
    }
}

#[derive(Debug, PartialEq)]
struct ScpOptions {
    source: String,
    destination: String,
    user: Option<String>,
    identity: Option<String>,
    certificate: Option<String>,
    port: Option<u16>,
    recursive: bool,
    preserve: bool,
    json: bool,
}

impl ScpOptions {
    fn parse(args: &[String]) -> Result<Self, ClientError> {
        let mut positional = Vec::new();
        let mut parsed = Self {
            source: String::new(),
            destination: String::new(),
            user: None,
            identity: None,
            certificate: None,
            port: None,
            recursive: false,
            preserve: false,
            json: false,
        };
        let mut index = 0;
        while index < args.len() {
            let flag = &args[index];
            let take = |index: &mut usize, name: &str| -> Result<String, ClientError> {
                *index += 1;
                args.get(*index)
                    .cloned()
                    .ok_or(err_usage(&format!("scp needs a value for {name}")))
            };
            match flag.as_str() {
                "--user" => parsed.user = Some(take(&mut index, flag)?),
                "--key" => parsed.identity = Some(expand_home(&take(&mut index, flag)?)),
                "--certificate" => parsed.certificate = Some(expand_home(&take(&mut index, flag)?)),
                "--port" => {
                    let value = take(&mut index, flag)?;
                    let port = value
                        .parse::<u16>()
                        .map_err(|_| err_usage("SCP port must be an integer from 1 to 65535"))?;
                    if port == 0 {
                        return Err(err_usage("SCP port must be an integer from 1 to 65535"));
                    }
                    parsed.port = Some(port);
                }
                "--recursive" | "-r" => parsed.recursive = true,
                "--preserve" | "-p" => parsed.preserve = true,
                "--json" => parsed.json = true,
                "--" => positional.extend_from_slice(&args[index + 1..]),
                value if value.starts_with('-') => {
                    return Err(err_usage(&format!("unknown scp option `{value}`")))
                }
                value => positional.push(value.to_owned()),
            }
            if flag == "--" {
                break;
            }
            index += 1;
        }
        if positional.len() != 2 {
            return Err(err_usage("scp needs exactly SOURCE and DEST"));
        }
        parsed.source = positional.remove(0);
        parsed.destination = positional.remove(0);
        Ok(parsed)
    }
}

fn remote_operand(value: &str) -> Option<(&str, &str)> {
    value
        .split_once(':')
        .filter(|(device, path)| !device.is_empty() && !path.is_empty())
}

async fn scp(args: &[String]) -> Result<Vec<String>, ClientError> {
    let options = ScpOptions::parse(args)?;
    let source_remote = remote_operand(&options.source);
    let destination_remote = remote_operand(&options.destination);
    let (selector, remote_path, uploading) =
        match (source_remote, destination_remote) {
            (None, Some((device, path))) => (device, path, true),
            (Some((device, path)), None) => (device, path, false),
            (Some(_), Some(_)) => return Err(err_usage(
                "scp supports exactly one Mycelium remote; remote-to-remote copies are ambiguous",
            )),
            (None, None) => return Err(err_usage("scp needs one DEVICE:PATH operand")),
        };
    let resolved = resolve_ssh(
        selector,
        options.user,
        options.identity,
        options.certificate,
        options.port,
    )
    .await?;
    let remote = format!("{}@{}:{}", resolved.username, resolved.host, remote_path);
    let (source, destination) = if uploading {
        (options.source.as_str(), remote.as_str())
    } else {
        (remote.as_str(), options.destination.as_str())
    };
    let argv = scp_argv(
        source,
        destination,
        &resolved,
        options.recursive,
        options.preserve,
    );
    if options.json {
        let mut output = resolved.json_with_argv(&argv);
        output["direction"] = serde_json::json!(if uploading { "upload" } else { "download" });
        return Ok(vec![output.to_string()]);
    }
    eprintln!(
        "mycelium: SCP {} through {}; waiting for remote write acknowledgements",
        if uploading { "upload" } else { "download" },
        resolved.jump.as_deref().unwrap_or(&resolved.host),
    );
    let status = std::process::Command::new("scp")
        .args(&argv)
        .status()
        .map_err(|error| err_usage(&format!("could not run SCP: {error}")))?;
    if !status.success() {
        return Err(err_usage(&format!("SCP exited with {status}")));
    }
    eprintln!("mycelium: SCP complete");
    Ok(Vec::new())
}

fn scp_argv(
    source: &str,
    destination: &str,
    resolved: &ResolvedSsh,
    recursive: bool,
    preserve: bool,
) -> Vec<String> {
    let mut argv = vec![
        "-o".into(),
        "BatchMode=yes".into(),
        "-o".into(),
        "ConnectTimeout=15".into(),
        "-o".into(),
        "IdentitiesOnly=yes".into(),
        "-o".into(),
        format!("IdentityFile={}", resolved.identity),
        "-o".into(),
        format!("CertificateFile={}", resolved.certificate),
        "-o".into(),
        "ServerAliveInterval=15".into(),
        "-o".into(),
        "ServerAliveCountMax=3".into(),
        "-X".into(),
        "nrequests=8".into(),
        "-X".into(),
        "buffer=65536".into(),
        "-P".into(),
        resolved.port.to_string(),
    ];
    if let Some(jump) = &resolved.jump {
        argv.extend(["-J".into(), jump.clone()]);
    }
    if recursive {
        argv.push("-r".into());
    }
    if preserve {
        argv.push("-p".into());
    }
    argv.extend([source.into(), destination.into()]);
    argv
}

fn ssh_argv(
    host: &str,
    username: &str,
    port: u16,
    jump: Option<&str>,
    identity: &str,
    certificate: &str,
    batch_mode: bool,
    extra: &[String],
) -> Vec<String> {
    let mut argv = vec![
        "-o".into(),
        "IdentitiesOnly=yes".into(),
        "-o".into(),
        format!("IdentityFile={identity}"),
        "-o".into(),
        format!("CertificateFile={certificate}"),
        "-p".into(),
        port.to_string(),
    ];
    if batch_mode {
        argv.extend(["-o".into(), "BatchMode=yes".into()]);
    }
    if let Some(jump) = jump {
        argv.extend(["-J".into(), jump.into()]);
    }
    argv.push(format!("{username}@{host}"));
    argv.extend_from_slice(extra);
    argv
}

fn require_readable(label: &str, path: &str) -> Result<(), ClientError> {
    std::fs::File::open(path).map(|_| ()).map_err(|error| err_usage(&format!(
        "{label} `{path}` is unavailable: {error}; issue a certificate with `mycelium access oidc join` or pass an explicit path"
    )))
}

fn expand_home(value: impl AsRef<str>) -> String {
    let value = value.as_ref();
    if value == "~" || value.starts_with("~/") {
        if let Some(home) = std::env::var_os("HOME") {
            return std::path::PathBuf::from(home)
                .join(value.trim_start_matches("~/"))
                .to_string_lossy()
                .into();
        }
    }
    value.to_owned()
}

async fn console(args: &[String]) -> Result<Vec<String>, ClientError> {
    let f = parse_flags(args);
    let id = f
        .rest
        .first()
        .ok_or(err_usage("console needs a device id"))?;
    let mut client = connect().await?;
    let plan = client
        .call(&Request::ConsolePlan { id: id.clone() })
        .await?;
    if f.json {
        return Ok(vec![plan.to_string()]);
    }
    run_console(&plan)?;
    Ok(vec!["console closed".into()])
}

fn run_console(plan: &serde_json::Value) -> Result<(), ClientError> {
    if plan["kind"].as_str() != Some("ilo4_textcons") {
        return Err(err_usage("daemon returned an unsupported console kind"));
    }
    let host = plan["host"]
        .as_str()
        .ok_or(err_usage("console plan has no host"))?;
    let username = plan["username"]
        .as_str()
        .ok_or(err_usage("console plan has no username"))?;
    let password_name = plan["password_env"]
        .as_str()
        .ok_or(err_usage("console plan has no password environment"))?;
    let password = std::env::var(password_name).map_err(|_| {
        err_usage(&format!(
            "{password_name} is not exported; source the credential environment first"
        ))
    })?;
    let destination = format!("{username}@{host}");
    let script = r#"
set timeout 20
spawn sshpass -e ssh -tt -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o KexAlgorithms=+diffie-hellman-group14-sha1 -o HostKeyAlgorithms=+ssh-rsa -- [lindex $argv 0]
expect {
  -re {hpiLO->} { send -- "textcons\r" }
  timeout { puts stderr "timed out waiting for iLO CLI"; exit 3 }
  eof { puts stderr "iLO disconnected before console start"; exit 4 }
}
set timeout -1
interact
"#;
    let status = std::process::Command::new("expect")
        .args(["-c", script, &destination])
        .env("SSHPASS", password)
        .status()
        .map_err(|error| err_usage(&format!("could not launch console: {error}")))?;
    if !status.success() {
        return Err(err_usage(&format!("console exited with {status}")));
    }
    Ok(())
}

async fn tunnel(args: &[String]) -> Result<Vec<String>, ClientError> {
    let f = parse_flags(args);
    let destination = f
        .rest
        .first()
        .ok_or(err_usage("tunnel needs <target>:<port>"))?;
    let (target, remote_port) = destination
        .rsplit_once(':')
        .and_then(|(host, port)| port.parse::<u16>().ok().map(|port| (host, port)))
        .ok_or(err_usage("tunnel destination must be <IP>:<port>"))?;
    let local_port = f.local_port.unwrap_or(remote_port);
    let mut client = connect().await?;
    let plan = client
        .call(&Request::TunnelPlan {
            target: target.to_owned(),
            remote_port,
            local_port,
            via: f.via,
        })
        .await?;
    if f.json {
        return Ok(vec![plan.to_string()]);
    }
    if !f.write {
        return Ok(render_tunnel_plan(&plan));
    }
    run_tunnel(&plan)?;
    Ok(vec!["tunnel closed".into()])
}

fn run_tunnel(plan: &serde_json::Value) -> Result<(), ClientError> {
    let args = plan["ssh_args"]
        .as_array()
        .ok_or(err_usage("daemon returned invalid tunnel argv"))?
        .iter()
        .map(|arg| {
            arg.as_str()
                .map(str::to_owned)
                .ok_or(err_usage("invalid SSH argument"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let password_env = plan["hop"]["password_env"].as_str();
    let mut command = if password_env.is_some() {
        let mut command = std::process::Command::new("sshpass");
        command.arg("-e").arg("ssh");
        command
    } else {
        std::process::Command::new("ssh")
    };
    if let Some(name) = password_env {
        let password = std::env::var(name).map_err(|_| {
            err_usage(&format!(
                "{name} is not exported; source the credential environment first"
            ))
        })?;
        command.env("SSHPASS", password);
    }
    let status = command
        .args(args)
        .status()
        .map_err(|error| err_usage(&format!("could not run SSH: {error}")))?;
    if !status.success() {
        return Err(err_usage(&format!("SSH tunnel exited with {status}")));
    }
    Ok(())
}

async fn discovery(args: &[String]) -> Result<Vec<String>, ClientError> {
    match args.first().map(String::as_str) {
        Some("scopes") => {
            let flags = parse_flags(&args[1..]);
            let mut client = connect().await?;
            let value = client.call(&Request::DiscoveryScopeList).await?;
            if flags.json {
                return Ok(vec![value.to_string()]);
            }
            let scopes: Vec<mycelium_core::DiscoveryScope> = serde_json::from_value(value)
                .map_err(|error| err_usage(&format!("bad discovery scopes: {error}")))?;
            let mut output = vec![format!("discovery scopes: {}", scopes.len())];
            for scope in scopes {
                output.push(format!(
                    "  {} protocols={} segments={}",
                    scope.observer,
                    scope
                        .protocols
                        .iter()
                        .map(|protocol| format!("{protocol:?}").to_ascii_lowercase())
                        .collect::<Vec<_>>()
                        .join(","),
                    scope.segments.into_iter().collect::<Vec<_>>().join(",")
                ));
            }
            Ok(output)
        }
        Some("scope") => {
            let flags = parse_flags(&args[1..]);
            match flags.rest.first().map(String::as_str) {
                Some("set") => {
                    let observer = flags
                        .rest
                        .get(1)
                        .ok_or(err_usage("discovery scope set needs an observer"))?;
                    let protocols = flags
                        .protocols
                        .iter()
                        .map(|protocol| match protocol.as_str() {
                            "ssdp" => Ok(DiscoveryProtocol::Ssdp),
                            "mdns" => Ok(DiscoveryProtocol::Mdns),
                            _ => Err(err_usage(&format!(
                                "unsupported discovery protocol `{protocol}`"
                            ))),
                        })
                        .collect::<Result<Vec<_>, _>>()?;
                    let mut client = connect().await?;
                    let value = client
                        .call(&Request::DiscoveryScopeSet {
                            observer: observer.clone(),
                            protocols,
                            segments: flags.segments,
                            write: flags.write,
                            dry_run: flags.dry_run,
                        })
                        .await?;
                    Ok(vec![value.to_string()])
                }
                Some("remove") => {
                    let observer = flags
                        .rest
                        .get(1)
                        .ok_or(err_usage("discovery scope remove needs an observer"))?;
                    let mut client = connect().await?;
                    let value = client
                        .call(&Request::DiscoveryScopeRemove {
                            observer: observer.clone(),
                            write: flags.write,
                            dry_run: flags.dry_run,
                        })
                        .await?;
                    Ok(vec![value.to_string()])
                }
                _ => Err(err_usage("usage: mycelium discovery scope set|remove ...")),
            }
        }
        _ => Err(err_usage("usage: mycelium discovery scopes|scope ...")),
    }
}

async fn allocations(args: &[String]) -> Result<Vec<String>, ClientError> {
    let flags = parse_flags(&args[1..]);
    match args.first().map(String::as_str) {
        Some("list") => {
            let mut client = connect().await?;
            let value = client.call(&Request::AllocationList).await?;
            if flags.json {
                return Ok(vec![value.to_string()]);
            }
            let receipts: Vec<AllocationReceipt> = serde_json::from_value(value)
                .map_err(|error| err_usage(&format!("bad allocation receipts: {error}")))?;
            let mut output = vec![format!("allocations: {}", receipts.len())];
            for receipt in receipts {
                output.push(format!(
                    "  {} {} {} generation={}",
                    receipt.identity,
                    receipt.resource,
                    receipt.allocation.canonical(),
                    receipt.generation
                ));
            }
            Ok(output)
        }
        Some("import") => {
            let site = flags
                .site
                .ok_or(err_usage("allocations import needs --site SITE"))?;
            let mut client = connect().await?;
            let value = client
                .call(&Request::AllocationImport {
                    site,
                    write: flags.write,
                    dry_run: flags.dry_run,
                })
                .await?;
            if flags.json || flags.dry_run {
                Ok(vec![value.to_string()])
            } else {
                let result = &value["result"];
                Ok(vec![format!(
                    "imported {} allocation receipt(s) for {}",
                    result["imported"].as_u64().unwrap_or(0),
                    result["site"].as_str().unwrap_or("?")
                )])
            }
        }
        Some("record") => {
            let site = flags
                .site
                .ok_or(err_usage("allocations record needs --site SITE"))?;
            let source = flags
                .source
                .ok_or(err_usage("allocations record needs --source ID"))?;
            let mut client = connect().await?;
            let value = client
                .call(&Request::AllocationRecord {
                    site,
                    vlan: flags.vlan,
                    subnet: flags.subnet,
                    gateway: flags.gateway,
                    source,
                    write: flags.write,
                    dry_run: flags.dry_run,
                })
                .await?;
            Ok(vec![value.to_string()])
        }
        _ => Err(err_usage(
            "usage: mycelium allocations list|import|record ...",
        )),
    }
}

async fn networks(args: &[String]) -> Result<Vec<String>, ClientError> {
    let flags = parse_flags(&args[1..]);
    match args.first().map(String::as_str) {
        Some("list") => {
            let mut client = connect().await?;
            let value = client.call(&Request::NetworkList).await?;
            if flags.json {
                return Ok(vec![value.to_string()]);
            }
            let networks: Vec<LogicalNetwork> = serde_json::from_value(value)
                .map_err(|error| err_usage(&format!("bad logical networks: {error}")))?;
            let mut output = vec![format!("networks: {}", networks.len())];
            for network in networks {
                output.push(format!(
                    "  {} {} site={} receipts={} generation={}",
                    network.identity,
                    network.name,
                    network.site,
                    network.receipt_ids.len(),
                    network.generation
                ));
            }
            Ok(output)
        }
        Some("adopt") => {
            let name = flags
                .rest
                .first()
                .ok_or(err_usage("networks adopt needs NAME"))?;
            let site = flags.site.ok_or(err_usage("networks adopt needs --site"))?;
            let subnet = flags
                .subnet
                .ok_or(err_usage("networks adopt needs --subnet"))?;
            let mut client = connect().await?;
            let value = client
                .call(&Request::NetworkAdopt {
                    name: name.clone(),
                    site,
                    vlan: flags.vlan,
                    subnet,
                    write: flags.write,
                    dry_run: flags.dry_run,
                })
                .await?;
            Ok(vec![value.to_string()])
        }
        Some("drift") => {
            let name = flags.rest.first().cloned();
            let mut client = connect().await?;
            let value = client.call(&Request::NetworkDrift { name }).await?;
            if flags.json {
                return Ok(vec![value.to_string()]);
            }
            let reports: Vec<NetworkDriftReport> = serde_json::from_value(value)
                .map_err(|error| err_usage(&format!("bad network drift report: {error}")))?;
            let mut output = Vec::new();
            for report in reports {
                output.push(format!(
                    "{}: {:?} members={}",
                    report.network.name,
                    report.state,
                    report.known_members.len()
                ));
                if !report.known_members.is_empty() {
                    output.push(format!(
                        "  members: {}",
                        report
                            .known_members
                            .into_iter()
                            .collect::<Vec<_>>()
                            .join(", ")
                    ));
                }
                for missing in report.missing_allocations {
                    output.push(format!("  missing allocation: {missing}"));
                }
                for mismatch in report.gateway_mismatches {
                    output.push(format!("  gateway mismatch: {mismatch}"));
                }
            }
            Ok(output)
        }
        Some("plan") => {
            let name = flags.rest.first().cloned();
            let mut client = connect().await?;
            let value = client.call(&Request::NetworkPlan { name }).await?;
            let plans: Vec<ActionPlan> = serde_json::from_value(value)
                .map_err(|error| err_usage(&format!("bad network action plan: {error}")))?;
            if flags.json {
                return Ok(vec![serde_json::to_string(&plans).map_err(|error| {
                    err_usage(&format!("cannot serialize plans: {error}"))
                })?]);
            }
            let mut output = Vec::new();
            for plan in plans {
                output.push(format!(
                    "{}: {} actions={} blockers={}",
                    plan.scope,
                    if plan.ready_to_apply() {
                        "ready"
                    } else {
                        "blocked"
                    },
                    plan.actions.len(),
                    plan.blockers.len()
                ));
                for blocker in plan.blockers {
                    output.push(format!("  blocker {}: {}", blocker.code, blocker.message));
                }
            }
            Ok(output)
        }
        Some("apply") => {
            let path = args
                .windows(2)
                .find(|pair| pair[0] == "--plan")
                .map(|pair| pair[1].clone())
                .ok_or_else(|| err_usage("networks apply needs --plan PATH"))?;
            let plan: ActionPlan = serde_json::from_slice(&std::fs::read(&path)?)
                .map_err(|error| err_usage(&format!("invalid action plan: {error}")))?;
            let mut client = connect().await?;
            let value = client
                .call(&Request::ActionPlanExecute {
                    plan,
                    mode: mycelium_core::ExecutionMode::from_legacy_flags(
                        flags.write,
                        flags.dry_run,
                    )
                    .map_err(|error| err_usage(&error))?,
                })
                .await?;
            if flags.json {
                Ok(vec![value.to_string()])
            } else {
                Ok(vec![format!(
                    "{}: {} action(s) {}",
                    value["scope"].as_str().unwrap_or("network"),
                    value["actions"].as_array().map_or(0, Vec::len),
                    if value["mode"].as_str() == Some("plan") {
                        "validated in dry-run"
                    } else {
                        "applied and verified"
                    }
                )])
            }
        }
        Some("bindings") => {
            let network = flags.rest.first().cloned();
            let mut client = connect().await?;
            let value = client
                .call(&Request::NetworkBindingList { network })
                .await?;
            if flags.json {
                return Ok(vec![value.to_string()]);
            }
            let mut output = vec!["network bindings:".into()];
            for binding in value.as_array().into_iter().flatten() {
                output.push(format!(
                    "  {} network={} device={} port={} tagged={}",
                    binding["identity"].as_str().unwrap_or("?"),
                    binding["network"].as_str().unwrap_or("?"),
                    binding["device"].as_str().unwrap_or("?"),
                    binding["port"].as_str().unwrap_or("?"),
                    binding["tagged"].as_bool().unwrap_or(false),
                ));
            }
            Ok(output)
        }
        Some("bind") => {
            let network = flags
                .rest
                .first()
                .cloned()
                .ok_or_else(|| err_usage("networks bind needs NAME"))?;
            let value_after = |flag: &str| {
                args.windows(2)
                    .find(|pair| pair[0] == flag)
                    .map(|pair| pair[1].clone())
            };
            let device = value_after("--device")
                .ok_or_else(|| err_usage("networks bind needs --device ID"))?;
            let port = value_after("--port")
                .ok_or_else(|| err_usage("networks bind needs --port PORT"))?;
            let mut client = connect().await?;
            let value = client
                .call(&Request::NetworkBindingSet {
                    network,
                    device,
                    port,
                    tagged: args.iter().any(|arg| arg == "--tagged"),
                    write: flags.write,
                    dry_run: flags.dry_run,
                })
                .await?;
            Ok(vec![value.to_string()])
        }
        Some("dhcp") => {
            let action = args.get(1).map(String::as_str).unwrap_or("list");
            if action == "list" {
                let network = args.get(2).filter(|value| !value.starts_with('-')).cloned();
                let mut client = connect().await?;
                let value = client.call(&Request::NetworkDhcpList { network }).await?;
                return Ok(vec![value.to_string()]);
            }
            if action != "set" {
                return Err(err_usage("networks dhcp supports list|set"));
            }
            let network = args
                .get(2)
                .filter(|value| !value.starts_with('-'))
                .cloned()
                .ok_or_else(|| err_usage("networks dhcp set needs NAME"))?;
            let value_after = |flag: &str| {
                args.windows(2)
                    .find(|pair| pair[0] == flag)
                    .map(|pair| pair[1].clone())
            };
            let device = value_after("--device")
                .ok_or_else(|| err_usage("DHCP intent needs --device ID"))?;
            let pool =
                value_after("--pool").ok_or_else(|| err_usage("DHCP intent needs --pool NAME"))?;
            let range = value_after("--range")
                .ok_or_else(|| err_usage("DHCP intent needs --range START-END"))?;
            let (range_start, range_end) = range
                .split_once('-')
                .map(|(start, end)| (start.to_owned(), end.to_owned()))
                .ok_or_else(|| err_usage("DHCP range must be START-END"))?;
            let dns_servers = args
                .windows(2)
                .filter(|pair| pair[0] == "--dns")
                .map(|pair| pair[1].clone())
                .collect();
            let mut client = connect().await?;
            let value = client
                .call(&Request::NetworkDhcpSet {
                    network,
                    device,
                    pool,
                    range_start,
                    range_end,
                    dns_servers,
                    write: flags.write,
                    dry_run: flags.dry_run,
                })
                .await?;
            Ok(vec![value.to_string()])
        }
        _ => Err(err_usage(
            "usage: mycelium networks list|adopt|drift|plan|apply|bindings|bind|dhcp ...",
        )),
    }
}

async fn fetch_topology() -> Result<Topology, ClientError> {
    let mut client = connect().await?;
    let value = client.call(&Request::Topology).await?;
    serde_json::from_value(value).map_err(|error| err_usage(&format!("bad topology json: {error}")))
}

async fn nbde(args: &[String]) -> Result<Vec<String>, ClientError> {
    let Some("plan") = args.first().map(String::as_str) else {
        return Err(err_usage(
            "usage: mycelium nbde plan <device> --tang URL... --threshold N",
        ));
    };
    let f = parse_flags(&args[1..]);
    let device = f
        .rest
        .first()
        .ok_or(err_usage("nbde plan needs a device"))?;
    if f.tang.is_empty() {
        return Err(err_usage("nbde plan needs at least one --tang endpoint"));
    }
    let threshold = f
        .threshold
        .ok_or(err_usage("nbde plan needs --threshold N"))?;
    let plan = fetch_topology()
        .await?
        .nbde_plan(device, &f.tang, threshold)
        .map_err(|error| err_usage(&error.to_string()))?;
    if f.json {
        Ok(vec![
            serde_json::to_string(&plan).map_err(|e| err_usage(&e.to_string()))?
        ])
    } else {
        Ok(render_nbde_plan(&plan))
    }
}

async fn plan(args: &[String]) -> Result<Vec<String>, ClientError> {
    let flags = parse_flags(args);
    if flags.rest.first().map(String::as_str) != Some("switch") {
        return Err(err_usage(
            "usage: mycelium plan switch <id> --desired <startup-config> [--json]",
        ));
    }
    let device = flags
        .rest
        .get(1)
        .ok_or(err_usage("plan switch needs a device id"))?;
    let desired_path = flags
        .desired
        .ok_or(err_usage("plan switch needs --desired <startup-config>"))?;
    let source = std::fs::read_to_string(&desired_path)?;
    let config = FastpathConfig::parse(&source)
        .map_err(|error| err_usage(&format!("cannot parse {desired_path}: {error}")))?;
    let desired = FastpathIntent::normalize(&config)
        .map_err(|error| err_usage(&format!("cannot normalize {desired_path}: {error}")))?;

    let mut client = connect().await?;
    let response = client
        .call(&Request::DeviceCall {
            id: device.clone(),
            capability: ID_SWITCH_OBSERVE.into(),
            params: serde_json::Map::new(),
            write: false,
            dry_run: false,
        })
        .await?;
    let observed: SnmpSwitchState = serde_json::from_value(response["result"]["output"].clone())
        .map_err(|error| err_usage(&format!("invalid switch observation: {error}")))?;
    let plan = observed.plan(device, &desired);
    if flags.json {
        Ok(vec![serde_json::to_string(&plan).map_err(|error| {
            err_usage(&format!("cannot serialize plan: {error}"))
        })?])
    } else {
        Ok(render_switch_plan(&plan))
    }
}

async fn daemon(args: &[String]) -> Result<Vec<String>, ClientError> {
    let sub = args.first().map(|s| s.as_str()).unwrap_or("status");
    match sub {
        "start" => {
            match Client::try_connect().await {
                Ok(_) => return Ok(vec!["myceliumd already running".into()]),
                Err(ClientError::Connect(_)) => {}
                Err(e) => return Err(e),
            }
            Client::spawn_daemon()?;
            // confirm it came up
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
            loop {
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                match Client::try_connect().await {
                    Ok(_) => {
                        return Ok(vec![format!(
                            "myceliumd up on {}",
                            myceliumd::socket_path().display()
                        )])
                    }
                    Err(_) if std::time::Instant::now() > deadline => {
                        return Err(ClientError::DaemonUnresponsive)
                    }
                    Err(_) => {}
                }
            }
        }
        "stop" => {
            let mut c = Client::try_connect().await?;
            c.request(&Request::Shutdown).await.ok();
            Ok(vec!["myceliumd stopped".into()])
        }
        "status" => match Client::try_connect().await {
            Ok(mut c) => {
                let v = c.call(&Request::Hello).await?;
                Ok(vec![format!(
                    "myceliumd v{} pid {} socket {}",
                    v["version"].as_str().unwrap_or("?"),
                    v["pid"].to_string(),
                    v["socket"].as_str().unwrap_or("?"),
                )])
            }
            Err(ClientError::Connect(_)) => Ok(vec!["myceliumd not running".into()]),
            Err(e) => Err(e),
        },
        other => Err(err_usage(&format!("unknown daemon subcommand `{other}`"))),
    }
}

async fn connect() -> Result<Client, ClientError> {
    Client::connect().await
}

fn err_usage(msg: &str) -> ClientError {
    ClientError::Protocol(msg.to_owned())
}

fn coerce(v: &str) -> serde_json::Value {
    match v {
        "true" => serde_json::Value::Bool(true),
        "false" => serde_json::Value::Bool(false),
        _ => match v.parse::<i64>() {
            Ok(i) => serde_json::Value::from(i),
            Err(_) => {
                if v.starts_with('{') || v.starts_with('[') {
                    serde_json::from_str(v).unwrap_or_else(|_| serde_json::json!(v))
                } else {
                    serde_json::json!(v)
                }
            }
        },
    }
}

// ---- renderers ----------------------------------------------------------

fn render_added(v: &serde_json::Value) -> Vec<String> {
    let mut out = Vec::new();
    if let Some(devs) = v["devices"].as_array() {
        for d in devs {
            let id = d["id"].as_str().unwrap_or("?");
            let meta = &d["meta"];
            out.push(format!(
                "added {id}  ({} {} {}, driver {})",
                meta["kind"].as_str().unwrap_or("?"),
                meta["vendor"].as_str().unwrap_or("?"),
                meta["model"].as_str().unwrap_or("?"),
                meta["driver"].as_str().unwrap_or("?"),
            ));
        }
    }
    out
}

fn render_devices(v: &serde_json::Value) -> Vec<String> {
    let mut out = vec![format!(
        "{:<28} {:<12} {:<22} {:<16} driver",
        "id", "kind", "model", "address"
    )];
    if let Some(arr) = v.as_array() {
        for d in arr {
            out.push(format!(
                "{:<28} {:<12} {:<22} {:<16} {}",
                d["id"].as_str().unwrap_or("?"),
                d["kind"].as_str().unwrap_or("?"),
                d["model"]
                    .as_str()
                    .or(d["hostname"].as_str())
                    .unwrap_or("-"),
                d["address"].as_str().unwrap_or("?"),
                d["driver"].as_str().unwrap_or("?"),
            ));
        }
    }
    out
}

fn render_describe(id: &str, v: &serde_json::Value) -> Vec<String> {
    let mut out = vec![format!("capabilities of {id}:")];
    if let Some(arr) = v.as_array() {
        for c in arr {
            let cid = c["id"].as_str().unwrap_or("?");
            let desc = c["spec"]["description"].as_str().unwrap_or("");
            let mut params = String::new();
            for p in c["spec"]["params"].as_array().unwrap_or(&vec![]) {
                params.push_str(&format!(
                    " <{}:{}>",
                    p["name"].as_str().unwrap_or("?"),
                    p["ty"].as_str().unwrap_or("string")
                ));
            }
            let m = if c["spec"]["mutation"].as_bool().unwrap_or(false) {
                " [write]"
            } else {
                ""
            };
            out.push(format!("  {cid}{m}{params}  — {desc}"));
        }
    }
    out
}

fn render_call(v: &serde_json::Value) -> Vec<String> {
    if let Some(digest) = v["plan_digest"].as_str() {
        return vec![format!(
            "{} device change {} ({} action receipt{})",
            v["state"].as_str().unwrap_or("unknown"),
            digest,
            v["actions"].as_array().map_or(0, Vec::len),
            if v["mode"].as_str() == Some("plan") {
                ", plan only"
            } else {
                ""
            }
        )];
    }
    let mut out = Vec::new();
    let res = &v["result"];
    let dry = res["dry_run"].as_bool().unwrap_or(false);
    let ok = res["ok"].as_bool().unwrap_or(true);
    if dry {
        out.push("DRY RUN — planned commands (nothing applied):".into());
    } else if !ok {
        out.push(format!(
            "device error: {}",
            res["message"].as_str().unwrap_or("?")
        ));
    }
    match &res["output"] {
        serde_json::Value::String(s) => {
            for line in s.lines() {
                out.push(line.to_owned());
            }
        }
        serde_json::Value::Array(items) => {
            if dry {
                for cmd in items {
                    out.push(format!("  {}", cmd.as_str().unwrap_or("?")));
                }
            } else {
                out.push(serde_json::to_string_pretty(items).unwrap_or_default());
            }
        }
        other => out.push(serde_json::to_string_pretty(other).unwrap_or_default()),
    }
    if let Some(m) = res["message"].as_str().filter(|m| ok && !m.is_empty()) {
        out.push(format!("note: {m}"));
    }
    out
}

fn render_scan(v: &serde_json::Value) -> Vec<String> {
    let mut out = Vec::new();
    let r = &v["report"];
    out.push(format!(
        "scan: {} new nodes, {} updated, {} segments | {} device(s) total, {} node(s), {} segment(s)",
        r["new_nodes"].as_i64().unwrap_or(0),
        r["updated_nodes"].as_i64().unwrap_or(0),
        r["merged_segments"].as_i64().unwrap_or(0),
        v["nodes"].as_i64().unwrap_or(0),
        v["nodes"].as_i64().unwrap_or(0),
        v["segments"].as_i64().unwrap_or(0),
    ));
    if let Some(c) = r["conflicts"].as_array() {
        for conflict in c {
            out.push(format!(
                "CONFLICT: {}",
                serde_json::to_string(conflict).unwrap_or_default()
            ));
        }
    }
    if let Some(w) = v["warnings"].as_array() {
        for warn in w {
            out.push(format!("warning: {}", warn.as_str().unwrap_or("?")));
        }
    }
    if let Some(targets) = v["discovered_targets"].as_array() {
        for target in targets {
            out.push(format!(
                "discovered target: {}",
                target.as_str().unwrap_or("?")
            ));
        }
    }
    out
}

fn render_topology(topo: &Topology) -> Vec<String> {
    let mut out = Vec::new();
    out.push("segments:".into());
    for seg in topo.segments.values() {
        let subnet = seg
            .subnet
            .map(|(ip, pfx)| format!(" {ip}/{pfx}"))
            .unwrap_or_default();
        let gw = seg.gw.map(|g| format!(" gw {g}")).unwrap_or_default();
        out.push(format!(
            "  {:<18} {:<14}{subnet}{gw}  [{}]",
            seg.id,
            seg.domain_name.clone().unwrap_or_default(),
            seg.origins
                .iter()
                .map(|o| o.split(':').next().unwrap_or("?"))
                .collect::<Vec<_>>()
                .join(","),
        ));
    }
    out.push("appliances:".into());
    for node in topo.nodes.values().filter(|n| n.device) {
        let label = node.annotation.name.as_deref().unwrap_or(&node.id);
        let kind = node
            .annotation
            .kind
            .as_deref()
            .map(|kind| format!(" kind={kind}"))
            .unwrap_or_default();
        let ips = node
            .ips
            .keys()
            .map(|i| i.to_string())
            .collect::<Vec<_>>()
            .join(",");
        out.push(format!(
            "  {:<28} ports={} ips={}{}",
            label,
            node.ports.len(),
            ips,
            format_args!("{kind}{}", render_lans(topo, node))
        ));
        render_device_links(&mut out, node);
        render_services(&mut out, node);
        render_overlays(&mut out, node);
    }
    out.push(format!(
        "hosts: {}",
        topo.nodes.values().filter(|n| !n.device).count()
    ));
    for node in topo.nodes.values().filter(|n| !n.device) {
        let names = if let Some(name) = &node.annotation.name {
            name.clone()
        } else if node.hostnames.is_empty() {
            "-".to_owned()
        } else {
            node.hostnames.iter().cloned().collect::<Vec<_>>().join(",")
        };
        let ips = node
            .ips
            .keys()
            .map(|i| i.to_string())
            .collect::<Vec<_>>()
            .join(",");
        let kind = node
            .annotation
            .kind
            .as_deref()
            .map(|kind| format!(" kind={kind}"))
            .unwrap_or_default();
        out.push(format!(
            "  {:<20} {:<20} {names}  [{ips}]{kind}{}",
            node.mac
                .map(|m| m.to_string())
                .unwrap_or_else(|| "no-mac".into()),
            node.id,
            render_lans(topo, node)
        ));
        for link in node.ports.values().filter_map(|link| link.b.as_ref()) {
            out.push(format!("    └─ {}", link));
        }
        render_services(&mut out, node);
        render_overlays(&mut out, node);
    }
    if !topo.advertisements.is_empty() {
        out.push(format!(
            "service advertisements: {}",
            topo.advertisements.len()
        ));
        for advertisement in topo.advertisements.values() {
            let endpoint = advertisement
                .target
                .as_deref()
                .map(str::to_owned)
                .or_else(|| {
                    advertisement
                        .addresses
                        .iter()
                        .next()
                        .map(ToString::to_string)
                })
                .unwrap_or_else(|| "unresolved".into());
            let port = advertisement
                .port
                .map(|port| format!(":{port}"))
                .unwrap_or_default();
            let node = topology_node_for_advertisement(topo, advertisement)
                .map(|node| format!(" node={}", node.id))
                .unwrap_or_default();
            out.push(format!(
                "  {}  {}.{}  {endpoint}{port}{node}",
                advertisement.instance, advertisement.service_type, advertisement.domain
            ));
        }
    }
    if !topo.resource_attachments.is_empty() {
        out.push(format!(
            "resource attachments: {}",
            topo.resource_attachments.len()
        ));
        for (resource_id, attachment) in &topo.resource_attachments {
            out.push(format!(
                "  {} → {} via {}",
                resource_id.0,
                attachment.host.label,
                render_attachment_transport(&attachment.transport)
            ));
        }
    }
    if !topo.leases.is_empty() {
        out.push("leases:".into());
        for l in &topo.leases {
            out.push(format!(
                "  {:<16} {:<20} {}",
                l.ip,
                l.mac,
                l.hostname.clone().unwrap_or_else(|| "-".into())
            ));
        }
    }
    if !topo.conflicts.is_empty() {
        out.push(format!("CONFLICTS: {}", topo.conflicts.len()));
        for c in &topo.conflicts {
            out.push(format!("  {c:?}"));
        }
    }
    out
}

fn render_attachment_transport(
    transport: &fpl_resource_observation::AttachmentTransport,
) -> String {
    use fpl_resource_observation::AttachmentTransport;
    match transport {
        AttachmentTransport::Usb { locator, .. }
        | AttachmentTransport::Nvme { locator }
        | AttachmentTransport::Scsi { locator }
        | AttachmentTransport::Virtio { locator }
        | AttachmentTransport::Integrated { locator }
        | AttachmentTransport::Unknown { locator, .. } => locator.clone(),
        AttachmentTransport::Pcie { address, .. } => format!("pcie:{address}"),
        AttachmentTransport::Network { endpoints } => {
            format!(
                "network:[{}]",
                endpoints.iter().cloned().collect::<Vec<_>>().join(",")
            )
        }
    }
}

fn topology_node_for_advertisement<'a>(
    topology: &'a Topology,
    advertisement: &mycelium_core::ServiceAdvertisement,
) -> Option<&'a mycelium_core::TopoNode> {
    topology.nodes.values().find(|node| {
        advertisement
            .addresses
            .iter()
            .any(|address| node.ips.contains_key(address))
            || advertisement.target.as_ref().is_some_and(|target| {
                let target = target.trim_end_matches('.').to_lowercase();
                node.hostnames.iter().any(|hostname| {
                    hostname == &target || hostname.split('.').next() == target.split('.').next()
                })
            })
    })
}

fn render_device_links(out: &mut Vec<String>, node: &mycelium_core::TopoNode) {
    for (name, link) in node.ports.iter().filter(|(_, link)| {
        !matches!(
            link.medium,
            Some(mycelium_core::LinkMedium::Virtual | mycelium_core::LinkMedium::Loopback)
        )
    }) {
        let medium = link
            .medium
            .map(|medium| format!("{medium:?}").to_ascii_lowercase())
            .unwrap_or_else(|| "unknown".into());
        let speed = link
            .speed_mbps
            .map(|speed| format!("{speed} Mbps"))
            .unwrap_or_else(|| "unknown speed".into());
        let duplex = link
            .duplex
            .map(|duplex| format!(" {duplex:?}").to_ascii_lowercase())
            .unwrap_or_default();
        out.push(format!(
            "    ├─ {name}: {medium}, {speed}{duplex}, {:?}",
            link.state
        ));
    }
}

fn render_services(out: &mut Vec<String>, node: &mycelium_core::TopoNode) {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    for service in node.services.values() {
        if service.name == "unknown" {
            continue;
        }
        let age = now.saturating_sub(service.observed_at);
        let state = if age > 300 {
            format!("STALE {}m", age / 60)
        } else {
            format!("{:?}", service.state).to_ascii_uppercase()
        };
        out.push(format!(
            "    └─ {}:{}/{}  {}  {}",
            service.name,
            service.port,
            service.transport,
            state,
            service.product.as_deref().unwrap_or("unidentified")
        ));
    }
}

fn render_lans(topo: &Topology, node: &mycelium_core::TopoNode) -> String {
    let lans =
        topo.segments
            .values()
            .filter(|segment| {
                let scoped_site = segment.id.split_once('/').and_then(|(first, _)| {
                    first.parse::<std::net::IpAddr>().is_err().then_some(first)
                });
                let scope_matches = scoped_site
                    .map(|site| node.sites.contains(site))
                    .unwrap_or(true);
                scope_matches
                    && segment.subnet.is_some_and(|(network, prefix)| {
                        node.ips
                            .keys()
                            .any(|address| mycelium_core::ipv4_in_cidr(*address, network, prefix))
                    })
            })
            .map(|segment| segment.id.clone())
            .collect::<Vec<_>>();
    if lans.is_empty() {
        String::new()
    } else {
        format!(" lans=[{}]", lans.join(","))
    }
}

fn render_overlays(out: &mut Vec<String>, node: &mycelium_core::TopoNode) {
    for overlay in node.overlays.values() {
        let state = if overlay.online { "ONLINE" } else { "OFFLINE" };
        let path = if overlay.self_node {
            "path=self".into()
        } else {
            overlay
                .endpoint
                .as_deref()
                .map(|endpoint| format!("direct={endpoint}"))
                .or_else(|| {
                    overlay
                        .relay
                        .as_deref()
                        .map(|relay| format!("relay={relay}"))
                })
                .unwrap_or_else(|| "path=unknown".into())
        };
        let routes = if overlay.routed_lans.is_empty() {
            String::new()
        } else {
            format!(
                " routes={}",
                overlay
                    .routed_lans
                    .iter()
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(",")
            )
        };
        let coordinator = match overlay.control_plane.coordinator {
            mycelium_core::MeshCoordinator::TailscaleCloud => "tailscale-cloud".to_owned(),
            mycelium_core::MeshCoordinator::Headscale => "headscale".to_owned(),
            mycelium_core::MeshCoordinator::Custom => overlay
                .control_plane
                .url
                .clone()
                .unwrap_or_else(|| "custom".into()),
            mycelium_core::MeshCoordinator::Unknown => "coordinator=unknown".to_owned(),
        };
        out.push(format!(
            "    └─ {} via {} ({})  {}{}  {}{}",
            overlay.network,
            overlay.observer,
            coordinator,
            state,
            if overlay.active { "/ACTIVE" } else { "" },
            path,
            routes
        ));
    }
}

fn render_boot_path(path: &mycelium_core::BootPath) -> Vec<String> {
    let mut out = vec![format!("boot paths for {}:", path.device)];
    for target in &path.targets {
        out.push(format!(
            "  {:<10} {:<32} {}",
            reachability_label(target.reachability),
            target.endpoint,
            target.reason
        ));
    }
    out
}

fn render_nbde_plan(plan: &NbdePlan) -> Vec<String> {
    let status = if plan.viable { "VIABLE" } else { "NOT VIABLE" };
    let mut out = vec![format!(
        "NBDE plan for {}: {status} — threshold {}, {} observed path(s)",
        plan.device, plan.threshold, plan.reachable
    )];
    for target in &plan.endpoints {
        out.push(format!(
            "  {:<10} {}",
            reachability_label(target.reachability),
            target.endpoint
        ));
    }
    for warning in &plan.warnings {
        out.push(format!("warning: {warning}"));
    }
    out
}

fn render_switch_plan(plan: &ActionPlan) -> Vec<String> {
    let status = if plan.ready_to_apply() {
        "READY"
    } else {
        "BLOCKED"
    };
    let mut lines = vec![format!(
        "switch plan {}: {status} — {} action(s), {} blocker(s)",
        plan.scope,
        plan.actions.len(),
        plan.blockers.len()
    )];
    for (index, action) in plan.actions.iter().enumerate() {
        let risk = match action.risk {
            ActionRisk::Low => "low",
            ActionRisk::Disruptive => "disruptive",
            ActionRisk::Destructive => "destructive",
        };
        lines.push(format!(
            "  {}. [{}] {} {}",
            index + 1,
            risk,
            action.capability,
            serde_json::to_string(&action.params).unwrap_or_else(|_| "{}".into())
        ));
        lines.push(format!(
            "     verify with {}",
            action.verification.capability
        ));
    }
    for blocker in &plan.blockers {
        let resource = blocker
            .resource
            .as_deref()
            .map(|resource| format!(" ({resource})"))
            .unwrap_or_default();
        lines.push(format!(
            "  BLOCKED {}{resource}: {}",
            blocker.code, blocker.message
        ));
    }
    lines
}

fn reachability_label(reachability: BootReachability) -> &'static str {
    match reachability {
        BootReachability::Direct => "direct",
        BootReachability::Routed => "routed",
        BootReachability::Unverified => "unverified",
    }
}

fn render_tunnel_plan(plan: &serde_json::Value) -> Vec<String> {
    let hop = &plan["hop"];
    vec![
        format!(
            "tunnel: http://127.0.0.1:{} -> {}:{} via {} ({}@{})",
            plan["local_port"].as_u64().unwrap_or(0),
            plan["target"].as_str().unwrap_or("?"),
            plan["remote_port"].as_u64().unwrap_or(0),
            hop["id"].as_str().unwrap_or("?"),
            hop["username"].as_str().unwrap_or("?"),
            hop["host"].as_str().unwrap_or("?"),
        ),
        "run with --write to open the foreground tunnel; Ctrl-C closes it".into(),
    ]
}

#[cfg(test)]
mod ssh_command_tests {
    #[test]
    fn self_check_reports_compiled_transport_capability() {
        let value = super::self_check();
        assert!(value.starts_with(concat!("mycelium ", env!("CARGO_PKG_VERSION"), " protocol ")));
        assert!(value.ends_with(if cfg!(feature = "iroh-sync") { "iroh-sync=true" } else { "iroh-sync=false" }));
    }
    use super::*;

    #[test]
    fn update_health_rejects_stale_or_unmanaged_socket_daemons() {
        assert!(supervised_peer_matches(123, Some(123)));
        assert!(!supervised_peer_matches(123, Some(456)));
        assert!(!supervised_peer_matches(0, Some(0)));
        assert!(!supervised_peer_matches(123, None));
    }

    #[test]
    fn updater_retains_enrolled_home_and_rejects_unit_injection() {
        let unit = systemd_update_service(
            std::path::Path::new("/var/lib/mycelium/bin/mycelium"),
            std::path::Path::new("/var/lib/mycelium"),
        )
        .unwrap();
        assert!(unit.contains("EnvironmentFile=/var/lib/mycelium/node.env"));
        assert!(unit.contains("Environment=MYCELIUM_HOME=/var/lib/mycelium"));
        assert!(systemd_update_service(
            std::path::Path::new("/tmp/%n"),
            std::path::Path::new("/var/lib/mycelium")
        )
        .is_err());
    }

    #[test]
    fn system_update_supervisor_matches_only_its_installation() {
        let binary = std::path::Path::new("/var/lib/mycelium/bin/mycelium");
        assert!(system_unit_matches_binary(
            "{ path=/var/lib/mycelium/bin/mycelium ; argv[]=/var/lib/mycelium/bin/mycelium _serve ; }",
            binary,
        ));
        assert!(!system_unit_matches_binary(
            "{ path=/other/bin/mycelium ; argv[]=/var/lib/mycelium/bin/mycelium _serve ; }",
            binary,
        ));
        assert!(!system_unit_matches_binary("", binary));
    }

    #[test]
    fn automatic_update_durations_are_explicit_and_bounded() {
        assert_eq!(parse_update_duration("15m").unwrap(), 900);
        assert_eq!(parse_update_duration("1h").unwrap(), 3600);
        assert!(parse_update_duration("15").is_err());
        assert!(parse_update_duration("1week").is_err());
    }

    #[test]
    fn rollout_offset_is_stable_and_inside_window() {
        let first = node_rollout_offset(1800);
        assert_eq!(first, node_rollout_offset(1800));
        assert!(first < 1800);
    }

    #[test]
    fn ssh_options_keep_remote_command_after_separator() {
        let args = [
            "titan",
            "--user",
            "avery",
            "--port",
            "2222",
            "--",
            "printf",
            "connected",
        ]
        .map(str::to_owned);
        let parsed = SshOptions::parse(&args).unwrap();
        assert_eq!(parsed.device, "titan");
        assert_eq!(parsed.user.as_deref(), Some("avery"));
        assert_eq!(parsed.port, Some(2222));
        assert_eq!(parsed.extra, ["printf", "connected"]);
    }

    #[test]
    fn ssh_argv_uses_only_explicit_identity_material() {
        let argv = ssh_argv(
            "lab-node",
            "operator",
            22,
            Some("gateway"),
            "/key",
            "/cert",
            false,
            &[],
        );
        assert!(argv
            .windows(2)
            .any(|pair| pair == ["-o", "IdentitiesOnly=yes"]));
        assert!(argv.contains(&"IdentityFile=/key".into()));
        assert!(argv.contains(&"CertificateFile=/cert".into()));
        assert!(argv.windows(2).any(|pair| pair == ["-J", "gateway"]));
        assert_eq!(argv.last().map(String::as_str), Some("operator@lab-node"));
    }

    #[test]
    fn personal_certificate_precedes_legacy_device_certificate() {
        let root =
            std::env::temp_dir().join(format!("mycelium-cert-selection-{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        let personal = root.join("user-cert.pub");
        let device = root.join("device-cert.pub");
        std::fs::write(&personal, "personal").unwrap();
        std::fs::write(&device, "expired legacy").unwrap();
        assert_eq!(
            select_ssh_certificate(None, None, &personal, &device),
            personal.to_string_lossy()
        );
        assert_eq!(
            select_ssh_certificate(Some("/explicit".into()), None, &personal, &device),
            "/explicit"
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn exec_argv_is_batch_mode_and_keeps_the_remote_command() {
        let argv = ssh_argv(
            "dgx-spark",
            "operator",
            22,
            Some("pris"),
            "/key",
            "/cert",
            true,
            &["uname".into(), "-a".into()],
        );
        assert!(argv.windows(2).any(|pair| pair == ["-o", "BatchMode=yes"]));
        assert!(argv.windows(2).any(|pair| pair == ["-J", "pris"]));
        assert_eq!(&argv[argv.len() - 2..], ["uname", "-a"]);
    }

    #[test]
    fn scp_options_require_exactly_one_remote() {
        let upload = ["./agent", "dgx-spark:/tmp/agent", "--preserve"].map(str::to_owned);
        let parsed = ScpOptions::parse(&upload).unwrap();
        assert_eq!(
            remote_operand(&parsed.destination),
            Some(("dgx-spark", "/tmp/agent"))
        );
        assert!(parsed.preserve);
        assert!(remote_operand("./local-file").is_none());
    }

    #[test]
    fn scp_argv_uses_the_derived_jump_and_scp_port_flag() {
        let resolved = ResolvedSsh {
            device: "dgx-spark".into(),
            host: "192.168.1.48".into(),
            username: "fpladmin".into(),
            port: 2222,
            jump: Some("pris".into()),
            identity: "/key".into(),
            certificate: "/cert".into(),
        };
        let argv = scp_argv(
            "./agent",
            "fpladmin@192.168.1.48:/tmp/agent",
            &resolved,
            false,
            true,
        );
        assert!(argv.windows(2).any(|pair| pair == ["-J", "pris"]));
        assert!(argv.windows(2).any(|pair| pair == ["-P", "2222"]));
        assert!(argv.contains(&"BatchMode=yes".into()));
        assert!(argv.contains(&"ConnectTimeout=15".into()));
        assert!(argv.contains(&"ServerAliveInterval=15".into()));
        assert!(argv.contains(&"ServerAliveCountMax=3".into()));
        assert!(argv.windows(2).any(|pair| pair == ["-X", "nrequests=8"]));
        assert!(argv.windows(2).any(|pair| pair == ["-X", "buffer=65536"]));
        assert_eq!(
            argv.last().map(String::as_str),
            Some("fpladmin@192.168.1.48:/tmp/agent")
        );
    }

    fn running_release(version: Option<&str>, digest_matches: bool) -> myceliumd::updates::RunningRelease {
        myceliumd::updates::RunningRelease {
            version: version.map(str::to_owned),
            source: "update state",
            digest: Some("00".repeat(32)),
            digest_matches,
        }
    }

    #[test]
    fn automatic_updates_never_step_back_a_verified_release() {
        let active = running_release(Some("0.2.26"), true);
        assert!(automatic_upgrade_allowed(&active, "0.2.26").is_err());
        // A string comparison would call 0.2.9 newer than 0.2.26.
        assert!(automatic_upgrade_allowed(&active, "0.2.9").is_err());
        assert_eq!(automatic_upgrade_allowed(&active, "0.2.27").unwrap(), None);
    }

    #[test]
    fn a_local_build_converges_to_the_channel_instead_of_freezing() {
        // neo's shape: the state recorded 0.2.26, a dev binary replaced it, and
        // the channel only offers 0.2.9. Keeping 0.2.26 as a floor would mean
        // the host never updates again.
        let local = running_release(Some("0.2.26"), false);
        let note = automatic_upgrade_allowed(&local, "0.2.9")
            .unwrap()
            .expect("a local build should converge and say why");
        assert!(note.contains("local build"), "{note}");
        assert!(note.contains("0.2.26"), "{note}");
        assert!(note.contains("0.2.9"), "{note}");
    }

    #[test]
    fn a_host_without_any_recorded_release_still_needs_a_manual_bootstrap() {
        let fresh = running_release(None, false);
        let error = automatic_upgrade_allowed(&fresh, "0.2.9").unwrap_err();
        assert!(error.contains("manual signed bootstrap"), "{error}");
    }

    #[test]
    fn an_invalid_candidate_version_is_reported_not_activated() {
        let active = running_release(Some("0.2.26"), true);
        let error = automatic_upgrade_allowed(&active, "not-a-version").unwrap_err();
        assert!(error.contains("invalid"), "{error}");
    }

    #[test]
    fn fleet_rows_flag_outdated_and_unrecorded_hosts() {
        let releases = serde_json::json!([{
            "version": "0.2.4",
            "channel": "canary",
            "target": "x86_64-unknown-linux-gnu",
            "protocol_version": 1,
            "artifact_digest": "00".repeat(32),
            "artifact_size": 1,
            "signer": "11".repeat(32),
            "signature": "22".repeat(64)
        }]);
        let parsed = myceliumd::updates::parse_releases(&releases);
        let peers = serde_json::json!([
            {
                "hello": {"hostname": "edge", "node_id": "a", "daemon_version": "0.1.0"},
                "health": {"platform_metrics": {
                    "mycelium_update.release_version": "0.2.0",
                    "mycelium_update.release_target": "x86_64-unknown-linux-gnu"
                }}
            },
            {
                "hello": {"hostname": "fresh", "node_id": "b", "daemon_version": "0.1.0"},
                "health": {"platform_metrics": {
                    "mycelium_update.release_version": "",
                    "mycelium_update.release_target": "x86_64-unknown-linux-gnu"
                }}
            }
        ]);
        let rows = fleet_update_rows(&peers, &parsed, "canary");
        assert_eq!(rows[0]["verdict"], "update-available");
        assert_eq!(rows[0]["needs_update"], true);
        assert_eq!(rows[1]["verdict"], "unknown");
        assert_eq!(rows[1]["needs_update"], serde_json::Value::Null);
    }
}
