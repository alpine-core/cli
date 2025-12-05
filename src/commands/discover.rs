use crate::{
    device_cache,
    discovery::{DiscoveryRunOptions, run_discovery_with_options},
    parse_socket,
};
use clap::Args;
use std::net::SocketAddr;
use tracing::info;

const DEFAULT_DIAG_UNICAST: &str = "192.168.39.121:9455";

#[derive(Debug, Clone, Args)]
pub struct DiscoverArgs {
    /// Discovery target address (ip:port). Defaults to broadcast 255.255.255.255:9455.
    #[arg(value_name = "ip:port")]
    pub addr: Option<String>,
    /// Force unicast discovery to a specific device. Defaults to 192.168.39.121:9455 if no value supplied.
    #[arg(
        long,
        value_name = "ip:port",
        num_args = 0..=1,
        default_missing_value = DEFAULT_DIAG_UNICAST
    )]
    pub force_unicast: Option<String>,
    /// Local bind address (ip:port) for discovery socket.
    #[arg(long, value_name = "ip:port")]
    pub local: Option<String>,
}

pub async fn run(args: DiscoverArgs, default_remote: SocketAddr) -> anyhow::Result<()> {
    let forced = args
        .force_unicast
        .as_deref()
        .map(|addr| parse_socket(addr))
        .transpose()?;
    let remote = if let Some(addr) = forced.clone() {
        addr
    } else if let Some(addr) = args.addr.as_deref() {
        parse_socket(addr)?
    } else {
        default_remote
    };

    let local_override = args.local.as_deref().map(parse_socket).transpose()?;

    let mut run_opts = DiscoveryRunOptions::default();
    run_opts.local_addr = local_override;
    if forced.is_some() {
        run_opts.prefer_multicast = false;
        run_opts.allow_broadcast = false;
        info!(
            "[CLI][DISCOVERY] forcing unicast discovery to {} via local {:?}",
            remote, run_opts.local_addr
        );
    }

    let outcome = run_discovery_with_options(remote, run_opts).await?;
    device_cache::upsert_device(&outcome)?;

    println!(
        "discovered device: {} ({})",
        outcome.reply.device_id, outcome.reply.manufacturer_id
    );
    println!("peer: {}", outcome.peer);
    println!("local addr: {}", outcome.local_addr);
    println!("discovery reply:");
    println!("{:#?}", outcome.reply);

    Ok(())
}
