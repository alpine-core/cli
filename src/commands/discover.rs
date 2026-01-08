use crate::{
    device_cache,
    discovery::{DiscoveryRunOptions, run_discovery_with_options},
    identity_store,
    parse_socket,
};
use base64::{engine::general_purpose, Engine as _};
use clap::Args;
use std::net::SocketAddr;
use tracing::info;

const DEFAULT_DIAG_UNICAST: &str = "192.168.39.121:19455";

#[derive(Debug, Clone, Args)]
pub struct DiscoverArgs {
    /// Discovery target address (ip:port). Defaults to broadcast 255.255.255.255:19455.
    #[arg(value_name = "ip:port")]
    pub addr: Option<String>,
    /// Force unicast discovery to a specific device. Defaults to 192.168.39.121:19455 if no value supplied.
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
    /// Enable multicast discovery (opt-in).
    #[arg(long)]
    pub multicast: bool,
    /// Enable subnet scan fallback (opt-in; unicast probes per host).
    #[arg(long)]
    pub scan_subnets: bool,
    /// Maximum hosts to probe per subnet when scanning.
    #[arg(long, default_value_t = 1024)]
    pub scan_max_hosts: u32,
    /// Per-host timeout in milliseconds when scanning.
    #[arg(long, default_value_t = 500)]
    pub scan_timeout_ms: u64,
    /// Scan rate in probes per second (best-effort).
    #[arg(long, default_value_t = 200)]
    pub scan_rate: u32,
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
    run_opts.prefer_multicast = args.multicast;
    run_opts.scan_subnets = args.scan_subnets;
    run_opts.scan_max_hosts = args.scan_max_hosts;
    run_opts.scan_timeout_ms = args.scan_timeout_ms;
    run_opts.scan_rate_per_sec = args.scan_rate;
    run_opts.cached_targets = load_cached_targets()?;
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
    if outcome.device_identity_trusted {
        if let Some(pubkey) = outcome.device_identity_pubkey.clone() {
            if identity_store::load_trusted_device_key(&outcome.reply.device_id).is_none() {
                if let Err(err) =
                    identity_store::store_trusted_device_key(&outcome.reply.device_id, &pubkey)
                {
                    eprintln!(
                        "[ALPINE][TRUST][WARN] failed to store attested device identity for {}: {}",
                        outcome.reply.device_id, err
                    );
                } else {
                    println!(
                        "[ALPINE][TRUST] attested device identity trusted: {}",
                        outcome.reply.device_id
                    );
                }
            }
        }
    }

    println!(
        "discovered device: {} ({})",
        outcome.reply.device_id, outcome.reply.manufacturer_id
    );
    println!("peer: {}", outcome.peer);
    println!("local addr: {}", outcome.local_addr);
    let caps = &outcome.reply.capabilities;
    println!("discovery reply (human-friendly):");
    println!("  alpine_version: {}", outcome.reply.alpine_version);
    println!("  device_id: {}", outcome.reply.device_id);
    println!("  manufacturer_id: {}", outcome.reply.manufacturer_id);
    println!("  model_id: {}", outcome.reply.model_id);
    println!("  hardware_rev: {}", outcome.reply.hardware_rev);
    println!("  firmware_rev: {}", outcome.reply.firmware_rev);
    println!("  mac: {}", outcome.reply.mac);
    println!("  device_identity_trusted: {}", outcome.device_identity_trusted);
    if let Some(err) = &outcome.device_identity_attestation_error {
        println!("  device_identity_attestation_error: {}", err);
    }
    if outcome.reply.device_identity_attestation.is_empty() {
        println!("  device_identity_attestation: <empty>");
    } else {
        let attestation_b64 =
            general_purpose::STANDARD.encode(&outcome.reply.device_identity_attestation);
        println!("  device_identity_attestation: {}", attestation_b64);
    }
    println!(
        "  capabilities: channel_formats={:?} max_channels={} grouping_supported={} streaming_supported={} encryption_supported={}",
        caps.channel_formats,
        caps.max_channels,
        caps.grouping_supported,
        caps.streaming_supported,
        caps.encryption_supported
    );

    Ok(())
}

fn load_cached_targets() -> anyhow::Result<Vec<SocketAddr>> {
    let mut targets = Vec::new();
    let devices = device_cache::load_devices()?;
    for device in devices {
        if let Some(addr) = device.last_addr.as_deref() {
            if let Ok(socket) = parse_socket(addr) {
                if !targets.contains(&socket) {
                    targets.push(socket);
                }
            }
        }
    }
    Ok(targets)
}
