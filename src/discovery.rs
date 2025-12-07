use alpine_protocol_sdk::{
    DiscoveryClient, DiscoveryClientOptions, DiscoveryOutcome, claim_discovery,
};
use get_if_addrs::get_if_addrs;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

fn default_local_addr() -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
}

#[derive(Debug, Clone)]
pub struct DiscoveryRunOptions {
    pub local_addr: Option<SocketAddr>,
    pub prefer_multicast: bool,
    pub allow_broadcast: bool,
}

impl Default for DiscoveryRunOptions {
    fn default() -> Self {
        Self {
            local_addr: None,
            prefer_multicast: false,
            allow_broadcast: true,
        }
    }
}

pub async fn run_discovery(remote_addr: SocketAddr) -> anyhow::Result<DiscoveryOutcome> {
    run_discovery_with_options(remote_addr, DiscoveryRunOptions::default()).await
}

pub async fn run_discovery_with_options(
    remote_addr: SocketAddr,
    opts: DiscoveryRunOptions,
) -> anyhow::Result<DiscoveryOutcome> {
    let _phase_guard = claim_discovery().map_err(anyhow::Error::from)?;
    let is_broadcast_target = matches!(remote_addr.ip(), IpAddr::V4(v4) if v4.is_broadcast());

    if !is_broadcast_target {
        // Unicast/explicit target path (leave existing behavior).
        let mut options = DiscoveryClientOptions::new(
            remote_addr,
            opts.local_addr.unwrap_or_else(default_local_addr),
            Duration::from_secs(3),
        );
        if !opts.prefer_multicast {
            options = options.disable_multicast();
        }
        if !opts.allow_broadcast {
            options = options.disable_broadcast();
        }
        println!(
            "[ALPINE][DISCOVERY] destination={} port={} iface={} local_ip={} broadcast_enabled={}",
            remote_addr,
            remote_addr.port(),
            options
                .interface
                .clone()
                .unwrap_or_else(|| "unknown".into()),
            options.local_addr,
            options.allow_broadcast
        );
        let client = DiscoveryClient::new(options).map_err(anyhow::Error::from)?;
        let outcome = client
            .discover(&["alpine-control".to_string()])
            .map_err(|err| map_discovery_error(err.into(), &[]))?;
        return Ok(outcome);
    }

    // Broadcast path: fan out per viable interface.
    let attempts = collect_interfaces(remote_addr.port())?;
    if attempts.is_empty() {
        anyhow::bail!(
            "no viable interfaces for broadcast discovery (need a non-loopback IPv4 address)"
        );
    }

    let mut attempt_summaries = Vec::new();
    let mut last_err: Option<anyhow::Error> = None;

    for attempt in attempts.iter() {
        let mut options = DiscoveryClientOptions::new(
            SocketAddr::new(IpAddr::V4(attempt.broadcast), remote_addr.port()),
            SocketAddr::new(IpAddr::V4(attempt.local_ip), 0),
            Duration::from_secs(3),
        );
        options.interface = Some(attempt.iface.clone());
        if !opts.prefer_multicast {
            options = options.disable_multicast();
        }
        if !opts.allow_broadcast {
            options = options.disable_broadcast();
        }
        println!(
            "[ALPINE][DISCOVERY] iface={} local_ip={} netmask={} broadcast={} bound={}:0 so_broadcast={}",
            attempt.iface,
            attempt.local_ip,
            attempt.netmask,
            attempt.broadcast,
            attempt.local_ip,
            options.allow_broadcast
        );
        attempt_summaries.push(format!(
            "{} (local_ip={} broadcast={})",
            attempt.iface, attempt.local_ip, attempt.broadcast
        ));

        match DiscoveryClient::new(options) {
            Ok(client) => match client.discover(&["alpine-control".to_string()]) {
                Ok(outcome) => return Ok(outcome),
                Err(err) => {
                    println!(
                        "[ALPINE][DISCOVERY][WARN] iface={} error={}",
                        attempt.iface, err
                    );
                    last_err = Some(anyhow::Error::from(err));
                    continue;
                }
            },
            Err(err) => {
                println!(
                    "[ALPINE][DISCOVERY][WARN] iface={} error={}",
                    attempt.iface, err
                );
                last_err = Some(anyhow::Error::from(err));
                continue;
            }
        }
    }

    Err(map_discovery_error(
        last_err.unwrap_or_else(|| anyhow::anyhow!("broadcast discovery failed")),
        &attempt_summaries,
    ))
}

fn map_discovery_error(err: anyhow::Error, attempts: &[String]) -> anyhow::Error {
    let err_str = format!("{}", err);
    if err_str.contains("timed out") || err_str.contains("Timeout") {
        if attempts.is_empty() {
            anyhow::anyhow!(
                "no devices responded to discovery; try --force-unicast <ip:port> or provide a manual IP"
            )
        } else {
            anyhow::anyhow!(
                "no devices responded to broadcast discovery on interfaces: {}. Broadcast may be blocked; try `alpine discover <ip:port>` or `--force-unicast <ip:port>`.",
                attempts.join(", ")
            )
        }
    } else {
        err
    }
}

struct IfaceAttempt {
    iface: String,
    local_ip: std::net::Ipv4Addr,
    netmask: std::net::Ipv4Addr,
    broadcast: std::net::Ipv4Addr,
}

fn collect_interfaces(_port: u16) -> anyhow::Result<Vec<IfaceAttempt>> {
    let mut attempts = Vec::new();
    let ifaces = get_if_addrs()?;
    for iface in ifaces {
        if iface.is_loopback() {
            continue;
        }
        if let get_if_addrs::IfAddr::V4(v4) = iface.addr {
            let ipv4 = v4.ip;
            let maskv4 = v4.netmask;
            let ip_u32 = u32::from_be_bytes(ipv4.octets());
            let mask_u32 = u32::from_be_bytes(maskv4.octets());
            let bcast = ip_u32 | (!mask_u32);
            let bcast_ip = std::net::Ipv4Addr::from(bcast.to_be_bytes());
            attempts.push(IfaceAttempt {
                iface: iface.name,
                local_ip: ipv4,
                netmask: maskv4,
                broadcast: bcast_ip,
            });
        }
    }
    Ok(attempts)
}
