use alpine_protocol_sdk::{
    DiscoveryClient, DiscoveryClientOptions, DiscoveryOutcome, claim_discovery,
};
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
            prefer_multicast: true,
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
    let client = DiscoveryClient::new(options).map_err(anyhow::Error::from)?;
    let outcome = client
        .discover(&["alpine-control".to_string()])
        .map_err(anyhow::Error::from)?;
    Ok(outcome)
}
