pub use alpine_protocol_sdk::discovery::DiscoveryRunOptions;
use alpine_protocol_sdk::discovery::{
    DiscoveryOutcome, DiscoveryRunError, run_discovery_with_options as run_sdk_discovery,
};
use std::net::SocketAddr;

use crate::trust::{TrustOptions, load_latest_trust_view};

pub async fn run_discovery(remote_addr: SocketAddr) -> anyhow::Result<DiscoveryOutcome> {
    run_discovery_with_options(remote_addr, DiscoveryRunOptions::default()).await
}

pub async fn run_discovery_with_options(
    remote_addr: SocketAddr,
    mut opts: DiscoveryRunOptions,
) -> anyhow::Result<DiscoveryOutcome> {
    let trust_opts = TrustOptions::default();
    let trust_view = match load_latest_trust_view(&trust_opts).await {
        Ok(view) => {
            for warning in &view.warnings {
                println!("[ALPINE][TRUST][WARN] {}", warning);
            }
            Some(view)
        }
        Err(err) => {
            println!("[ALPINE][TRUST][WARN] {}", err);
            None
        }
    };
    opts.attester_registry = trust_view.as_ref().map(|view| view.registry.clone());

    run_sdk_discovery(remote_addr, opts)
        .await
        .map_err(map_discovery_error)
}

fn map_discovery_error(err: DiscoveryRunError) -> anyhow::Error {
    match err {
        DiscoveryRunError::Broadcast(alpine_protocol_sdk::DiscoveryError::Timeout)
        | DiscoveryRunError::Unicast(alpine_protocol_sdk::DiscoveryError::Timeout) => {
            anyhow::anyhow!(
                "no devices responded to discovery; try --force-unicast <ip:port> or provide a manual IP"
            )
        }
        other => anyhow::Error::new(other),
    }
}
