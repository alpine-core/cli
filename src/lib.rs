pub mod commands;
pub mod device_cache;
pub mod discovery;
pub mod identity_store;
pub mod netinfo;
pub mod selector;
pub mod stream_session;

use std::net::SocketAddr;

pub fn parse_socket(addr: &str) -> anyhow::Result<SocketAddr> {
    let trimmed = addr.strip_prefix("udp://").unwrap_or(addr);
    Ok(trimmed.parse()?)
}
