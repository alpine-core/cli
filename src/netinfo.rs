use std::net::{IpAddr, SocketAddr, UdpSocket};

use get_if_addrs::get_if_addrs;
use tracing::{info, warn};

pub fn log_local_interfaces() {
    match get_if_addrs() {
        Ok(ifaces) => {
            if ifaces.is_empty() {
                info!("[CLI][NET] no interfaces detected");
                return;
            }
            info!("[CLI][NET] detected {} network interfaces:", ifaces.len());
            for iface in ifaces {
                info!(
                    "[CLI][NET] iface={} addr={} loopback={} multicast={}",
                    iface.name,
                    iface.ip(),
                    iface.is_loopback(),
                    iface.ip().is_multicast()
                );
            }
        }
        Err(err) => warn!("[CLI][NET] interface enumeration failed: {}", err),
    }
}

pub fn log_udp_route_hint(remote: SocketAddr) {
    match determine_local_socket(remote) {
        Some(local) => info!(
            "[CLI][NET] UDP route hint: remote={} local_bind={}",
            remote, local
        ),
        None => warn!(
            "[CLI][NET] unable to determine UDP routing hint for remote {}",
            remote
        ),
    }
}

fn determine_local_socket(remote: SocketAddr) -> Option<SocketAddr> {
    let fallback = SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::new(8, 8, 8, 8)), 53);
    let targets = [remote, fallback];
    for target in targets {
        if let Ok(sock) = UdpSocket::bind("0.0.0.0:0") {
            if sock.connect(target).is_ok() {
                if let Ok(local) = sock.local_addr() {
                    return Some(local);
                }
            }
        }
    }
    None
}
