use log::{debug, info, warn};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::net::{IpAddr, Ipv4Addr};
use tokio::net::UdpSocket;

use crate::errors::ConnectionError;
use crate::message::Group;

pub fn obtain_local_addr(sock: &UdpSocket) -> Result<IpAddr, ConnectionError>
{
    return sock
        .local_addr()
        .map(|s| s.ip().clone())
        .map_err(|err| ConnectionError::IoError(err));
}

pub async fn obtain_socket(
    local_address: &SocketAddr,
    remote_addr: &SocketAddr,
) -> Result<UdpSocket, ConnectionError>
{
    debug!("Send to {} using {}", remote_addr, local_address);
    let sock = UdpSocket::bind(local_address).await?;
    sock.connect(remote_addr).await?;
    return Ok(sock);
}

pub fn join_group(sock: &UdpSocket, interface_addr: &IpAddr, remote_ip: &IpAddr)
{
    let interface_ipv4 = match interface_addr {
        IpAddr::V4(ipv4) => ipv4,
        _ => {
            warn!("Ipv6 multicast not supported");
            return;
        }
    };

    let op = match remote_ip {
        IpAddr::V4(multicast_ipv4) => {
            sock.set_multicast_loop_v4(false).unwrap_or(());
            sock.join_multicast_v4(multicast_ipv4.clone(), interface_ipv4.clone())
        }
        _ => {
            warn!("Ipv6 multicast not supported");
            return;
        }
    };
    if let Err(_) = op {
        warn!("Unable to join multicast network");
    } else {
        debug!("Joined multicast {}", remote_ip);
    }
}

pub fn join_groups(sock: &UdpSocket, groups: &[Group], ipv4: &Ipv4Addr)
{
    let mut cache = HashMap::new();
    for group in groups {
        for addr in &group.allowed_hosts {
            if cache.contains_key(&addr.ip()) {
                continue;
            }
            if addr.ip().is_multicast() {
                let op = match addr.ip() {
                    IpAddr::V4(ip) => {
                        sock.set_multicast_loop_v4(false).unwrap_or(());
                        sock.join_multicast_v4(ip, ipv4.clone())
                    }
                    _ => {
                        warn!("Multicast ipv6 not supported");
                        continue;
                    }
                };
                if let Err(_) = op {
                    warn!("Unable to join multicast {}", addr.ip());
                    continue;
                } else {
                    cache.insert(addr.ip(), true);
                    info!("Joined multicast {}", addr.ip());
                }
            }
        }
    }
}
