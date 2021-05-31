use log::{debug, warn};

use std::collections::HashMap;
use std::io;
use std::net::IpAddr;
use tokio::net::UdpSocket;

use crate::config::Groups;
use crate::socket::to_socket_address;

pub struct Multicast
{
    cache: HashMap<IpAddr, bool>,
}

impl Multicast
{
    pub fn new() -> Self
    {
        return Multicast {
            cache: HashMap::new(),
        };
    }

    pub fn join_group(
        &mut self,
        sock: &UdpSocket,
        interface_addr: &IpAddr,
        remote_ip: &IpAddr,
    ) -> bool
    {
        if self.cache.contains_key(&remote_ip) {
            return true;
        }
        let op = match remote_ip {
            IpAddr::V4(multicast_ipv4) => {
                if let IpAddr::V4(ipv4) = interface_addr {
                    sock.set_multicast_loop_v4(false).unwrap_or(());
                    sock.join_multicast_v4(multicast_ipv4.clone(), ipv4.clone())
                } else {
                    Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("invalid ipv4 address {}", interface_addr),
                    ))
                }
            }
            IpAddr::V6(multicast_ipv6) => {
                sock.set_multicast_loop_v6(false).unwrap_or(());
                sock.join_multicast_v6(multicast_ipv6, 0)
            }
        };
        if let Err(_) = op {
            warn!(
                "Unable to join multicast network {} using {}",
                remote_ip, interface_addr,
            );
            return false;
        } else {
            debug!("Joined multicast {}", remote_ip);
            self.cache.insert(remote_ip.clone(), true);
            return true;
        }
    }

    pub async fn join_groups(&mut self, sock: &UdpSocket, groups: &Groups, local_addr: &IpAddr)
    {
        for (_, group) in groups {
            for remote_host in &group.allowed_hosts {
                let addr = match to_socket_address(remote_host) {
                    Ok(a) => a,
                    _ => {
                        warn!("Unable to parse or retrieve address for {}", remote_host);
                        continue;
                    }
                };

                if addr.ip().is_multicast()
                    && (local_addr.is_ipv4() == addr.is_ipv4()
                        || local_addr.is_ipv6() == addr.is_ipv6())
                {
                    self.join_group(sock, local_addr, &addr.ip());
                }
            }
        }
    }
}
