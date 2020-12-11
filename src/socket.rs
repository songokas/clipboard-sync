use log::{debug, error, info, warn};
#[cfg(feature = "quinn")]
use quinn::{Endpoint, Incoming};
use std::collections::HashMap;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr};
use tokio::net::UdpSocket;

use crate::message::Group;

pub enum SocketEndpoint
{
    #[cfg(feature = "basic")]
    #[cfg(feature = "frames")]
    Socket(UdpSocket),
    #[cfg(feature = "quinn")]
    QuicClient(Endpoint),
    #[cfg(feature = "quinn")]
    QuicServer(Incoming),
}

impl SocketEndpoint
{
    pub fn socket(&self) -> Option<&UdpSocket>
    {
        if let Self::Socket(s) = self {
            return Some(s);
        } else {
            return None;
        }
    }

    pub fn socket_consume(self) -> Option<UdpSocket>
    {
        return match self {
            Self::Socket(s) => Some(s),
            _ => None
        };
    }

    pub fn ip(&self) -> Option<IpAddr>
    {
        return match self {
            Self::Socket(s) => {
                return s
                   .local_addr()
                   .map(|s| s.ip().clone())
                   .ok();
            },
            _ => None
        };
    }

    #[cfg(feature = "quinn")]
    pub fn client_consume(self) -> Option<Endpoint>
    {
        return if let Self::QuicClient(s) = self {
            Some(s)
        } else {
            None
        };
    }

    #[cfg(feature = "quinn")]
    pub fn server(&mut self) -> Option<&mut Incoming>
    {
        return if let Self::QuicServer(s) = self {
            Some(s)
        } else {
            None
        };
    }
}

#[derive(Debug, Copy, Clone)]
pub enum Protocol
{
    Basic,
    Frames,
    Quic,
}

impl Protocol
{
    pub fn requires_public_key(&self) -> bool
    {
        return if let Self::Quic = self { true } else { false };
    }
}

impl fmt::Display for Protocol
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result
    {
        write!(f, "{}", self)
    }
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
