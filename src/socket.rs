use cached::proc_macro::cached;
use cached::TimedSizedCache;
use log::{debug, warn};

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::time::Instant;
use tokio::net::lookup_host;
use tokio::net::UdpSocket;
use tokio::time::{timeout, Duration};

use crate::errors::DnsError;
use crate::message::Group;

pub trait Timeout = Fn(Duration) -> bool;

#[cached(
    create = "{ TimedSizedCache::with_size_and_lifespan(1000, 3600) }",
    type = "TimedSizedCache<String, Result<SocketAddr, DnsError>>",
    convert = r#"{ format!("{}", host.as_ref()) }"#
)]
pub async fn to_socket(host: impl AsRef<str>) -> Result<SocketAddr, DnsError>
{
    let to_err = |e| {
        DnsError::Failed(format!(
            "Unable to retrieve ip for {}. Message: {}",
            host.as_ref(),
            e
        ))
    };
    for addr in lookup_host(host.as_ref()).await.map_err(to_err)? {
        return Ok(addr);
    }
    return Err(DnsError::Failed(format!(
        "Unable to retrieve ip for {}",
        host.as_ref()
    )));
}

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
            warn!("Unable to join multicast network {}", remote_ip);
            return false;
        } else {
            debug!("Joined multicast {}", remote_ip);
            self.cache.insert(remote_ip.clone(), true);
            return true;
        }
    }

    pub async fn join_groups(&mut self, sock: &UdpSocket, groups: &[Group], local_addr: &IpAddr)
    {
        for group in groups {
            for remote_host in &group.allowed_hosts {
                let addr = match to_socket(remote_host).await {
                    Ok(a) => a,
                    _ => {
                        warn!("Unable to parse or retrieve address for {}", remote_host);
                        continue;
                    }
                };
                if addr.ip().is_multicast() {
                    self.join_group(sock, local_addr, &addr.ip());
                }
            }
        }
    }
}

pub async fn receive_from_timeout(
    socket: &UdpSocket,
    buf: &mut [u8],
    timeout_callback: impl Timeout,
) -> io::Result<(usize, SocketAddr)>
{
    let timeout_duration = Duration::from_millis(50);
    let now = Instant::now();
    loop {
        match timeout(timeout_duration, socket.recv_from(buf)).await {
            Ok(v) => return v,
            Err(_) => {
                if timeout_callback(now.elapsed()) {
                    return io::Result::Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        format!("socket read timeout {}", now.elapsed().as_millis()),
                    ));
                }
                continue;
            }
        };
    }
}

pub async fn to_visible_ip(local_ip: Option<IpAddr>, group: &Group) -> IpAddr
{
    if let Some(host) = &group.visible_ip {
        if let Ok(sock_addr) = to_socket(format!("{}:0", host)).await {
            return sock_addr.ip();
        }
    }
    if let Some(ip) = local_ip {
        return ip;
    }
    return group.send_using_address.ip();
}
