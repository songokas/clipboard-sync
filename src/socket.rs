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

use crate::errors::{ConnectionError, DnsError};
use crate::message::Group;

pub async fn retrieve_identity(
    remote_ip: &IpAddr,
    local_ip: Option<IpAddr>,
    group: &Group,
) -> Result<IpAddr, ConnectionError>
{
    let is_private = match remote_ip {
        IpAddr::V4(ip) => ip.is_private() || ip.is_link_local(),
        _ => false,
    };

    let identity = if remote_ip.is_multicast() {
        // match group.protocol {
        //     Protocol::Basic => (),
        //     _ => {
        //         return Err(ConnectionError::InvalidProtocol(format!(
        //             "Protocol {} does not support multicast",
        //             group.protocol
        //         )));
        //     }
        // };
        to_visible_ip(local_ip, group).await
    } else if remote_ip.is_loopback() || is_private {
        to_visible_ip(local_ip, group).await
    } else {
        let host = group.visible_ip.as_ref().ok_or(ConnectionError::NoPublic(
            "Group missing public ip however global routing requested".to_owned(),
        ))?;
        let sock_addr = to_socket(format!("{}:0", host)).await?;
        sock_addr.ip()
    };
    return Ok(identity);
}

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
    timeout_callback: impl Fn(Duration) -> bool,
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

#[cfg(test)]
mod sockettest
{
    use super::*;
    use crate::message::Group;
    use crate::{assert_error_type, wait};

    fn identity_provider() -> Vec<(IpAddr, IpAddr, Option<IpAddr>, Group)>
    {
        return vec![
            (
                "127.0.0.2".parse().unwrap(),
                "192.168.0.1".parse().unwrap(),
                Some("127.0.0.2".parse().unwrap()),
                Group::from_name("test1"),
            ),
            (
                "127.0.0.2".parse().unwrap(),
                "172.16.0.1".parse().unwrap(),
                Some("127.0.0.2".parse().unwrap()),
                Group::from_name("test2"),
            ),
            (
                "127.0.0.2".parse().unwrap(),
                "224.0.0.1".parse().unwrap(),
                Some("127.0.0.2".parse().unwrap()),
                Group::from_name("test3"),
            ),
            (
                "127.0.0.2".parse().unwrap(),
                "169.254.0.1".parse().unwrap(),
                Some("127.0.0.2".parse().unwrap()),
                Group::from_name("test4"),
            ),
            (
                "127.0.0.3".parse().unwrap(),
                "169.254.0.1".parse().unwrap(),
                None,
                Group::from_addr("test5", "127.0.0.3:9811", "192.168.0.1"),
            ),
            (
                "192.168.0.1".parse().unwrap(),
                "127.0.0.1".parse().unwrap(),
                Some("192.168.0.1".parse().unwrap()),
                Group::from_name("test4"),
            ),
            (
                "192.168.0.1".parse().unwrap(),
                "127.0.0.1".parse().unwrap(),
                None,
                Group::from_addr("test5", "192.168.0.1:9811", "192.168.0.1"),
            ),
            (
                "8.8.8.8".parse().unwrap(),
                "1.1.1.1".parse().unwrap(),
                Some("127.0.0.1".parse().unwrap()),
                Group::from_public("test4", "8.8.8.8"),
            ),
        ];
    }
    #[test]
    fn test_retrieve_identity()
    {
        for (expected, remote_ip, local_ip, group) in identity_provider() {
            let res = wait!(retrieve_identity(&remote_ip, local_ip, &group));
            assert_eq!(expected, res.unwrap());
        }
    }

    #[test]
    fn test_retrieve_identity_errors()
    {
        let r1 = (
            "1.1.1.1".parse().unwrap(),
            Some("127.0.0.1".parse().unwrap()),
            Group::from_public("test1", "8.8.8.8.3"),
        );
        let res = wait!(retrieve_identity(&r1.0, r1.1, &r1.2));
        assert_error_type!(res, ConnectionError::DnsError(_));

        let r1 = (
            "1.1.1.1".parse().unwrap(),
            Some("127.0.0.1".parse().unwrap()),
            Group::from_public("test2", "abc"),
        );
        let res = wait!(retrieve_identity(&r1.0, r1.1, &r1.2));
        assert_error_type!(res, ConnectionError::DnsError(_));

        // #[cfg(feature = "frames")]
        // {
        //     let mut g = Group::from_name("test3");
        //     g.protocol = Protocol::Frames;
        //     let r1 = (
        //         "224.0.0.1".parse().unwrap(),
        //         Some("127.0.0.1".parse().unwrap()),
        //         g,
        //     );
        //     let res = wait!(retrieve_identity(&r1.0, r1.1, &r1.2));
        //     assert_error_type!(res, ConnectionError::InvalidProtocol(_));
        // }
        let r1 = (
            "1.1.1.1".parse().unwrap(),
            Some("127.0.0.1".parse().unwrap()),
            Group::from_name("test5"),
        );
        let res = wait!(retrieve_identity(&r1.0, r1.1, &r1.2));
        assert_error_type!(res, ConnectionError::NoPublic(_));
    }
}
