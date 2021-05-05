use std::fmt;
use std::net::{IpAddr, SocketAddr};

use crate::errors::{ConnectionError, DnsError};
use crate::message::Group;
use crate::socket::{to_socket, to_visible_ip};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity
{
    addr: String,
}

impl Identity
{
    pub fn from_ip(ip: &IpAddr) -> Self
    {
        return Self {
            addr: ip.to_string(),
        };
    }

    pub fn from_addr(addr: &SocketAddr) -> Self
    {
        return Self::from_ip(&addr.ip());
    }
}

impl From<&str> for Identity
{
    fn from(item: &str) -> Self
    {
        return Identity {
            addr: item.to_owned(),
        };
    }
}

impl fmt::Display for Identity
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result
    {
        write!(f, "{}", self.addr)
    }
}

pub async fn retrieve_identity(
    remote_ip: &IpAddr,
    local_ip: Option<IpAddr>,
    group: &Group,
) -> Result<Identity, ConnectionError>
{
    let is_private = match remote_ip {
        IpAddr::V4(ip) => ip.is_private() || ip.is_link_local(),
        _ => false,
    };

    let ip = if remote_ip.is_multicast() || remote_ip.is_loopback() || is_private {
        to_visible_ip(local_ip, group).await
    } else {
        let ip = match &group.visible_ip {
            Some(host) => to_socket(format!("{}:0", host)).await.map(|s| s.ip()),
            #[cfg(feature = " public-ip")]
            None => retrieve_public_ip().await,
            #[cfg(not(feature = " public-ip"))]
            None => Err(DnsError::Failed("No public ip provided".to_owned())),
        };
        match ip {
            Ok(ip) => ip,
            Err(_) => to_visible_ip(local_ip, group).await,
        }
    };
    return Ok(Identity::from_ip(&ip));
}

#[cfg(feature = " public-ip")]
#[cached(size = 1, time = 60)]
pub async fn retrieve_public_ip() -> Result<IpAddr, DnsError>
{
    return public_ip::addr()
        .await
        .ok_or(DnsError::Failed("Failed to retrieve public ip".to_owned()));
}

#[cfg(test)]
mod sockettest
{
    use super::*;
    use crate::message::Group;
    use crate::wait;

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
            assert_eq!(Identity::from_ip(&expected), res.unwrap());
        }
    }
}
