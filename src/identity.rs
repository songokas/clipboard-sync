use std::fmt;
use std::net::{IpAddr, SocketAddr};

use crate::errors::ConnectionError;
use crate::message::Group;
use crate::socket::{retrieve_local_address, to_socket};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    addr: String,
}

impl From<&IpAddr> for Identity {
    fn from(item: &IpAddr) -> Self {
        return Self {
            addr: item.to_string(),
        };
    }
}

impl From<IpAddr> for Identity {
    fn from(item: IpAddr) -> Self {
        return Self {
            addr: item.to_string(),
        };
    }
}

impl From<&SocketAddr> for Identity {
    fn from(item: &SocketAddr) -> Self {
        return item.ip().into();
    }
}

impl From<SocketAddr> for Identity {
    fn from(item: SocketAddr) -> Self {
        return item.ip().into();
    }
}

impl From<&str> for Identity {
    fn from(item: &str) -> Self {
        return Identity {
            addr: item.to_owned(),
        };
    }
}

impl fmt::Display for Identity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.addr)
    }
}

pub async fn retrieve_identity(
    remote_address: &SocketAddr,
    group: &Group,
) -> Result<Identity, ConnectionError> {
    if let Some(host) = &group.visible_ip {
        return Ok(to_socket(format!("{}:0", host)).await.map(Identity::from)?);
    }

    let remote_ip = remote_address.ip();
    let is_private = match remote_ip {
        IpAddr::V4(ip) => ip.is_private() || ip.is_link_local(),
        _ => false,
    };
    let is_local = remote_ip.is_multicast() || remote_ip.is_loopback() || is_private;

    if !is_local {
        #[cfg(feature = " public-ip")]
        return Ok(retrieve_public_ip().await.map(Identity::from)?);
        #[cfg(not(feature = " public-ip"))]
        return Err(ConnectionError::FailedToConnect(
            "No public ip provided".to_owned(),
        ));
    }

    return Ok(
        retrieve_local_address(&group.send_using_address, remote_address)
            .await
            .map(Identity::from)?,
    );
}

#[cfg(test)]
mod sockettest {
    use super::*;
    use crate::message::Group;
    use crate::wait;

    fn identity_provider() -> Vec<(IpAddr, SocketAddr, Group)> {
        return vec![
            (
                "127.0.0.2".parse().unwrap(),
                "192.168.0.1:0".parse().unwrap(),
                Group::from_addr("test5", "127.0.0.2:9811", "192.168.0.1"),
            ),
            (
                "127.0.0.2".parse().unwrap(),
                "172.16.0.1:0".parse().unwrap(),
                // Some("127.0.0.2".parse().unwrap()),
                Group::from_name("test2"),
            ),
            (
                "127.0.0.2".parse().unwrap(),
                "224.0.0.1:0".parse().unwrap(),
                // Some("127.0.0.2".parse().unwrap()),
                Group::from_name("test3"),
            ),
            (
                "127.0.0.2".parse().unwrap(),
                "169.254.0.1:0".parse().unwrap(),
                // Some("127.0.0.2".parse().unwrap()),
                Group::from_name("test4"),
            ),
            (
                "127.0.0.3".parse().unwrap(),
                "169.254.0.1:0".parse().unwrap(),
                // None,
                Group::from_addr("test5", "127.0.0.3:9811", "192.168.0.1"),
            ),
            (
                "192.168.0.1".parse().unwrap(),
                "127.0.0.1:0".parse().unwrap(),
                // Some("192.168.0.1".parse().unwrap()),
                Group::from_name("test4"),
            ),
            (
                "192.168.0.1".parse().unwrap(),
                "127.0.0.1:0".parse().unwrap(),
                // None,
                Group::from_addr("test5", "192.168.0.1:9811", "192.168.0.1"),
            ),
            (
                "8.8.8.8".parse().unwrap(),
                "1.1.1.1:0".parse().unwrap(),
                // Some("127.0.0.1".parse().unwrap()),
                Group::from_public("test4", "8.8.8.8"),
            ),
        ];
    }
    #[test]
    fn test_retrieve_identity() {
        for (expected, remote_ip, group) in identity_provider() {
            let res = wait!(retrieve_identity(&remote_ip, &group));
            assert_eq!(Identity::from(&expected), res.unwrap());
        }
    }
}
