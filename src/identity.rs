use std::fmt;
use std::net::{IpAddr, SocketAddr};

use crate::errors::ConnectionError;
use crate::message::Group;
use crate::socket::{remove_ipv4_mapping, retrieve_local_address, to_socket, IpAddrExt};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    addr: String,
}

impl Identity {
    // for ipv6 sockets ipv4 mapped address should be use as ipv4 address
    pub fn from_mapped(item: &SocketAddr) -> Self {
        return Self::from(remove_ipv4_mapping(item));
    }
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

    if IpAddrExt::is_global(&remote_address.ip()) {
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
mod identitytest {
    use super::*;
    use crate::assert_error_type;
    use crate::message::Group;
    use crate::wait;

    fn identity_provider() -> Vec<(&'static str, SocketAddr, Group)> {
        return vec![
            (
                "127.0.0.1",
                "127.0.0.1:0".parse().unwrap(),
                Group::from_addr("test1", "127.0.0.1:9811", "127.0.0.1"),
            ),
            // (
            //     "192.168.0.154",
            //     "172.16.0.1:0".parse().unwrap(),
            //     Group::from_addr("test1", "0.0.0.0:9811", "192.168.0.1"),
            // ),
            // (
            //     "127.0.0.2".parse().unwrap(),
            //     "224.0.0.1:0".parse().unwrap(),
            //     // Some("127.0.0.2".parse().unwrap()),
            //     Group::from_name("test3"),
            // ),
            // (
            //     "127.0.0.2".parse().unwrap(),
            //     "169.254.0.1:0".parse().unwrap(),
            //     // Some("127.0.0.2".parse().unwrap()),
            //     Group::from_name("test4"),
            // ),
            // (
            //     "127.0.0.3".parse().unwrap(),
            //     "169.254.0.1:0".parse().unwrap(),
            //     // None,
            //     Group::from_addr("test5", "127.0.0.3:9811", "192.168.0.1"),
            // ),
            // (
            //     "192.168.0.1".parse().unwrap(),
            //     "127.0.0.1:0".parse().unwrap(),
            //     // Some("192.168.0.1".parse().unwrap()),
            //     Group::from_name("test4"),
            // ),
            // (
            //     "192.168.0.1".parse().unwrap(),
            //     "127.0.0.1:0".parse().unwrap(),
            //     // None,
            //     Group::from_addr("test5", "192.168.0.1:9811", "192.168.0.1"),
            // ),
            (
                "8.8.8.8",
                "1.1.1.1:0".parse().unwrap(),
                Group::from_visible("test4", "8.8.8.8"),
            ),
            (
                "192.168.0.1",
                "192.168.0.18:0".parse().unwrap(),
                Group::from_visible("test4", "192.168.0.1"),
            ),
        ];
    }
    #[test]
    fn test_retrieve_identity() {
        for (expected, remote_addr, group) in identity_provider() {
            let res = wait!(retrieve_identity(&remote_addr, &group));
            assert_eq!(Identity::from(expected), res.unwrap());
        }
    }

    #[test]
    fn test_retrieve_identity_errors() {
        let r1 = (
            "1.1.1.1:0".parse().unwrap(),
            Group::from_visible("test1", "8.8.8.8.3"),
        );
        let res = wait!(retrieve_identity(&r1.0, &r1.1));
        assert_error_type!(res, ConnectionError::DnsError(_));

        let r1 = (
            "1.1.1.1:0".parse().unwrap(),
            Group::from_visible("test2", "abc"),
        );
        let res = wait!(retrieve_identity(&r1.0, &r1.1));
        assert_error_type!(res, ConnectionError::DnsError(_));

        let r1 = (
            "224.0.0.1:0".parse().unwrap(),
            Group::from_addr("test3", "192.168.254.254:0", "192.168.0.1"),
        );
        let res = wait!(retrieve_identity(&r1.0, &r1.1));
        assert_error_type!(res, ConnectionError::FailedToConnect(_));

        let r1 = ("1.1.1.1:0".parse().unwrap(), Group::from_name("test5"));
        let res = wait!(retrieve_identity(&r1.0, &r1.1));
        assert_error_type!(res, ConnectionError::FailedToConnect(_));
    }
}
