use std::fmt;
use std::net::{IpAddr, SocketAddr};

use crate::errors::ConnectionError;
use crate::message::Group;
#[cfg(feature = "public-ip")]
use crate::socket::retrieve_public_ip;
use crate::socket::{remove_ipv4_mapping, retrieve_local_address, to_socket_address, IpAddrExt};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity
{
    address: IpAddr,
}

pub trait IdentityVerifier
{
    fn verify(&self, identity: &Identity) -> Option<&Group>;
}

impl Identity
{
    // for ipv6 sockets ipv4 mapped address should be used as ipv4 address
    pub fn from_mapped(item: &SocketAddr) -> Self
    {
        Self::from(remove_ipv4_mapping(item))
    }

    pub fn is_global(&self) -> bool
    {
        IpAddrExt::is_global(&self.address)
    }
}

impl From<&IpAddr> for Identity
{
    fn from(item: &IpAddr) -> Self
    {
        Self { address: *item }
    }
}

impl From<IpAddr> for Identity
{
    fn from(item: IpAddr) -> Self
    {
        Self { address: item }
    }
}

impl From<&SocketAddr> for Identity
{
    fn from(item: &SocketAddr) -> Self
    {
        remove_ipv4_mapping(item).ip().into()
    }
}

impl From<SocketAddr> for Identity
{
    fn from(item: SocketAddr) -> Self
    {
        remove_ipv4_mapping(&item).ip().into()
    }
}

impl fmt::Display for Identity
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result
    {
        write!(f, "{}", self.address.to_string())
    }
}

pub async fn retrieve_identity(
    remote_address: &SocketAddr,
    group: &Group,
) -> Result<Identity, ConnectionError>
{
    if let Some(relay) = &group.relay {
        match to_socket_address(&relay.host) {
            Ok(relay_addr) if &relay_addr == remote_address => {
                return Ok(Identity::from(remote_address))
            }
            _ => (),
        };
    };

    if let Some(host) = &group.visible_ip {
        return Ok(to_socket_address(format!("{}:0", host)).map(Identity::from)?);
    }

    let local_addr = retrieve_local_address(&group.send_using_address, remote_address).await?;

    if IpAddrExt::is_global(&remote_address.ip()) {
        #[cfg(feature = "public-ip")]
        return Ok(retrieve_public_ip(local_addr).await.map(Identity::from)?);
        #[cfg(not(feature = "public-ip"))]
        return Err(ConnectionError::FailedToConnect(
            "No public ip provided".to_owned(),
        ));
    }

    Ok(Identity::from(local_addr))
}

pub fn identity_matching_hosts(
    hosts: impl IntoIterator<Item = impl AsRef<str>>,
    identity: &Identity,
    trust_relay: &Option<String>,
) -> bool
{
    if let Some(ref r) = trust_relay {
        if let Ok(s) = to_socket_address(r) {
            if &Identity::from(s.ip()) == identity {
                return true;
            }
        };
    }
    for host in hosts {
        let external_ip = match to_socket_address(host) {
            Ok(s) => s.ip(),
            _ => continue,
        };
        if (external_ip.is_multicast() && !identity.is_global())
            || &Identity::from(external_ip) == identity
        {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod identitytest
{
    use super::*;
    use crate::assert_error_type;
    use crate::message::Group;
    use crate::wait;

    fn identity_provider() -> Vec<(&'static str, SocketAddr, Group)>
    {
        return vec![
            (
                "127.0.0.1",
                "127.0.0.1:0".parse().unwrap(),
                Group::from_addr("test1", "127.0.0.1:9811", "127.0.0.1"),
            ),
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
    fn test_retrieve_identity()
    {
        for (expected, remote_addr, group) in identity_provider() {
            let res = wait!(retrieve_identity(&remote_addr, &group));
            assert_eq!(
                Identity::from(expected.parse::<IpAddr>().unwrap()),
                res.unwrap()
            );
        }
    }

    #[test]
    fn test_retrieve_identity_errors()
    {
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
    }
}
