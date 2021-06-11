use std::fmt;
use std::net::{IpAddr, SocketAddr};

use crate::config::Groups;
use crate::errors::{ConnectionError, ValidationError};
use crate::message::{Group, Message};
#[cfg(feature = "public-ip")]
use crate::socket::retrieve_public_ip;
use crate::socket::{remove_ipv4_mapping, retrieve_local_address, to_socket_address, IpAddrExt};

use crate::time::{get_time, is_timestamp_valid};

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
        return Self::from(remove_ipv4_mapping(item));
    }
}

impl From<&IpAddr> for Identity
{
    fn from(item: &IpAddr) -> Self
    {
        return Self {
            address: item.clone(),
        };
    }
}

impl From<IpAddr> for Identity
{
    fn from(item: IpAddr) -> Self
    {
        return Self { address: item };
    }
}

impl From<&SocketAddr> for Identity
{
    fn from(item: &SocketAddr) -> Self
    {
        return remove_ipv4_mapping(item).ip().into();
    }
}

impl From<SocketAddr> for Identity
{
    fn from(item: SocketAddr) -> Self
    {
        return remove_ipv4_mapping(&item).ip().into();
    }
}

// impl From<&str> for Identity
// {
//     fn from(item: &str) -> Self
//     {
//         return Identity {
//             address: item.to_owned(),
//         };
//     }
// }

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
    match &group.relay {
        Some(relay) => match to_socket_address(&relay.host) {
            Ok(relay_addr) if &relay_addr == remote_address => {
                return Ok(Identity::from(remote_address))
            }
            _ => (),
        },
        _ => (),
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

    return Ok(Identity::from(local_addr));
}

pub fn identity_matching_hosts(
    hosts: impl IntoIterator<Item = impl AsRef<str>>,
    identity: &Identity,
    trust_relay: &Option<String>,
) -> bool
{
    if let Some(ref r) = trust_relay {
        match to_socket_address(r) {
            Ok(s) => {
                if &Identity::from(s.ip()) == identity {
                    return true;
                }
            }
            _ => (),
        };
    }
    for host in hosts {
        let external_ip = match to_socket_address(host) {
            Ok(s) => s.ip(),
            _ => continue,
        };
        if external_ip.is_multicast() || &Identity::from(external_ip) == identity {
            return true;
        }
    }
    return false;
}

pub fn validate<'a>(
    buffer: &[u8],
    groups: &'a Groups,
    identity: &Identity,
) -> Result<(Message, &'a Group), ValidationError>
{
    let message: Message = bincode::deserialize(buffer).map_err(|err| {
        ValidationError::DeserializeFailed(format!(
            "Validation invalid data provided: {}",
            (*err).to_string()
        ))
    })?;

    let group = match groups.iter().find(|(_, group)| group.name == message.group) {
        Some((_, group)) => group,
        _ => {
            return Err(ValidationError::IncorrectGroup(format!(
                "Group {} does not exist",
                message.group
            )));
        }
    };

    if !is_timestamp_valid(message.time, group.message_valid_for) {
        let now = get_time();
        let diff = if now >= message.time {
            now - message.time
        } else {
            message.time - now
        };
        return Err(ValidationError::InvalidTimestamp(
            diff,
            group.message_valid_for,
        ));
    }

    if !identity_matching_hosts(
        group.allowed_hosts.iter(),
        identity,
        &group.relay.as_ref().map(|r| r.host.clone()),
    ) {
        return Err(ValidationError::IncorrectGroup(format!(
            "Group {} does not allow {}",
            group.name, identity
        )));
    }

    return Ok((message, group));
}

#[cfg(test)]
mod identitytest
{
    use indexmap::indexmap;

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

    #[test]
    fn test_validate()
    {
        let groups = indexmap! {
            "test1".to_owned() => Group::from_addr("test1", "127.0.0.1:8900", "127.0.0.1:8900"),
            "test2".to_owned() => Group::from_name("test2"),
        };
        let sequences: Vec<(&'static str, Vec<u8>, IpAddr, bool)> = vec![
            (
                "group name and ip match",
                bincode::serialize(&Message::from_group("test1"))
                    .unwrap()
                    .to_vec(),
                "127.0.0.1".parse::<IpAddr>().unwrap(),
                true,
            ),
            (
                "group name doest not match",
                bincode::serialize(&Message::from_group("none"))
                    .unwrap()
                    .to_vec(),
                "127.0.0.1".parse::<IpAddr>().unwrap(),
                false,
            ),
            (
                "ip doest not match",
                bincode::serialize(&Message::from_group("test1"))
                    .unwrap()
                    .to_vec(),
                "127.0.0.2".parse::<IpAddr>().unwrap(),
                false,
            ),
            (
                "empty ip",
                bincode::serialize(&Message::from_group("test1"))
                    .unwrap()
                    .to_vec(),
                "0.0.0.0".parse::<IpAddr>().unwrap(),
                false,
            ),
            (
                "random1",
                [3, 3, 98].to_vec(),
                "0.0.0.0".parse::<IpAddr>().unwrap(),
                false,
            ),
            (
                "empty data",
                [].to_vec(),
                "0.0.0.0".parse::<IpAddr>().unwrap(),
                false,
            ),
        ];

        for (name, bytes, id, expected) in sequences {
            let result = validate(&bytes, &groups, &Identity::from(id));
            assert_eq!(result.is_ok(), expected, "{}", name);
        }
    }
}
