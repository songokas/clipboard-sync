use std::fmt;
use std::net::{IpAddr, SocketAddr};

use crate::errors::ConnectionError;
use crate::message::Group;
use crate::socket::{to_socket, to_visible_ip};

#[derive(Debug, Clone)]
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

    let ip = if remote_ip.is_multicast() {
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
    return Ok(Identity::from_ip(&ip));
}
