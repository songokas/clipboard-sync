use std::fmt;
use std::net::{IpAddr, SocketAddr};

use indexmap::indexset;

use crate::errors::ConnectionError;
use crate::message::{GroupName, SendGroup};
use crate::socket::retrieve_public_ip;
use crate::socket::{remove_ipv4_mapping, resolve_local_ip, to_socket_address, IpAddrExt};

#[cfg_attr(test, derive(serde::Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq, Copy)]
pub struct Identity(IpAddr);

pub trait IdentityVerifier {
    fn verify(&self, identity: Identity) -> Option<&GroupName>;
}

impl Identity {
    pub fn is_global(&self) -> bool {
        IpAddrExt::is_global(&self.0)
    }

    pub fn as_socket_addr(&self) -> SocketAddr {
        SocketAddr::new(self.0, 0)
    }
}

impl From<&IpAddr> for Identity {
    fn from(item: &IpAddr) -> Self {
        Self(*item)
    }
}

impl From<IpAddr> for Identity {
    fn from(item: IpAddr) -> Self {
        Self(item)
    }
}

impl From<&SocketAddr> for Identity {
    fn from(item: &SocketAddr) -> Self {
        remove_ipv4_mapping(item).ip().into()
    }
}

impl From<SocketAddr> for Identity {
    fn from(item: SocketAddr) -> Self {
        remove_ipv4_mapping(&item).ip().into()
    }
}

impl fmt::Display for Identity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

pub async fn retrieve_identity(
    local_addr: SocketAddr,
    remote_addr: SocketAddr,
    group: &SendGroup,
) -> Result<Identity, ConnectionError> {
    let local = indexset! { local_addr };
    if let Some(relay) = &group.relay {
        match to_socket_address(&local, &relay.host) {
            Ok((_, relay_addr)) if relay_addr == remote_addr => {
                return Ok(Identity::from(remote_addr))
            }
            _ => (),
        };
    };

    if let Some(host) = &group.visible_ip {
        return Ok(
            to_socket_address(&local, format!("{}:0", host)).map(|(_, r)| Identity::from(r))?
        );
    }

    if IpAddrExt::is_global(&remote_addr.ip()) {
        return Ok(retrieve_public_ip(local_addr).await.map(Identity::from)?);
    }

    if local_addr.ip().is_unspecified() {
        if let Some(ip) = resolve_local_ip(local_addr.ip(), remote_addr) {
            return Ok(ip.into());
        }
    }
    Ok(local_addr.into())
}

pub fn identity_matching_hosts(
    hosts: impl IntoIterator<Item = impl AsRef<str>>,
    identity: Identity,
    trust_relay: &Option<String>,
) -> bool {
    let local = indexset! { identity.as_socket_addr() };
    if let Some(ref r) = trust_relay {
        if let Ok((_, r)) = to_socket_address(&local, r) {
            if Identity::from(r.ip()) == identity {
                return true;
            }
        };
    }
    for host in hosts {
        let external_ip = match to_socket_address(&local, host) {
            Ok((_, r)) => r.ip(),
            _ => continue,
        };
        if (external_ip.is_multicast() && !identity.is_global())
            || Identity::from(external_ip) == identity
        {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use test_data_file::test_data_file;

    use super::*;

    #[test_data_file(path = "tests/samples/identity.json")]
    #[tokio::test]
    async fn test_retrieve_identity(
        expected: IpAddr,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
        group: SendGroup,
    ) {
        let res = retrieve_identity(local_addr, remote_addr, &group).await;
        assert_eq!(Identity::from(expected), res.unwrap());
    }
}
