use indexmap::IndexSet;

use core::{
    convert::TryInto,
    net::{Ipv4Addr, Ipv6Addr},
};
use log::{debug, error, trace};
use std::net::{IpAddr, SocketAddr, ToSocketAddrs, UdpSocket};

use crate::{
    defaults::INIDICATION_SIZE,
    errors::{ConnectionError, DnsError},
};

#[derive(Debug, Clone)]
pub struct Destination {
    pub host: String,
    pub addr: SocketAddr,
}

impl Destination {
    pub fn new(host: String, addr: SocketAddr) -> Self {
        Self { host, addr }
    }

    pub fn host(&self) -> &str {
        &self.host
    }

    pub fn addr(&self) -> &SocketAddr {
        &self.addr
    }
}

impl From<Destination> for SocketAddr {
    fn from(d: Destination) -> SocketAddr {
        d.addr
    }
}

impl From<SocketAddr> for Destination {
    fn from(item: SocketAddr) -> Self {
        Self::new(item.ip().to_string(), item)
    }
}

impl std::fmt::Display for Destination {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "host: {} destination: {}", self.host(), self.addr())
    }
}

pub fn to_socket_address(
    local_addresses: &IndexSet<SocketAddr>,
    remote_addr: impl AsRef<str>,
) -> Result<(SocketAddr, SocketAddr), DnsError> {
    let to_err = |e| {
        DnsError::Failed(format!(
            "Unable to retrieve ip for {}. Message: {}",
            remote_addr.as_ref(),
            e
        ))
    };
    let addresses = remote_addr.as_ref().to_socket_addrs().map_err(to_err)?;
    for address in addresses {
        let Some(local_addr) = local_addresses
            .iter()
            .find(|l| l.is_ipv4() == address.is_ipv4() || l.is_ipv6() == address.is_ipv6())
        else {
            continue;
        };
        trace!(
            "Resolve dns: using local_addr={local_addr} remote_addr={address} from provided dns={}",
            remote_addr.as_ref()
        );
        return Ok((*local_addr, address));
    }
    Err(DnsError::Failed(format!(
        "Unable to retrieve ip for {}",
        remote_addr.as_ref()
    )))
}

#[cfg(feature = "public-ip")]
#[cfg_attr(feature = "cached", cached::proc_macro::cached(size = 10, time = 3600))]
pub async fn retrieve_public_ip(_local_addr: SocketAddr) -> Result<IpAddr, DnsError> {
    let result = public_ip::addr()
        .await
        .ok_or_else(|| DnsError::Failed("Failed to retrieve public ip".into()));
    if let Ok(ip) = result {
        debug!("Retrieved public ip {}", ip);
    }
    result
}

#[cfg(not(feature = "public-ip"))]
#[cfg_attr(feature = "cached", cached::proc_macro::cached(size = 10, time = 3600))]
pub async fn retrieve_public_ip(_local_addr: SocketAddr) -> Result<IpAddr, DnsError> {
    use crate::defaults::PUBLIC_IP_HTTP_RESOLVER;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let err = |e| DnsError::Failed(format!("Failed to retrieve public ip {e}"));
    let mut stream = tokio::net::TcpStream::connect(PUBLIC_IP_HTTP_RESOLVER)
        .await
        .map_err(err)?;
    // Format HTTP request
    let request = format!("GET / HTTP/1.1\r\nHost: {PUBLIC_IP_HTTP_RESOLVER}\r\n\r\n");
    stream.write_all(request.as_bytes()).await.map_err(err)?;
    let mut response = Vec::with_capacity(1000);
    stream.read_buf(&mut response).await.map_err(err)?;

    let ip = String::from_utf8_lossy(&response)
        .lines()
        .next_back()
        .and_then(|a| a.parse().ok())
        .ok_or_else(|| DnsError::Failed("Failed to retrieve public ip invalid last line".into()))?;
    debug!("Retrieved public ip {}", ip);
    Ok(ip)
}

pub fn ipv6_support() -> bool {
    let sock_addr: SocketAddr = match "[::]:0".parse() {
        Ok(a) => a,
        Err(_) => return false,
    };
    UdpSocket::bind(sock_addr).is_ok()
}

pub fn resolve_addresses(
    local_addresses: &IndexSet<SocketAddr>,
    remote_host: &str,
    cname: Option<&str>,
) -> Result<(SocketAddr, Destination), ConnectionError> {
    resolve_destination(local_addresses, remote_host, cname).inspect_err(|e| {
        error!("Unable to resolve destination address {remote_host} that matches local address {local_addresses:?} {e}");
    })
}

#[cfg_attr(
    feature = "cached",
    cached::proc_macro::cached(size = 10, option = true, time = 3600)
)]
pub fn resolve_local_ip(local_ip: IpAddr, remote_addr: SocketAddr) -> Option<IpAddr> {
    UdpSocket::bind(SocketAddr::new(local_ip, 0))
        .and_then(|s| {
            s.connect(remote_addr)?;
            s.local_addr().map(|s| s.ip())
        })
        .ok()
}

pub fn resolve_destination(
    local_addresses: &IndexSet<SocketAddr>,
    remote_host: &str,
    cname: Option<&str>,
) -> Result<(SocketAddr, Destination), ConnectionError> {
    let (local_addr, remote_addr) = match to_socket_address(local_addresses, remote_host) {
        Ok(a) => a,
        Err(e) => return Err(ConnectionError::DnsError(e)),
    };

    if remote_addr.port() == 0 {
        return Err(ConnectionError::DnsError(DnsError::Failed(format!(
            "Invalid remote address port specified {}",
            remote_addr.port(),
        ))));
    }

    let destination_host_or_ip = remote_host
        .strip_suffix(&format!(":{}", remote_addr.port()))
        .unwrap_or(remote_host);
    let host = cname.unwrap_or(destination_host_or_ip);

    Ok((local_addr, Destination::new(host.to_string(), remote_addr)))
}

pub fn remove_ipv4_mapping(addr: &SocketAddr) -> SocketAddr {
    let use_addr: SocketAddr = match addr {
        SocketAddr::V6(a) => Ipv6AddrExt::to_ipv4_mapped(a.ip())
            .map(|ip| SocketAddr::new(IpAddr::V4(ip), a.port()))
            .unwrap_or(SocketAddr::V6(*a)),
        _ => *addr,
    };
    use_addr
}

pub fn split_into_messages(data: &[u8]) -> Vec<Vec<u8>> {
    let mut index = 0;
    let mut messages = Vec::new();
    loop {
        let Some(size_indication_data) = data
            .get(index..(index + INIDICATION_SIZE))
            .and_then(|d| TryInto::<[u8; INIDICATION_SIZE]>::try_into(d).ok())
        else {
            break;
        };
        index += size_indication_data.len();
        let size = u64::from_be_bytes(size_indication_data) as usize;
        let Some(data) = data.get(index..(index + size)).map(|d| d.to_vec()) else {
            break;
        };
        index += data.len();
        messages.push(data);
    }
    messages
}

// @TODO remove once stable https://github.com/rust-lang/rust/issues/27709

pub trait IpAddrExt {
    fn is_global(&self) -> bool;
}

pub trait Ipv6AddrExt {
    fn to_ipv4_mapped(&self) -> Option<Ipv4Addr>;
}

impl IpAddrExt for IpAddr {
    // #[rustc_const_unstable(feature = "const_ip", issue = "76205")]
    #[inline]
    fn is_global(&self) -> bool {
        match self {
            IpAddr::V4(ip) => IpAddrExt::is_global(ip),
            IpAddr::V6(ip) => IpAddrExt::is_global(ip),
        }
    }
}

impl IpAddrExt for Ipv4Addr {
    // #[rustc_const_unstable(feature = "const_ipv4", issue = "76205")]
    #[inline]
    fn is_global(&self) -> bool {
        // check if this address is 192.0.0.9 or 192.0.0.10. These addresses are the only two
        // globally routable addresses in the 192.0.0.0/24 range.
        if u32::from_be_bytes(self.octets()) == 0xc0000009
            || u32::from_be_bytes(self.octets()) == 0xc000000a
        {
            return true;
        }
        !self.is_private()
            && !self.is_loopback()
            && !self.is_link_local()
            && !self.is_broadcast()
            && !self.is_documentation()
            && !self.is_multicast()
            // && !self.is_shared()
            // && !self.is_ietf_protocol_assignment()
            // && !self.is_reserved()
            // && !self.is_benchmarking()
            // Make sure the address is not in 0.0.0.0/8
            && self.octets()[0] != 0
    }
}

impl IpAddrExt for Ipv6Addr {
    // @TODO include other ranges, wait for is_global stable
    // #[rustc_const_unstable(feature = "const_ipv6", issue = "76205")]
    #[inline]
    fn is_global(&self) -> bool {
        let first = self.segments()[0];
        (0x2001..=0x3FFF).contains(&first)
        // match self.multicast_scope() {
        //     Some(Ipv6MulticastScope::Global) => true,
        //     None => self.is_unicast_global(),
        //     _ => false,
        // }
    }
}

impl Ipv6AddrExt for Ipv6Addr {
    // #[rustc_const_unstable(feature = "const_ipv6", issue = "76205")]
    #[inline]
    fn to_ipv4_mapped(&self) -> Option<Ipv4Addr> {
        match self.octets() {
            [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, a, b, c, d] => {
                Some(Ipv4Addr::new(a, b, c, d))
            }
            _ => None,
        }
    }
}

#[cfg(test)]
mod test {
    use indexmap::indexset;
    use test_data_file::test_data_file;

    use super::*;

    #[tokio::test]
    #[ignore]
    async fn test_retrieve_public_ip() {
        let result = retrieve_public_ip("127.0.0.1:0".parse().unwrap()).await;
        assert!(result.is_ok(), "{result:?}");
    }

    #[test]
    fn test_to_socket_addr() {
        let local_addr = "127.0.0.1:0".parse::<SocketAddr>().unwrap();
        to_socket_address(&indexset! {local_addr}, "google.com:0").unwrap();
        let s = to_socket_address(&indexset! {local_addr}, "1.1.1.1:0").unwrap();
        assert_eq!((local_addr, "1.1.1.1:0".parse::<SocketAddr>().unwrap()), s);

        let s = to_socket_address(&indexset! {local_addr}, "abc");
        assert!(matches!(s, Err(DnsError::Failed(_))));
    }

    #[test_data_file(path = "tests/samples/ipv6_is_global.list")]
    #[test]
    fn test_ipv6_is_global(ip: IpAddr, is_global: bool) {
        assert_eq!(IpAddrExt::is_global(&ip), is_global);
    }

    #[test_data_file(path = "tests/samples/split_into_messages.json")]
    #[test]
    fn test_split_into_messages(data: Vec<u8>, expected: Vec<Vec<u8>>) {
        let messages = split_into_messages(&data);
        assert_eq!(expected, messages);
    }
}
