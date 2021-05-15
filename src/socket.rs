use cached::proc_macro::cached;
use cached::TimedSizedCache;

use log::debug;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Instant;
use tokio::net::lookup_host;
use tokio::net::UdpSocket;
use tokio::time::{timeout, Duration};

use crate::errors::{ConnectionError, DnsError};

//@TODO experimental
// pub trait Timeout = Fn(Duration) -> bool;

pub struct Destination {
    host: String,
    addr: SocketAddr,
}

impl Destination {
    pub fn new(host: String, addr: SocketAddr) -> Self {
        return Self { host, addr };
    }

    pub fn host(&self) -> &str {
        return &self.host;
    }

    pub fn addr(&self) -> &SocketAddr {
        return &self.addr;
    }
}

impl Into<SocketAddr> for Destination {
    fn into(self) -> SocketAddr {
        return self.addr().clone();
    }
}

impl From<SocketAddr> for Destination {
    fn from(item: SocketAddr) -> Self {
        return Self::new(item.ip().to_string(), item.clone());
    }
}

impl std::fmt::Display for Destination {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "host: {} destination: {}", self.host(), self.addr())
    }
}

#[cached(
    create = "{ TimedSizedCache::with_size_and_lifespan(1000, 3600) }",
    type = "TimedSizedCache<String, SocketAddr>",
    convert = r#"{ format!("{}", socket_addr.as_ref()) }"#,
    result = true
)]
pub async fn to_socket(socket_addr: impl AsRef<str>) -> Result<SocketAddr, DnsError> {
    let to_err = |e| {
        DnsError::Failed(format!(
            "Unable to retrieve ip for {}. Message: {}",
            socket_addr.as_ref(),
            e
        ))
    };
    for addr in lookup_host(socket_addr.as_ref()).await.map_err(to_err)? {
        debug!("Retrieved socket {} for dns {}", addr, socket_addr.as_ref());
        return Ok(addr);
    }
    return Err(DnsError::Failed(format!(
        "Unable to retrieve ip for {}",
        socket_addr.as_ref()
    )));
}

pub async fn receive_from_timeout(
    socket: &UdpSocket,
    buf: &mut [u8],
    timeout_callback: impl Fn(Duration) -> bool,
) -> io::Result<(usize, SocketAddr)> {
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

#[cached(
    create = "{ TimedSizedCache::with_size_and_lifespan(100, 600) }",
    type = "TimedSizedCache<String, SocketAddr>",
    convert = r#"{ format!("{}", remote_address.ip().to_string()) }"#,
    result = true
)]
pub async fn retrieve_local_address(
    local_addresses: &Vec<SocketAddr>,
    remote_address: &SocketAddr,
) -> Result<SocketAddr, ConnectionError> {
    let socket = obtain_socket(local_addresses, remote_address).await?;
    let sock_addr = socket.local_addr()?;
    return Ok(sock_addr);
}

#[cfg(feature = "public-ip")]
#[cached(size = 1, time = 600)]
pub async fn retrieve_public_ip() -> Result<IpAddr, DnsError> {
    let result = public_ip::addr()
        .await
        .ok_or(DnsError::Failed("Failed to retrieve public ip".to_owned()));
    if let Ok(ip) = result {
        debug!("Retrieved public ip {}", ip);
    }
    return result;
}

pub fn get_matching_address<'a>(
    local_addresses: &'a Vec<SocketAddr>,
    remote_address: &SocketAddr,
) -> Option<&'a SocketAddr> {
    for local_address in local_addresses.iter() {
        if local_address.is_ipv4() == remote_address.is_ipv4()
            || local_address.is_ipv6() == remote_address.is_ipv6()
        {
            return Some(local_address);
        }
    }
    return None;
}

#[cached(size = 1, time = 1000000)]
pub fn has_ipv6_support() -> bool {
    std::net::UdpSocket::bind("[::]:0").is_ok()
}

pub async fn obtain_socket(
    local_addresses: &Vec<SocketAddr>,
    remote_address: &SocketAddr,
) -> Result<UdpSocket, ConnectionError> {
    let local_address = get_matching_address(local_addresses, remote_address).ok_or_else(|| {
        ConnectionError::FailedToConnect(format!(
            "Unable to find local address from {:?} that can connect to the remote address {}",
            local_addresses, remote_address
        ))
    })?;
    let sock = UdpSocket::bind(local_address).await.map_err(|e| {
        ConnectionError::FailedToConnect(format!(
            "Unable to bind local address {} {}",
            local_address, e
        ))
    })?;
    sock.connect(remote_address).await.map_err(|e| {
        ConnectionError::FailedToConnect(format!(
            "Unable to connect local address {} to remote address {} {}",
            local_address, remote_address, e
        ))
    })?;
    return Ok(sock);
}

pub fn remove_ipv4_mapping(addr: &SocketAddr) -> SocketAddr {
    let use_addr: SocketAddr = match addr {
        SocketAddr::V6(a) => Ipv6AddrExt::to_ipv4_mapped(a.ip())
            .map(|ip| SocketAddr::new(IpAddr::V4(ip), a.port()))
            .unwrap_or(SocketAddr::V6(a.clone())),
        _ => addr.clone(),
    };
    return use_addr;
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
        return first >= 0x2001 && first <= 0x3FFF;
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
mod sockettest {
    use super::*;
    use crate::assert_error_type;
    use crate::wait;

    #[cfg(feature = "public-ip")]
    #[test]
    fn test_retrieve_public_ip() {
        assert!(wait!(retrieve_public_ip()).is_ok());
    }

    #[test]
    fn test_retrieve_local_address() {
        let l = "127.0.0.1:0".parse().unwrap();
        let r = "127.0.0.1:0".parse().unwrap();
        assert!(wait!(retrieve_local_address(&vec![l], &r)).is_ok());
    }

    #[test]
    fn test_to_socket() {
        wait!(to_socket("google.com:0")).unwrap();
        let s = wait!(to_socket("1.1.1.1:0")).unwrap();
        assert_eq!("1.1.1.1:0".parse::<SocketAddr>().unwrap(), s);

        let s = wait!(to_socket("abc"));
        assert_error_type!(s, DnsError::Failed(_));
    }

    #[test]
    fn test_ipv6_is_global() {
        let ip: IpAddr = "2606:4700:4700::1111".parse().unwrap();
        assert!(IpAddrExt::is_global(&ip));
        let ip: IpAddr = "2a00:1450:401b:800::200e".parse().unwrap();
        assert!(IpAddrExt::is_global(&ip));

        let ip: IpAddr = "fd6d:8d64:af0c::1".parse().unwrap();
        assert!(!IpAddrExt::is_global(&ip));
        let ip: IpAddr = "fe80::1".parse().unwrap();
        assert!(!IpAddrExt::is_global(&ip));
    }
}
