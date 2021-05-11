use cached::proc_macro::cached;
use cached::TimedSizedCache;

use std::io;
use std::net::SocketAddr;
use std::time::Instant;
use tokio::net::lookup_host;
use tokio::net::UdpSocket;
use tokio::time::{timeout, Duration};

use crate::errors::{ConnectionError, DnsError};

//@TODO experimental
// pub trait Timeout = Fn(Duration) -> bool;

pub struct Destination
{
    host: String,
    addr: SocketAddr,
}

impl Destination
{
    pub fn new(host: String, addr: SocketAddr) -> Self
    {
        return Self { host, addr };
    }

    pub fn host(&self) -> &str
    {
        return &self.host;
    }

    pub fn addr(&self) -> &SocketAddr
    {
        return &self.addr;
    }
}

impl Into<SocketAddr> for Destination
{
    fn into(self) -> SocketAddr
    {
        return self.addr().clone();
    }
}

impl From<SocketAddr> for Destination
{
    fn from(item: SocketAddr) -> Self
    {
        return Self::new(item.ip().to_string(), item.clone());
    }
}

impl std::fmt::Display for Destination
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result
    {
        write!(f, "host: {} destination: {}", self.host(), self.addr())
    }
}

#[cached(
    create = "{ TimedSizedCache::with_size_and_lifespan(1000, 3600) }",
    type = "TimedSizedCache<String, SocketAddr>",
    convert = r#"{ format!("{}", socket_addr.as_ref()) }"#,
    result = true
)]
pub async fn to_socket(socket_addr: impl AsRef<str>) -> Result<SocketAddr, DnsError>
{
    let to_err = |e| {
        DnsError::Failed(format!(
            "Unable to retrieve ip for {}. Message: {}",
            socket_addr.as_ref(),
            e
        ))
    };
    for addr in lookup_host(socket_addr.as_ref()).await.map_err(to_err)? {
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

#[cached(
    create = "{ TimedSizedCache::with_size_and_lifespan(100, 600) }",
    type = "TimedSizedCache<String, SocketAddr>",
    convert = r#"{ format!("{}", remote_address.ip().to_string()) }"#,
    result = true
)]
pub async fn retrieve_local_address(
    local_addresses: &Vec<SocketAddr>,
    remote_address: &SocketAddr,
) -> Result<SocketAddr, ConnectionError>
{
    let socket = obtain_socket(local_addresses, remote_address).await?;
    let sock_addr = socket.local_addr()?;
    return Ok(sock_addr);
}

#[cfg(feature = " public-ip")]
#[cached(size = 1, time = 600)]
pub async fn retrieve_public_ip() -> Result<IpAddr, DnsError>
{
    return public_ip::addr()
        .await
        .ok_or(DnsError::Failed("Failed to retrieve public ip".to_owned()));
}

pub fn get_matching_address<'a>(
    local_addresses: &'a Vec<SocketAddr>,
    remote_address: &SocketAddr,
) -> Option<&'a SocketAddr>
{
    for local_address in local_addresses.iter() {
        if local_address.is_ipv4() == remote_address.is_ipv4()
            || local_address.is_ipv6() == remote_address.is_ipv6()
        {
            return Some(local_address);
        }
    }
    return None;
}

pub async fn obtain_socket(
    local_addresses: &Vec<SocketAddr>,
    remote_address: &SocketAddr,
) -> Result<UdpSocket, ConnectionError>
{
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

#[cfg(test)]
mod sockettest
{
    use super::*;
    use crate::assert_error_type;
    use crate::wait;

    #[cfg(feature = " public-ip")]
    #[test]
    fn test_retrieve_public_ip()
    {
        assert!(wait!(retrieve_public_ip()).is_ok());
    }

    #[test]
    fn test_retrieve_local_address()
    {
        let l = "127.0.0.1:0".parse().unwrap();
        let r = "127.0.0.1:0".parse().unwrap();
        assert!(wait!(retrieve_local_address(&l, &r)).is_ok());
    }

    #[test]
    fn test_to_socket()
    {
        wait!(to_socket("google.com:0")).unwrap();
        let s = wait!(to_socket("1.1.1.1:0")).unwrap();
        assert_eq!("1.1.1.1:0".parse::<SocketAddr>().unwrap(), s);

        let s = wait!(to_socket("abc"));
        assert_error_type!(s, DnsError::Failed(_));
    }
}
