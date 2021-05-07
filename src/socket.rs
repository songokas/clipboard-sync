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

#[cached(
    create = "{ TimedSizedCache::with_size_and_lifespan(1000, 3600) }",
    type = "TimedSizedCache<String, Result<SocketAddr, DnsError>>",
    convert = r#"{ format!("{}", host.as_ref()) }"#
)]
pub async fn to_socket(host: impl AsRef<str>) -> Result<SocketAddr, DnsError> {
    let to_err = |e| {
        DnsError::Failed(format!(
            "Unable to retrieve ip for {}. Message: {}",
            host.as_ref(),
            e
        ))
    };
    for addr in lookup_host(host.as_ref()).await.map_err(to_err)? {
        return Ok(addr);
    }
    return Err(DnsError::Failed(format!(
        "Unable to retrieve ip for {}",
        host.as_ref()
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

// #[cached(
//     create = "{ TimedSizedCache::with_size_and_lifespan(100, 600) }",
//     type = "TimedSizedCache<String, Result<SocketAddr, ConnectionError>>",
//     convert = r#"{ format!("{}{}", local_address.ip().to_string(), remote_address.ip().to_string()) }"#
// )]
pub async fn retrieve_local_address(
    local_address: &SocketAddr,
    remote_address: &SocketAddr,
) -> Result<SocketAddr, ConnectionError> {
    let socket = obtain_socket(local_address, remote_address).await?;
    let sock_addr = socket.local_addr()?;
    return Ok(sock_addr);
}

#[cfg(feature = " public-ip")]
#[cached(size = 1, time = 60)]
pub async fn retrieve_public_ip() -> Result<IpAddr, DnsError> {
    return public_ip::addr()
        .await
        .ok_or(DnsError::Failed("Failed to retrieve public ip".to_owned()));
}

pub async fn obtain_socket(
    local_address: &SocketAddr,
    remote_address: &SocketAddr,
) -> Result<UdpSocket, ConnectionError> {
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
