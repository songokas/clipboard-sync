use std::net::SocketAddr;
use tokio::net::{ToSocketAddrs, UdpSocket};
use tokio::time::Duration;

use crate::errors::ConnectionError;
use crate::message::Group;
use crate::socket::{Protocol, SocketEndpoint};

mod basic;
#[cfg(feature = "frames")]
mod frames;
#[cfg(feature = "quiche")]
mod quiche;
#[cfg(feature = "quinn")]
mod quinn;

// use self::quinn::{obtain_client_endpoint, obtain_server_endpoint, send_data_quic, receive_data_quic};
#[cfg(feature = "quiche")]
use self::quiche::{receive_data_quic, send_data_quic};

pub async fn obtain_client_socket(
    local_address: &SocketAddr,
    remote_addr: impl ToSocketAddrs,
    protocol: &Protocol,
) -> Result<SocketEndpoint, ConnectionError>
{
    // debug!("Send to {} using {}", remote_addr, local_address);
    match protocol {
        #[cfg(feature = "quinn")]
        Protocol::Quic(_) => obtain_client_endpoint(local_address).await,
        _ => {
            let sock = UdpSocket::bind(local_address).await?;
            sock.connect(remote_addr).await?;
            return Ok(SocketEndpoint::Socket(sock));
        }
    }
}

pub async fn obtain_server_socket(
    local_address: &SocketAddr,
    protocol: &Protocol,
) -> Result<SocketEndpoint, ConnectionError>
{
    match protocol {
        #[cfg(feature = "quinn")]
        Protocol::Quic(_) => obtain_server_endpoint(local_address)
            .await
            .and_then(|i| Ok(SocketEndpoint::QuicServer(i)))
            .map_err(|err| ConnectionError::EndpointError(err)),
        _ => {
            let sock = UdpSocket::bind(local_address).await?;
            return Ok(SocketEndpoint::Socket(sock));
        }
    }
}

pub async fn send_data(
    endpoint: SocketEndpoint,
    data: Vec<u8>,
    addr: &SocketAddr,
    group: &Group,
) -> Result<usize, ConnectionError>
{
    return match &group.protocol {
        #[cfg(feature = "frames")]
        Protocol::Frames => {
            frames::send_data_frames(endpoint.socket_consume().unwrap(), data, addr, group).await
        }
        #[cfg(feature = "quinn")]
        Protocol::Quic(_) => {
            send_data_quic(endpoint.client_consume().unwrap(), data, addr, group).await
        }
        #[cfg(feature = "quiche")]
        Protocol::Quic(c) => {
            send_data_quic(
                endpoint.socket_consume().unwrap(),
                data,
                addr,
                group,
                c.verify_dir.clone(),
            )
            .await
        }
        Protocol::Basic => basic::send_data_basic(endpoint.socket_consume().unwrap(), data).await,
    };
}

pub async fn receive_data(
    endpoint: &mut SocketEndpoint,
    max_len: usize,
    groups: &[Group],
    protocol: &Protocol,
    timeout: impl Fn(Duration) -> bool,
) -> Result<(Vec<u8>, SocketAddr), ConnectionError>
{
    return match protocol {
        #[cfg(feature = "frames")]
        Protocol::Frames => {
            frames::receive_data_frames(endpoint.socket().unwrap(), max_len, groups, timeout).await
        }
        #[cfg(feature = "quinn")]
        Protocol::Quic(_) => receive_data_quic(endpoint.server().unwrap(), max_len, timeout).await,
        #[cfg(feature = "quiche")]
        Protocol::Quic(c) => {
            receive_data_quic(
                endpoint.socket().unwrap(),
                max_len,
                groups,
                &c.private_key,
                &c.public_key,
                timeout,
            )
            .await
        }
        Protocol::Basic => {
            basic::receive_data_basic(endpoint.socket().unwrap(), max_len, timeout).await
        }
    };
}
