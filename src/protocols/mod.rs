use quinn::{Endpoint, Incoming};
use tokio::net::{UdpSocket, ToSocketAddrs};
use std::net::{SocketAddr};

mod quic;
mod basic;
mod frames;

pub enum SocketEndpoint
{
    #[cfg(feature = "basic")]
    #[cfg(feature = "frames")]
    Socket(UdpSocket),
    #[cfg(feature = "quic")]
    QuicClient(Endpoint),
    #[cfg(feature = "quic")]
    QuickServer(Incoming)
}

pub enum Protocol
{
    Basic,
    Frames,
    Quic,
}

impl Protocol
{
    pub fn requires_public_key(&self) -> bool
    {
        return if let Self::Quic = self { true } else { false };
    }
}

pub async fn obtain_client_socket(
    local_address: &SocketAddr,
    remote_addr: impl ToSocketAddrs,
    protocol: Protocol
) -> Result<SocketEndpoint, ConnectionError>
{
    // debug!("Send to {} using {}", remote_addr, local_address);
    match protocol {
        #[cfg(feature = "quic")]
        Quick => obtain_client_endpoint(local_address),
        _ => {
            let sock = UdpSocket::bind(local_address).await?;
            sock.connect(remote_addr).await?;
            return Ok(SocketEndpoint::Socket(sock));
        }
    }
}

pub fn obtain_server_socket(
    local_address: &SocketAddr,
    protocol: Protocol,
    config: &FullConfig,

) -> Result<SocketEndpoint, ConnectionError>
{
    match protocol {
        #[cfg(feature = "quic")]
        Quick => obtain_server_endpoint(local_address, config.get_private_key(), config.get_public_key()),
        _ => {
            let sock = UdpSocket::bind(local_address).await?;
            return Ok(SocketEndpoint(sock));
        }
    }
    let sock = 

}

pub async fn send_data(
    socket: UdpSocket,
    data: Vec<u8>,
    addr: &SocketAddr,
    group: &Group,
    protocol: Protocol,
) -> Result<usize, ConnectionError>
{
    return match protocol {
        #[cfg(feature = "frames")]
        "frames" => send_data_frames(socket, data, addr, group).await,
        #[cfg(feature = "quic")]
        "quic" => send_data_quic(socket, data, addr).await,
        #[cfg(feature = "basic")]
        "basic" => send_data_basic(socket, data).await,
        _ => Err(ConnectionError::InvalidProtocol(protocol.to_owned())),
    };
}

pub async fn receive_data(
    socket: &SocketEndpoint,
    max_len: usize,
    groups: &[Group],
    protocol: Protocol,
) -> Result<(Vec<u8>, SocketAddr), ConnectionError>
{
    return match protocol {
        #[cfg(feature = "frames")]
        Protocol::Frames => receive_data_frames(socket.socket(), max_len, groups).await,
        #[cfg(feature = "quic")]
        Protocol::Quic => receive_data_quic(socket.server(), max_len).await,
        #[cfg(feature = "basic")]
        Protocol::Basic => receive_data_basic(socket, max_len).await,
        _ => Err(ConnectionError::InvalidProtocol(protocol.to_owned())),
    };
}