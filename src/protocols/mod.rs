use laminar::{Config, Socket};
use std::fmt;
use std::net::IpAddr;
use std::net::SocketAddr;
use tokio::net::{TcpListener, TcpSocket, UdpSocket};

use crate::config::CertLoader;
use crate::encryption::DataEncryptor;
use crate::errors::CliError;
use crate::errors::ConnectionError;
use crate::fragmenter::{FragmentEncryptor, FrameDecryptor};
use crate::socket::Timeout;

#[cfg(feature = "quinn")]
use quinn::{Endpoint, Incoming};

mod basic;
#[cfg(feature = "frames")]
mod frames;
#[path = "laminar.rs"]
mod laminarpr;
#[cfg(feature = "quiche")]
mod quiche;
#[cfg(feature = "quinn")]
mod quinn;
mod tcp;

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Protocol
{
    Basic,
    #[cfg(feature = "frames")]
    Frames,
    #[cfg(feature = "quic")]
    Quic(Certificates),
    Laminar,
    Tcp,
}

impl Protocol
{
    pub fn requires_public_key(&self) -> bool
    {
        #[cfg(feature = "quic")]
        if let Self::Quic(_) = self {
            return true;
        }
        return false;
    }

    #[allow(unused_variables)]
    pub fn from(
        protocol_opt: Option<&str>,
        certs_callback: impl CertLoader,
    ) -> Result<Protocol, CliError>
    {
        let protocol = match protocol_opt {
            #[cfg(feature = "quic")]
            Some(v) if v == "quic" => {
                let c = certs_callback()?;
                Protocol::Quic(c.clone())
            }
            #[cfg(feature = "frames")]
            Some(v) if v == "frames" => Protocol::Frames,
            Some(v) if v == "basic" => Protocol::Basic,
            Some(v) if v == "laminar" => Protocol::Laminar,
            Some(v) if v == "tcp" => Protocol::Tcp,
            Some(v) => {
                return Err(CliError::ArgumentError(format!(
                    "Protocol {} is not available",
                    v
                )));
            }
            None => Protocol::Basic,
        };
        return Ok(protocol);
    }
}

impl fmt::Display for Protocol
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result
    {
        return match self {
            #[cfg(feature = "quic")]
            Self::Quic(_) => write!(f, "quic"),
            #[cfg(feature = "frames")]
            Self::Frames => write!(f, "frames"),
            Self::Basic => write!(f, "basic"),
            Self::Laminar => write!(f, "laminar"),
            Self::Tcp => write!(f, "tcp"),
        };
    }
}

pub enum LocalSocket
{
    Socket(UdpSocket),
    Laminar((Socket, Config)),
    Tcp(TcpSocket),
    TcpListener(TcpListener),
    #[cfg(feature = "quinn")]
    QuicClient(Endpoint),
    #[cfg(feature = "quinn")]
    QuicServer(Incoming),
}

#[allow(irrefutable_let_patterns)]
impl LocalSocket
{
    pub fn socket(&self) -> Option<&UdpSocket>
    {
        if let Self::Socket(s) = self {
            return Some(s);
        }
        return None;
    }

    pub fn socket_consume(self) -> Option<UdpSocket>
    {
        if let Self::Socket(s) = self {
            return Some(s);
        }
        return None;
    }

    pub fn tcp_listener(&self) -> Option<&TcpListener>
    {
        if let Self::TcpListener(s) = self {
            return Some(s);
        }
        return None;
    }

    pub fn tcp_consume(self) -> Option<TcpSocket>
    {
        if let Self::Tcp(s) = self {
            return Some(s);
        }
        return None;
    }

    pub fn laminar(&mut self) -> Option<(&mut Socket, &mut Config)>
    {
        if let Self::Laminar((s, c)) = self {
            return Some((s, c));
        }
        return None;
    }

    pub fn laminar_consume(self) -> Option<(Socket, Config)>
    {
        if let Self::Laminar((s, c)) = self {
            return Some((s, c));
        }
        return None;
    }

    pub fn ip(&self) -> Option<IpAddr>
    {
        return match self {
            Self::Socket(s) => s.local_addr().map(|s| s.ip().clone()).ok(),
            Self::Laminar((s, c)) => s.local_addr().map(|s| s.ip().clone()).ok(),
            _ => None,
        };
    }

    #[cfg(feature = "quinn")]
    pub fn client_consume(self) -> Option<Endpoint>
    {
        if let Self::QuicClient(s) = self {
            return Some(s);
        }
        return None;
    }

    #[cfg(feature = "quinn")]
    pub fn server(&mut self) -> Option<&mut Incoming>
    {
        if let Self::QuicServer(s) = self {
            return Some(s);
        }
        return None;
    }
}

// use self::quinn::{obtain_client_endpoint, obtain_server_endpoint, send_data_quic, receive_data_quic};
#[cfg(feature = "quiche")]
use self::quiche::{receive_data_quic, send_data_quic};

pub async fn obtain_client_socket(
    local_address: &SocketAddr,
    remote_addr: &SocketAddr,
    protocol: &Protocol,
) -> Result<LocalSocket, ConnectionError>
{
    // debug!("Send to {} using {}", remote_addr, local_address);
    match protocol {
        #[cfg(feature = "quinn")]
        Protocol::Quic(_) => quin::obtain_socket(local_address).await,
        Protocol::Laminar => {
            let sock = laminarpr::obtain_socket(local_address)?;
            return Ok(LocalSocket::Laminar(sock));
        }
        Protocol::Tcp => {
            let socket = tcp::obtain_client_socket(local_address.clone())?;
            return Ok(LocalSocket::Tcp(socket));
        }
        _ => {
            let sock = basic::obtain_socket(local_address, remote_addr).await?;
            return Ok(LocalSocket::Socket(sock));
        }
    }
}

pub async fn obtain_server_socket(
    local_address: &SocketAddr,
    protocol: &Protocol,
) -> Result<LocalSocket, ConnectionError>
{
    match protocol {
        #[cfg(feature = "quinn")]
        Protocol::Quic(_) => obtain_server_endpoint(local_address)
            .await
            .and_then(|i| Ok(SocketEndpoint::QuicServer(i)))
            .map_err(|err| ConnectionError::EndpointError(err)),
        Protocol::Laminar => {
            let s = laminarpr::obtain_socket(local_address)?;
            return Ok(LocalSocket::Laminar(s));
        }
        Protocol::Tcp => {
            let listener = tcp::obtain_server_socket(local_address.clone())?;
            return Ok(LocalSocket::TcpListener(listener));
        }
        _ => {
            let sock = UdpSocket::bind(local_address).await?;
            return Ok(LocalSocket::Socket(sock));
        }
    }
}

pub async fn send_data(
    local_socket: LocalSocket,
    encryptor: impl FragmentEncryptor,
    protocol: &Protocol,
    destination: SocketAddr,
    data: Vec<u8>,
) -> Result<usize, ConnectionError>
{
    return match protocol {
        #[cfg(feature = "frames")]
        Protocol::Frames => {
            frames::send_data(
                local_socket
                    .socket_consume()
                    .ok_or(ConnectionError::InvalidProtocol(
                        "Frames protocol socket expected".to_owned(),
                    ))?,
                encryptor,
                data,
                &destination,
            )
            .await
        }
        #[cfg(feature = "quinn")]
        Protocol::Quic(_) => {
            send_data_quic(
                local_socket
                    .client_consume()
                    .ok_or(ConnectionError::InvalidProtocol(
                        "Quic protocol client expected".to_owned(),
                    ))?,
                data,
                destination,
            )
            .await
        }
        #[cfg(feature = "quiche")]
        Protocol::Quic(c) => {
            send_data_quic(
                local_socket
                    .socket_consume()
                    .ok_or(ConnectionError::InvalidProtocol(
                        "Quic protocol socket expected".to_owned(),
                    ))?,
                encryptor,
                data,
                destination,
                group,
                c.verify_dir.clone(),
            )
            .await
        }
        Protocol::Basic => {
            basic::send_data(
                local_socket
                    .socket_consume()
                    .ok_or(ConnectionError::InvalidProtocol(
                        "Basic protocol socket expected".to_owned(),
                    ))?,
                data,
                &destination,
            )
            .await
        }
        Protocol::Laminar => {
            let (socket, config) =
                local_socket
                    .laminar_consume()
                    .ok_or(ConnectionError::InvalidProtocol(
                        "Laminar protocol socket expected".to_owned(),
                    ))?;
            laminarpr::send_data(socket, &config, encryptor, data, &destination).await
        }
        Protocol::Tcp => {
            let socket = local_socket
                .tcp_consume()
                .ok_or(ConnectionError::InvalidProtocol(
                    "Basic protocol socket expected".to_owned(),
                ))?;
            tcp::send_data(socket, data, &destination).await
        }
    };
}

pub async fn receive_data(
    local_socket: &mut LocalSocket,
    encryptor: &(impl FrameDecryptor + DataEncryptor),
    protocol: &Protocol,
    max_len: usize,
    timeout: impl Timeout,
) -> Result<(Vec<u8>, SocketAddr), ConnectionError>
{
    return match protocol {
        #[cfg(feature = "frames")]
        Protocol::Frames => {
            frames::receive_data(
                local_socket
                    .socket()
                    .ok_or(ConnectionError::InvalidProtocol(
                        "Frames protocol socket expected".to_owned(),
                    ))?,
                encryptor,
                max_len,
                timeout,
            )
            .await
        }
        #[cfg(feature = "quinn")]
        Protocol::Quic(_) => {
            receive_data_quic(
                local_socket
                    .server()
                    .ok_or(ConnectionError::InvalidProtocol(
                        "Quic protocol server expected".to_owned(),
                    ))?,
                encryptor,
                max_len,
                timeout,
            )
            .await
        }
        #[cfg(feature = "quiche")]
        Protocol::Quic(c) => {
            receive_data_quic(
                local_socket
                    .socket()
                    .ok_or(ConnectionError::InvalidProtocol(
                        "Quic protocol socket expected".to_owned(),
                    ))?,
                encryptor,
                &c.private_key,
                &c.public_key,
                max_len,
                timeout,
            )
            .await
        }
        Protocol::Basic => {
            basic::receive_data(
                local_socket
                    .socket()
                    .ok_or(ConnectionError::InvalidProtocol(
                        "Basic protocol socket expected".to_owned(),
                    ))?,
                max_len,
                timeout,
            )
            .await
        }
        Protocol::Laminar => {
            let (s, c) = local_socket
                .laminar()
                .ok_or(ConnectionError::InvalidProtocol(
                    "Basic protocol socket expected".to_owned(),
                ))?;
            laminarpr::receive_data(s, encryptor, max_len, timeout).await
        }
        Protocol::Tcp => {
            tcp::receive_data(
                local_socket
                    .tcp_listener()
                    .ok_or(ConnectionError::InvalidProtocol(
                        "Tcp protocol socket expected".to_owned(),
                    ))?,
                max_len,
                timeout,
            )
            .await
        }
    };
}
