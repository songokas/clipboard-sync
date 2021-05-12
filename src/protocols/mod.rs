use std::collections::HashMap;
use std::fmt;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::{TcpListener, TcpSocket, UdpSocket};
use tokio::sync::Mutex;
use tokio::time::Duration;

mod basic;
#[cfg(feature = "frames")]
mod frames;
#[path = "laminar.rs"]
mod laminarpr;
#[cfg(feature = "quiche")]
mod quiche;
#[cfg(feature = "quinn")]
#[path = "quinn.rs"]
mod quinnpr;
mod tcp;

// use crate::config::CertLoader;
#[cfg(feature = "quic")]
use crate::config::Certificates;
use crate::encryption::DataEncryptor;
use crate::errors::CliError;
use crate::errors::ConnectionError;
use crate::fragmenter::{FrameDataDecryptor, FrameDecryptor, FrameEncryptor, FrameIndexEncryptor};
use crate::socket::{get_matching_address, Destination};

#[cfg(feature = "quinn")]
use quinn::{Endpoint, Incoming};

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Protocol {
    Basic,
    #[cfg(feature = "frames")]
    Frames,
    #[cfg(feature = "quic")]
    Quic(Certificates),
    Laminar,
    Tcp,
}

impl Protocol {
    pub fn requires_public_key(&self) -> bool {
        #[cfg(feature = "quic")]
        if let Self::Quic(_) = self {
            return true;
        }
        return false;
    }

    #[allow(unused_variables)]
    pub fn from(
        protocol_opt: Option<&str>,
        #[cfg(feature = "quic")] certs_callback: impl Fn() -> Result<Certificates, CliError>,
    ) -> Result<Protocol, CliError> {
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

impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
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

#[derive(Clone)]
pub enum LocalSocket {
    Socket(Arc<UdpSocket>),
    Laminar(Arc<laminarpr::LaminarSocket>),
    Tcp(Arc<Mutex<TcpSocket>>),
    TcpListener(Arc<TcpListener>),
    #[cfg(feature = "quinn")]
    Quinn(Arc<(Endpoint, Mutex<Incoming>)>),
}

#[allow(irrefutable_let_patterns)]
impl LocalSocket {
    pub fn socket(&self) -> Option<Arc<UdpSocket>> {
        if let Self::Socket(s) = self {
            return Some(Arc::clone(&s));
        }
        return None;
    }

    pub fn tcp_listener(&self) -> Option<&TcpListener> {
        if let Self::TcpListener(s) = self {
            return Some(&s);
        }
        return None;
    }

    pub fn tcp_consume(self) -> Option<TcpSocket> {
        if let Self::Tcp(s) = self {
            return Some(Arc::try_unwrap(s).ok()?.into_inner());
        }
        return None;
    }

    pub fn laminar_sender(&self) -> Option<laminarpr::LaminarSender> {
        if let Self::Laminar(a) = self {
            return Some(a.get_sender());
        }
        return None;
    }

    pub fn laminar_receiver(&self) -> Option<laminarpr::LaminarReceiver> {
        if let Self::Laminar(a) = self {
            return Some(a.get_receiver());
        }
        return None;
    }

    #[cfg(feature = "quinn")]
    pub fn quinn_client(&self) -> Option<&Endpoint> {
        if let Self::Quinn((c, s)) = self {
            return Some(&c);
        }
        return None;
    }

    #[cfg(feature = "quinn")]
    pub fn quinn_server(&mut self) -> Option<&mut Incoming> {
        if let Self::Quinn((_, s)) = self {
            return Some(s.lock().await.get_mut());
        }
        return None;
    }
}

type LocalSocketPool = HashMap<SocketAddr, LocalSocket>;

pub struct SocketPool {
    pool: Mutex<LocalSocketPool>,
}

impl SocketPool {
    pub fn new() -> Self {
        return SocketPool {
            pool: Mutex::new(LocalSocketPool::new()),
        };
    }

    pub async fn obtain_client_socket(
        &self,
        local_addresses: &Vec<SocketAddr>,
        remote_address: &SocketAddr,
        protocol: &Protocol,
    ) -> Result<LocalSocket, ConnectionError> {
        let local_address =
            get_matching_address(local_addresses, remote_address).ok_or_else(|| {
                ConnectionError::FailedToConnect(format!(
                "Unable to find local address from {:?} that can connect to the remote address {}",
                local_addresses, remote_address
            ))
            })?;
        match self.pool.lock().await.get(local_address) {
            Some(s) => return Ok(s.clone()),
            _ => (),
        };
        match protocol {
            #[cfg(feature = "quinn")]
            Protocol::Quic(c) => {
                let (endpoint, incoming) =
                    quinnpr::obtain_client_endpoint(local_address, &c).await?;
                return Ok(LocalSocket::Quinn(Arc::new((
                    endpoint,
                    Mutex::new(incoming),
                ))));
            }
            Protocol::Laminar => {
                let socket = laminarpr::run_laminar(local_address)?;
                return Ok(LocalSocket::Laminar(Arc::new(socket)));
            }
            Protocol::Tcp => {
                let socket = tcp::obtain_client_socket(local_address.clone())?;
                return Ok(LocalSocket::Tcp(Arc::new(Mutex::new(socket))));
            }
            _ => {
                let socket = UdpSocket::bind(local_address).await?;
                if remote_address.ip().is_multicast() {
                    socket.set_multicast_loop_v4(false).unwrap_or(());
                    socket.set_multicast_loop_v6(false).unwrap_or(());
                }
                let socket_wrapped = Arc::new(socket);
                return Ok(LocalSocket::Socket(socket_wrapped));
            }
        }
    }

    pub async fn obtain_server_socket(
        &self,
        local_address: SocketAddr,
        protocol: &Protocol,
    ) -> Result<LocalSocket, ConnectionError> {
        match protocol {
            #[cfg(feature = "quinn")]
            Protocol::Quic(c) => {
                let socket = quinnpr::obtain_server_endpoint(&local_address, c).await?;
                let lsocket = LocalSocket::Quinn(socket);
                let rsocket = lsocket.clone();
                self.pool.lock().await.insert(local_address, lsocket);
                return Ok(rsocket);
            }
            Protocol::Laminar => {
                let socket = laminarpr::run_laminar(&local_address)?;
                let lsocket = LocalSocket::Laminar(Arc::new(socket));
                let rsocket = lsocket.clone();
                self.pool.lock().await.insert(local_address, lsocket);
                return Ok(rsocket);
            }
            Protocol::Tcp => {
                let listener = tcp::obtain_server_socket(local_address)?;
                return Ok(LocalSocket::TcpListener(Arc::new(listener)));
            }
            _ => {
                let socket = UdpSocket::bind(&local_address).await?;
                let socket_wrapped = Arc::new(socket);
                let socket_return = Arc::clone(&socket_wrapped);
                let lsocket = LocalSocket::Socket(socket_wrapped);
                self.pool.lock().await.insert(local_address, lsocket);
                return Ok(LocalSocket::Socket(socket_return));
            }
        }
    }

    // pub async fn release_socket(&self, local_address: &SocketAddr) -> bool {
    //     if self.udp_pool.lock().await.contains_key(local_address) {
    //         return self.udp_pool.lock().await.remove(local_address).is_some();
    //     } else if self.laminar_pool.lock().await.contains_key(local_address) {
    //         self.laminar_pool
    //             .lock()
    //             .await
    //             .remove(local_address)
    //             .map(|_| true)
    //             .unwrap_or(false);
    //     }
    //     return false;
    // }

    // async fn get_laminar_socket(
    //     &self,
    //     local_address: &SocketAddr,
    // ) -> Result<Arc<laminarpr::LaminarSocket>, ConnectionError> {
    //     {
    //         let hash = self.laminar_pool.lock().await;
    //         if let Some(sock) = hash.get(local_address) {
    //             return Ok(Arc::clone(sock));
    //         }
    //     }

    //     let sock = Arc::new(laminarpr::run_laminar(local_address)?);
    //     let ret = Arc::clone(&sock);
    //     self.laminar_pool
    //         .lock()
    //         .await
    //         .insert(local_address.clone(), sock);
    //     return Ok(ret);
    // }

    // async fn get_socket(
    //     &self,
    //     local_address: &SocketAddr,
    // ) -> Result<LocalSocket, ConnectionError> {
    //     let hash = self.pool.lock().await;
    //     if let Some(sock) = hash.get(local_address) {
    //         return Ok(sock);
    //     }

    // let socket = UdpSocket::bind(local_address).await?;
    // let sock = Arc::new(socket);
    // let ret = Arc::clone(&sock);
    // self.udp_pool
    //     .lock()
    //     .await
    //     .insert(local_address.clone(), sock);
    // return Ok(ret);
    // }
}

pub async fn send_data(
    local_socket: LocalSocket,
    encryptor: impl FrameEncryptor
        + FrameDataDecryptor
        + FrameIndexEncryptor
        + Send
        + Sync
        + Clone
        + 'static,
    protocol: &Protocol,
    destination: Destination,
    data: Vec<u8>,
    timeout: impl Fn(Duration) -> bool + std::marker::Send + std::marker::Sync + 'static,
) -> Result<usize, ConnectionError> {
    return match protocol {
        #[cfg(feature = "frames")]
        Protocol::Frames => {
            frames::send_data(
                local_socket
                    .socket()
                    .ok_or(ConnectionError::InvalidProtocol(
                        "Frames protocol socket expected".to_owned(),
                    ))?,
                encryptor,
                data,
                destination.into(),
                timeout,
            )
            .await
        }
        #[cfg(feature = "quinn")]
        Protocol::Quic(_) => {
            quinnpr::send_data(
                local_socket
                    .quinn_client()
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
            quiche::send_data(
                local_socket
                    .socket()
                    .ok_or(ConnectionError::InvalidProtocol(
                        "Quic protocol socket expected".to_owned(),
                    ))?,
                encryptor,
                data,
                destination,
                c.verify_dir.clone(),
                timeout,
            )
            .await
        }
        Protocol::Basic => {
            basic::send_data(
                local_socket
                    .socket()
                    .ok_or(ConnectionError::InvalidProtocol(
                        "Basic protocol socket expected".to_owned(),
                    ))?,
                data,
                &destination.into(),
                timeout,
            )
            .await
        }
        Protocol::Laminar => {
            let socket = local_socket
                .laminar_sender()
                .ok_or(ConnectionError::InvalidProtocol(
                    "Laminar protocol socket expected".to_owned(),
                ))?;
            laminarpr::send_data(&socket, encryptor, data, &destination.into()).await
        }
        Protocol::Tcp => {
            let socket = local_socket
                .tcp_consume()
                .ok_or(ConnectionError::InvalidProtocol(
                    "Basic protocol socket expected".to_owned(),
                ))?;
            tcp::send_data(socket, data, &destination.into()).await
        }
    };
}

pub async fn receive_data(
    local_socket: &mut LocalSocket,
    encryptor: &(impl FrameDecryptor + DataEncryptor),
    protocol: &Protocol,
    max_len: usize,
    timeout: impl Fn(Duration) -> bool,
) -> Result<(Vec<u8>, SocketAddr), ConnectionError> {
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
            quinnpr::receive_data(
                local_socket
                    .server()
                    .ok_or(ConnectionError::InvalidProtocol(
                        "Quic protocol server expected".to_owned(),
                    ))?,
                max_len,
                timeout,
            )
            .await
        }
        #[cfg(feature = "quiche")]
        Protocol::Quic(c) => {
            quiche::receive_data(
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
            let socket =
                local_socket
                    .laminar_receiver()
                    .ok_or(ConnectionError::InvalidProtocol(
                        "Basic protocol socket expected".to_owned(),
                    ))?;
            laminarpr::receive_data(&socket, encryptor, max_len, timeout).await
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
