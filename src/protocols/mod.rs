use indexmap::IndexSet;
use std::collections::HashMap;
use std::fmt;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio::net::{TcpListener, TcpSocket, UdpSocket};
use tokio::sync::Mutex;
use tokio::time::Duration;

mod basic;
#[cfg(feature = "frames")]
mod frames;
#[path = "laminar.rs"]
pub mod laminarpr;
#[cfg(feature = "quiche")]
mod quiche;
#[cfg(feature = "quinn")]
#[path = "quinn.rs"]
mod quinnpr;
pub mod tcp;

// use crate::config::CertLoader;
#[cfg(feature = "quic")]
use crate::config::Certificates;
use crate::encryption::DataEncryptor;
use crate::errors::CliError;
use crate::errors::ConnectionError;
use crate::errors::LimitError;
use crate::fragmenter::RelayEncryptor;
use crate::fragmenter::{FrameDataDecryptor, FrameDecryptor, FrameEncryptor, FrameIndexEncryptor};
use crate::identity::IdentityVerifier;
use crate::socket::{get_matching_address, Destination};
use crate::stream::{send_stream, StreamPool};

#[cfg(feature = "quinn")]
use quinn::{Endpoint, Incoming};

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
        false
    }

    #[allow(unused_variables)]
    pub fn from(
        protocol_opt: Option<&str>,
        #[cfg(feature = "quic")] certs_callback: impl Fn() -> Result<Certificates, CliError>,
    ) -> Result<Protocol, CliError>
    {
        let protocol = match protocol_opt {
            #[cfg(feature = "quic")]
            Some(v) if v == "quic" => {
                let c = certs_callback()?;
                Protocol::Quic(c)
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
        Ok(protocol)
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
    Socket(Arc<UdpSocket>),
    Laminar(laminarpr::LaminarSocket),
    Tcp(Mutex<TcpSocket>),
    Stream(Arc<TcpStream>),
    TcpListener((TcpListener, Arc<StreamPool>)),
    #[cfg(feature = "quinn")]
    Quinn((Endpoint, Arc<Mutex<Incoming>>)),
}

#[allow(irrefutable_let_patterns)]
impl LocalSocket
{
    pub fn socket(&self) -> Option<Arc<UdpSocket>>
    {
        if let Self::Socket(s) = self {
            return Some(Arc::clone(s));
        }
        None
    }

    pub fn tcp_listener(&self) -> Option<(&TcpListener, Arc<StreamPool>)>
    {
        if let Self::TcpListener((s, p)) = self {
            return Some((s, p.clone()));
        }
        None
    }

    pub fn tcp_consume(self) -> Option<TcpSocket>
    {
        if let Self::Tcp(s) = self {
            return Some(s.into_inner());
        }
        None
    }

    pub fn stream(&self) -> Option<Arc<TcpStream>>
    {
        if let Self::Stream(s) = self {
            return Some(Arc::clone(s));
        }
        None
    }

    pub fn laminar_sender(&self) -> Option<laminarpr::LaminarSender>
    {
        if let Self::Laminar(a) = self {
            return Some(a.get_sender());
        }
        None
    }

    pub fn laminar_receiver(&self) -> Option<laminarpr::LaminarReceiver>
    {
        if let Self::Laminar(a) = self {
            return Some(a.get_receiver());
        }
        None
    }

    #[cfg(feature = "quinn")]
    pub fn quinn_client(&self) -> Option<&Endpoint>
    {
        if let Self::Quinn((c, _)) = self {
            return Some(c);
        }
        None
    }

    #[cfg(feature = "quinn")]
    pub fn quinn_server(&self) -> Option<Arc<Mutex<Incoming>>>
    {
        if let Self::Quinn((_, s)) = self {
            return Some(s.clone());
        }
        None
    }
}

type LocalSocketPool = HashMap<SocketAddr, Arc<LocalSocket>>;

pub struct SocketPool
{
    local_pool: Mutex<LocalSocketPool>,
    stream_pool: Arc<StreamPool>,
}

impl SocketPool
{
    pub fn default() -> Self
    {
        SocketPool {
            local_pool: Mutex::new(LocalSocketPool::default()),
            stream_pool: Arc::new(StreamPool::default()),
        }
    }

    pub async fn obtain_client_socket(
        &self,
        local_addresses: &IndexSet<SocketAddr>,
        remote_address: &SocketAddr,
        protocol: &Protocol,
        using_heartbeat: bool,
    ) -> Result<Arc<LocalSocket>, ConnectionError>
    {
        let local_address = || {
            get_matching_address(local_addresses, remote_address).ok_or_else(|| {
                ConnectionError::FailedToConnect(format!(
                "Unable to find local address from {:?} that can connect to the remote address {}",
                local_addresses, remote_address
            ))
            })
        };

        if let Some(s) = self.local_pool.lock().await.get(local_address()?) {
            return Ok(s.clone());
        };

        match protocol {
            #[cfg(feature = "quinn")]
            Protocol::Quic(c) => {
                let (endpoint, incoming) =
                    quinnpr::obtain_client_endpoint(local_address()?, c).await?;
                Ok(Arc::new(LocalSocket::Quinn((
                    endpoint,
                    Arc::new(Mutex::new(incoming)),
                ))))
            }
            Protocol::Laminar => {
                let socket = laminarpr::run_laminar(local_address()?)?;
                Ok(Arc::new(LocalSocket::Laminar(socket)))
            }
            Protocol::Tcp => {
                self.cleanup(60).unwrap_or_default();
                if let Some(stream) = self.stream_pool.get_by_destination(remote_address).await {
                    if stream.peer_addr().is_ok() {
                        // debug!("Tcp reuse stream for {}", remote_address);
                        self.stream_pool.add(stream.clone()).await;
                        return Ok(Arc::new(LocalSocket::Stream(stream)));
                    };
                };
                if using_heartbeat {
                    let use_local = local_address()?;
                    // debug!("Tcp create stream from {} to {}", use_local, remote_address);
                    let stream = tcp::connect_stream(*use_local, *remote_address).await?;
                    let shared_stream = Arc::new(stream);
                    self.stream_pool.add(shared_stream.clone()).await;
                    let socket = Arc::new(LocalSocket::Stream(shared_stream.clone()));
                    return Ok(socket);
                }
                let socket = tcp::obtain_client_socket(*local_address()?)?;
                Ok(Arc::new(LocalSocket::Tcp(Mutex::new(socket))))
            }
            _ => {
                let socket = UdpSocket::bind(local_address()?).await?;
                if remote_address.ip().is_multicast() {
                    socket.set_multicast_loop_v4(false).unwrap_or(());
                    socket.set_multicast_loop_v6(false).unwrap_or(());
                }
                let socket_wrapped = Arc::new(socket);
                Ok(Arc::new(LocalSocket::Socket(socket_wrapped)))
            }
        }
    }

    pub async fn obtain_server_socket(
        &self,
        local_address: SocketAddr,
        protocol: &Protocol,
    ) -> Result<Arc<LocalSocket>, ConnectionError>
    {
        match protocol {
            #[cfg(feature = "quinn")]
            Protocol::Quic(c) => {
                let (e, i) = quinnpr::obtain_server_endpoint(&local_address, c).await?;
                let lsocket = Arc::new(LocalSocket::Quinn((e, Arc::new(Mutex::new(i)))));
                let rsocket = Arc::clone(&lsocket);
                self.local_pool.lock().await.insert(local_address, lsocket);
                Ok(rsocket)
            }
            Protocol::Laminar => {
                let socket = laminarpr::run_laminar(&local_address)?;
                let lsocket = Arc::new(LocalSocket::Laminar(socket));
                let rsocket = Arc::clone(&lsocket);
                self.local_pool.lock().await.insert(local_address, lsocket);
                Ok(rsocket)
            }
            Protocol::Tcp => {
                let listener = tcp::obtain_server_socket(local_address)?;
                Ok(Arc::new(LocalSocket::TcpListener((
                    listener,
                    self.stream_pool.clone(),
                ))))
            }
            _ => {
                let socket = UdpSocket::bind(&local_address)
                    .await
                    .map_err(|e| ConnectionError::BindError(local_address, e))?;
                let lsocket = Arc::new(LocalSocket::Socket(Arc::new(socket)));
                let rsocket = Arc::clone(&lsocket);
                self.local_pool.lock().await.insert(local_address, lsocket);
                Ok(rsocket)
            }
        }
    }

    pub fn cleanup(&self, oldest: u64) -> Result<usize, LimitError>
    {
        self.stream_pool.cleanup(oldest)
    }

    #[cfg(test)]
    fn count(&self) -> usize
    {
        match self.local_pool.try_lock() {
            Ok(h) => h.len(),
            _ => 0,
        }
    }
}

pub async fn send_data<E, T>(
    local_socket: Arc<LocalSocket>,
    encryptor: E,
    protocol: &Protocol,
    destination: Destination,
    data: Vec<u8>,
    timeout_callback: T,
) -> Result<usize, ConnectionError>
where
    E: FrameEncryptor
        + FrameDataDecryptor
        + FrameIndexEncryptor
        + RelayEncryptor
        + Send
        + Sync
        + Clone
        + 'static,
    T: Fn(Duration) -> bool + Send + Sync + 'static,
{
    return match protocol {
        #[cfg(feature = "frames")]
        Protocol::Frames => {
            frames::send_data(
                local_socket.socket().ok_or_else(|| {
                    ConnectionError::InvalidProtocol("Frames protocol socket expected".to_owned())
                })?,
                encryptor,
                data,
                destination.into(),
                timeout_callback,
            )
            .await
        }
        #[cfg(feature = "quinn")]
        Protocol::Quic(_) => {
            quinnpr::send_data(
                local_socket.quinn_client().ok_or_else(|| {
                    ConnectionError::InvalidProtocol("Quic protocol client expected".to_owned())
                })?,
                data,
                destination,
            )
            .await
        }
        #[cfg(feature = "quiche")]
        Protocol::Quic(c) => {
            quiche::send_data(
                local_socket.socket().ok_or_else(|| {
                    ConnectionError::InvalidProtocol("Quic protocol socket expected".to_owned())
                })?,
                encryptor,
                data,
                destination,
                c.verify_dir.clone(),
                timeout_callback,
            )
            .await
        }
        Protocol::Basic => {
            basic::send_data(
                local_socket.socket().ok_or_else(|| {
                    ConnectionError::InvalidProtocol("Basic protocol socket expected".to_owned())
                })?,
                &encryptor,
                data,
                &destination.into(),
                timeout_callback,
            )
            .await
        }
        Protocol::Laminar => {
            let socket = local_socket.laminar_sender().ok_or_else(|| {
                ConnectionError::InvalidProtocol("Laminar protocol socket expected".to_owned())
            })?;
            laminarpr::send_data(&socket, encryptor, data, &destination.into()).await
        }
        Protocol::Tcp => {
            if let Some(stream) = local_socket.stream() {
                send_stream(&stream, &encryptor, data, timeout_callback).await
            } else {
                let socket = Arc::try_unwrap(local_socket)
                    .map_err(|_| {
                        ConnectionError::InvalidProtocol("unable to use tcp socket".to_owned())
                    })?
                    .tcp_consume()
                    .ok_or_else(|| {
                        ConnectionError::InvalidProtocol("Tcp protocol socket expected".to_owned())
                    })?;
                tcp::send_data(
                    socket,
                    &encryptor,
                    data,
                    &destination.into(),
                    timeout_callback,
                )
                .await
            }
        }
    };
}

pub async fn receive_data(
    local_socket: Arc<LocalSocket>,
    encryptor: &(impl FrameDecryptor + DataEncryptor + IdentityVerifier),
    protocol: &Protocol,
    max_len: usize,
    timeout: impl Fn(Duration) -> bool,
) -> Result<(Vec<u8>, SocketAddr), ConnectionError>
{
    return match protocol {
        #[cfg(feature = "frames")]
        Protocol::Frames => {
            frames::receive_data(
                local_socket.socket().ok_or_else(|| {
                    ConnectionError::InvalidProtocol("Frames protocol socket expected".to_owned())
                })?,
                encryptor,
                max_len,
                timeout,
            )
            .await
        }
        #[cfg(feature = "quinn")]
        Protocol::Quic(_) => {
            let inc = local_socket.quinn_server().ok_or_else(|| {
                ConnectionError::InvalidProtocol("Quic protocol server expected".to_owned())
            })?;
            let mut incoming = inc.try_lock().map_err(|_| {
                ConnectionError::InvalidProtocol(
                    "Quic server is locked and can not be used multiple times".into(),
                )
            })?;
            quinnpr::receive_data(&mut *incoming, max_len, timeout).await
        }
        #[cfg(feature = "quiche")]
        Protocol::Quic(c) => {
            quiche::receive_data(
                local_socket.socket().ok_or_else(|| {
                    ConnectionError::InvalidProtocol("Quic protocol socket expected".to_owned())
                })?,
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
                local_socket.socket().ok_or_else(|| {
                    ConnectionError::InvalidProtocol("Basic protocol socket expected".to_owned())
                })?,
                encryptor,
                max_len,
                timeout,
            )
            .await
        }
        Protocol::Laminar => {
            let socket = local_socket.laminar_receiver().ok_or_else(|| {
                ConnectionError::InvalidProtocol("Basic protocol socket expected".to_owned())
            })?;
            laminarpr::receive_data(&socket, encryptor, max_len, timeout).await
        }
        Protocol::Tcp => {
            tcp::receive_data(
                local_socket.tcp_listener().ok_or_else(|| {
                    ConnectionError::InvalidProtocol("Tcp protocol socket expected".to_owned())
                })?,
                encryptor,
                max_len,
                timeout,
            )
            .await
        }
    };
}

#[cfg(test)]
mod protocolstest
{
    use super::*;
    #[cfg(feature = "quic")]
    use crate::config::Certificates;
    use indexmap::indexset;
    #[cfg(feature = "quic-quinn")]
    use tokio::time::sleep;

    async fn test_pool_client_socket_can_be_obtained_once(protocol: Protocol, port: u32)
    {
        let pool = SocketPool::default();
        let local_addresses = indexset! {format!("127.0.0.1:{}", port).parse().unwrap()};
        let remote_address = "127.0.0.1:8000".parse().unwrap();

        assert_eq!(pool.count(), 0);
        let _1 = pool
            .obtain_client_socket(&local_addresses, &remote_address, &protocol, false)
            .await
            .unwrap();
        assert_eq!(pool.count(), 0);
        let local_socket2 = pool
            .obtain_client_socket(&local_addresses, &remote_address, &protocol, false)
            .await;
        assert_eq!(pool.count(), 0);
        assert!(local_socket2.is_err());
    }

    async fn test_pool_client_socket_can_be_obtained_many_times_if_server_socket_is_used(
        protocol: Protocol,
        port: u32,
    )
    {
        let pool = SocketPool::default();
        let local_addresses = indexset! {format!("127.0.0.1:{}", port).parse().unwrap()};
        let remote_address = "127.0.0.1:8000".parse().unwrap();

        assert_eq!(pool.count(), 0);

        let _1 = pool
            .obtain_server_socket(local_addresses[0], &protocol)
            .await
            .unwrap();
        assert_eq!(pool.count(), 1);

        let _2 = pool
            .obtain_client_socket(&local_addresses, &remote_address, &protocol, false)
            .await
            .unwrap();
        assert_eq!(pool.count(), 1);
        let _3 = pool
            .obtain_client_socket(&local_addresses, &remote_address, &protocol, false)
            .await
            .unwrap();
        assert_eq!(pool.count(), 1);
    }

    async fn test_pool_client_socket_can_be_obtained_once_its_dropped(protocol: Protocol, port: u32)
    {
        let pool = SocketPool::default();
        let local_addresses = indexset! {format!("127.0.0.1:{}", port).parse().unwrap()};
        let remote_address = "127.0.0.1:8000".parse().unwrap();
        assert_eq!(pool.count(), 0);
        {
            let _1 = pool
                .obtain_client_socket(&local_addresses, &remote_address, &protocol, false)
                .await
                .unwrap();
        }
        #[cfg(feature = "quic-quinn")]
        sleep(Duration::from_millis(100)).await;
        let _2 = pool
            .obtain_client_socket(&local_addresses, &remote_address, &protocol, false)
            .await
            .unwrap();
        let local_socket3 = pool
            .obtain_client_socket(&local_addresses, &remote_address, &protocol, false)
            .await;
        assert!(local_socket3.is_err());
    }

    #[tokio::test]
    async fn test_socket_pool_all_protos()
    {
        #[cfg(feature = "quic")]
        let certs = Certificates {
            private_key: "tests/certs/localhost.key".to_owned(),
            public_key: "tests/certs/localhost.crt".to_owned(),
            verify_dir: Some("tests/certs/cert-verify".to_owned()),
        };
        for (protocol, port) in [
            (Protocol::Basic, 9811),
            #[cfg(feature = "frames")]
            (Protocol::Frames, 9911),
            (Protocol::Laminar, 9912),
            #[cfg(feature = "quic-quinn")]
            (Protocol::Quic(certs), 7313),
            #[cfg(feature = "quic-quiche")]
            (Protocol::Quic(certs), 7913),
        ]
        .to_vec()
        {
            test_pool_client_socket_can_be_obtained_once(protocol.clone(), 1 + port).await;
            test_pool_client_socket_can_be_obtained_many_times_if_server_socket_is_used(
                protocol.clone(),
                2 + port,
            )
            .await;
            test_pool_client_socket_can_be_obtained_once_its_dropped(protocol, 3 + port).await;
        }
    }
}
