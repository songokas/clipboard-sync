use connection_pool::ConnectionPool;
use tcp_stream_pool::TcpStreamPool;
use tls_stream_pool::TlsStreamPool;
use udp_pool::UdpSocketPool;

#[cfg(feature = "quic")]
pub mod connection_pool;
#[cfg(not(feature = "quic"))]
pub mod connection_pool {
    pub type ConnectionPool = String;
}
pub mod destination_pool;
pub mod socket_pool;
pub mod split_stream_pool;
pub mod udp_pool;

pub mod tcp_stream_pool {
    use std::sync::Arc;

    use tokio::net::{
        tcp::{OwnedReadHalf, OwnedWriteHalf},
        TcpSocket,
    };
    use tokio::sync::Mutex;

    use super::{socket_pool::SocketState, split_stream_pool::SplitStreamPool};

    pub type LockedTcpWrite = Arc<Mutex<OwnedWriteHalf>>;
    pub type LockedStateTcpWrite = Mutex<SocketState<LockedTcpWrite, TcpSocket>>;
    pub type TcpStreamPool = SplitStreamPool<OwnedReadHalf, OwnedWriteHalf, TcpSocket>;
}

#[cfg(feature = "tls")]
pub mod tls_stream_pool {

    use std::sync::Arc;

    use rustls_tokio_stream::{TlsStreamRead, TlsStreamWrite};
    use tokio::{net::TcpSocket, sync::Mutex};

    use super::{socket_pool::SocketState, split_stream_pool::SplitStreamPool};

    pub type LockedTcpWrite = Arc<Mutex<TlsStreamWrite>>;
    pub type LockedStateTcpWrite = Mutex<SocketState<LockedTcpWrite, TcpSocket>>;
    pub type TlsStreamPool = SplitStreamPool<TlsStreamRead, TlsStreamWrite, TcpSocket>;
}

#[cfg(not(feature = "tls"))]
pub mod tls_stream_pool {
    pub type TlsStreamPool = String;
}

#[derive(Default, Clone)]
pub struct PoolFactory {
    pub upd: UdpSocketPool,
    pub tcp: TcpStreamPool,
    pub quic: ConnectionPool,
    pub tcp_tls: TlsStreamPool,
}
