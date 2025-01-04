use std::io;
use std::net::SocketAddr;
use std::path::PathBuf;
use thiserror::Error;
use tokio::time::Duration;

#[derive(Debug, Error)]
pub enum EncryptionError {
    #[error("{0}")]
    InvalidMessage(String),
    #[error("{0}")]
    EncryptionFailed(String),
    #[error("{0}")]
    DecryptionFailed(String),
    #[error("{0}")]
    SerializeFailed(String),
    #[error("{0}")]
    ValidationError(#[from] ValidationError),
}

#[derive(Debug, Error)]
pub enum FilesystemError {
    #[error("Directory does not exist {0}")]
    NoDirectory(PathBuf),
    #[error("Failed to serialize path {0}")]
    SerializeFailed(String),
    #[error(transparent)]
    IoError(#[from] io::Error),
}

#[derive(Debug, Error)]
pub enum ValidationError {
    #[error("{0}")]
    IncorrectGroup(String),
    #[error("{0}")]
    DeserializeFailed(String),
    #[error("Failed to validate timestamp. Valid for {}s received {}s", .max_expected.as_secs_f32(), .difference)]
    InvalidTimestamp {
        difference: u64,
        max_expected: Duration,
    },
}

#[derive(Debug, Error, Clone)]
pub enum DnsError {
    #[error("{0}")]
    Failed(String),
}

#[derive(Debug, Error)]
pub enum ConnectionError {
    #[error("Timeout of {} ms occurred while waiting for {0}", .1.as_millis())]
    Timeout(&'static str, Duration),
    #[error("Connection limit reached expected {max_len} received {received}")]
    LimitReached { received: usize, max_len: usize },
    #[error("Connection expected data, but none was received")]
    NoData,
    #[error(transparent)]
    IoError(#[from] io::Error),

    #[error("Packet received from invalid source ip address {}", .0.ip())]
    InvalidSource(SocketAddr),
    #[error("Packet received from unknown source ip address")]
    NoSourceIp,

    #[error("Failed to bind {0}. {1}")]
    BindError(std::net::SocketAddr, io::Error),
    #[error(transparent)]
    SocketError(#[from] std::net::AddrParseError),
    #[error("{0}")]
    FailedToConnect(String),
    #[error("{0}")]
    InvalidBuffer(String),
    #[error("Failed to validate data: {0}")]
    ReceiveError(#[from] ValidationError),
    #[error("{0}")]
    Encryption(#[from] EncryptionError),

    #[error("Failed to join tasks")]
    JoinError(#[from] tokio::task::JoinError),
    #[error("Dns error {0}")]
    DnsError(#[from] DnsError),

    #[cfg(feature = "quic")]
    #[error(transparent)]
    QuicConnection(#[from] quinn::ConnectionError),

    #[cfg(feature = "quic")]
    #[error(transparent)]
    QuicWriteError(#[from] quinn::WriteError),

    #[cfg(feature = "quic")]
    #[error("Failed to connect {0}")]
    QuicConnect(#[from] quinn::ConnectError),

    #[error("Failed to close connection")]
    FailedToClose,

    #[error(transparent)]
    LimitError(#[from] RelayLimitError),

    #[cfg(feature = "tls")]
    #[error(transparent)]
    CertificateError(#[from] rustls::pki_types::pem::Error),
    #[error("Failed to connect {0}")]
    NotConnected(SocketAddr),
    #[error("Configuration error: {0}")]
    BadConfiguration(String),
}

impl ConnectionError {
    pub fn is_closed(&self) -> bool {
        #[cfg(feature = "quic")]
        return matches!(
            self,
            Self::QuicConnection(quinn::ConnectionError::ApplicationClosed(_)) | Self::NoData
        );
        #[cfg(not(feature = "quic"))]
        matches!(self, Self::NoData)
    }
}

#[derive(Debug, Error)]
pub enum CliError {
    #[error(transparent)]
    IoError(#[from] io::Error),
    #[error("{0}")]
    ArgumentError(String),
    #[error(transparent)]
    SocketError(#[from] std::net::AddrParseError),
    #[error(transparent)]
    ConnectionError(#[from] ConnectionError),
    #[error(transparent)]
    ClipboardError(#[from] ClipboardError),
    #[error("Failed to join tasks")]
    JoinError(#[from] tokio::task::JoinError),
    #[error("Unable to send messages. Channel closed")]
    ChannelClosed,
}

#[derive(Debug, Error)]
pub enum ClipboardError {
    #[error("Invalid utf-8 string provided {0}")]
    InvalidUtf8(String),
    #[error("Unable to access clipboard: {0}")]
    AccessError(String),
    #[error("Unable to set clipboard: {0}")]
    SetError(String),
    #[error("Filesystem: {0}")]
    Filesystem(#[from] FilesystemError),
}

#[derive(Debug, Error)]
pub enum RelayLimitError {
    #[error("{0}")]
    Lock(String),
    #[error("Max group limit reached {}", .0)]
    Groups(usize),
    #[error("Max ip limit reached {}", .0)]
    Ips(usize),
}
