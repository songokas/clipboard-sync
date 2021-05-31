// use err_derive::Error;
use std::io;
use std::net::SocketAddr;
use thiserror::Error;
use tokio::time::Duration;

#[derive(Debug, Error)]
pub enum EncryptionError
{
    #[error("{0}")]
    InvalidMessage(String),
    #[error("{0}")]
    EncryptionFailed(String),
    #[error("{0}")]
    DecryptionFailed(String),
    #[error("{0}")]
    SerializeFailed(String),
}

#[derive(Debug, Error)]
pub enum ValidationError
{
    #[error("{0}")]
    IncorrectGroup(String),
    #[error("{0}")]
    DeserializeFailed(String),
    #[error("Failed to validate timestamp. Valid for {} received {}", .1, .0)]
    InvalidTimestamp(u64, u16),
}

#[derive(Debug, Error, Clone)]
pub enum DnsError
{
    #[error("{0}")]
    Failed(String),
}

#[derive(Debug, Error)]
pub enum ConnectionError
{
    #[error("Timeout of {} ms occurred while waiting for {0}", .1.as_millis())]
    Timeout(String, Duration),
    #[error("Connection limit reached: {max_len} received {received}")]
    LimitReached
    {
        received: usize, max_len: usize
    },
    #[error(transparent)]
    IoError(#[from] io::Error),

    #[error("Packet received from invalid source ip address {}", .0.ip())]
    InvalidSource(SocketAddr),
    #[error("Packet received from unknown source ip address")]
    NoSourceIp(),

    #[error("Failed to bind {0}. {1}")]
    BindError(std::net::SocketAddr, io::Error),
    #[error(transparent)]
    SocketError(#[from] std::net::AddrParseError),
    #[error("{0}")]
    FailedToConnect(String),
    #[error("{0}")]
    InvalidBuffer(String),
    #[error("{0}")]
    InvalidProtocol(String),
    #[error("Failed to validate data {0}")]
    ReceiveError(#[from] ValidationError),
    #[error("Failed to encrypt {0}")]
    Encryption(#[from] EncryptionError),

    #[error("Invalid key provided. {0}")]
    InvalidKey(String),
    #[error("Failed to join tasks")]
    JoinError(#[from] tokio::task::JoinError),
    #[error("Dns error {0}")]
    DnsError(#[from] DnsError),

    #[cfg(feature = "quiche")]
    #[error("Quic error occurred {0}")]
    Http3(#[from] quiche::Error),

    #[cfg(feature = "quinn")]
    #[error(transparent)]
    EndpointError(#[from] EndpointError),
    #[cfg(feature = "quinn")]
    #[error(transparent)]
    QuicConnection(#[from] quinn::ConnectionError),
    #[cfg(feature = "quinn")]
    #[error(transparent)]
    QuicWriteError(#[from] quinn::WriteError),
    #[cfg(feature = "quinn")]
    #[error("Failed to connect {0}")]
    QuicConnect(#[from] quinn::ConnectError),
}

#[derive(Debug, Error)]
pub enum CliError
{
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

    #[cfg(feature = "quinn")]
    #[error(transparent)]
    KeyError(#[from] quinn::ParseError),
    #[error("Failed to join tasks")]
    JoinError(#[from] tokio::task::JoinError),
    #[error("Invalid key provided")]
    InvalidKey(String),
    #[error(transparent)]
    FsNotify(#[from] notify::Error),
}

#[derive(Debug, Error)]
pub enum ClipboardError
{
    #[error("{0}")]
    IoError(#[from] io::Error),
    #[error("{0}")]
    ConnectionError(#[from] ConnectionError),
    #[error("{0}")]
    EncryptionError(#[from] EncryptionError),
    #[error("{0}")]
    ValidationError(#[from] ValidationError),
    #[error("{0}")]
    Invalid(String),
    #[error("{0}")]
    Provider(String),
    #[error("{0}")]
    Access(String),
}

#[cfg(feature = "quinn")]
#[derive(Debug, Error)]
pub enum EndpointError
{
    #[error(transparent)]
    IoError(#[from] io::Error),
    #[error(transparent)]
    ParseError(#[from] quinn::ParseError),
    #[error(transparent)]
    ConnectError(#[from] quinn::EndpointError),
    #[error(transparent)]
    CertificateError(#[from] quinn::crypto::rustls::TLSError),
    #[error("{0}")]
    InvalidKey(String),
}
