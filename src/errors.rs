// use err_derive::Error;
use std::io;
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
    #[error("Timeout occurred {}ms while waiting for {0}", .1.as_millis())]
    Timeout(String, Duration),
    #[error("Connection limit reached: {max_len} received {received}")]
    LimitReached
    {
        received: usize, max_len: usize
    },
    #[error(transparent)]
    IoError(#[from] io::Error),
    #[error("Failed to parse address")]
    SocketError(#[from] std::net::AddrParseError),
    #[error("{0}")]
    FailedToConnect(String),
    #[error("{0}")]
    InvalidBuffer(String),
    // NoPublic(String),
    #[error("{0}")]
    InvalidProtocol(String),
    #[error("Failed to validate data")]
    ReceiveError(#[from] ValidationError),
    #[error("Failed to encrypt")]
    Encryption(#[from] EncryptionError),

    #[error("Invalid key provided. {0}")]
    InvalidKey(String),
    #[error("Failed to join tasks")]
    JoinError(#[from] tokio::task::JoinError),
    #[error("Dns error")]
    DnsError(#[from] DnsError),

    #[cfg(feature = "quiche")]
    #[error(transparent)]
    Http3(#[from] quiche::Error),
    // #[cfg(feature = "quin")]
    // EndpointError(EndpointError),
    // #[cfg(feature = "quin")]
    // QuicConnection(quinn::ConnectionError),
    // #[cfg(feature = "quin")]
    // QuicWriteError(quinn::WriteError),
    // #[cfg(feature = "quin")]
    // QuicConnect(quinn::ConnectError),
    // #[cfg(feature = "quin")]
    // QuicReadError(quinn::ReadToEndError),
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
    // #[cfg(feature = "quinn")]
    // KeyError(quinn::ParseError),
    #[error("Failed to join tasks")]
    JoinError(#[from] tokio::task::JoinError),
    #[error("Invalid key provided")]
    InvalidKey(String),
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

// #[cfg(feature = "quinn")]
// #[derive(Debug, Error)]
// pub enum EndpointError
// {
//     #[error(transparent)]
//     IoError(io::Error),
//     #[error(transparent)]
//     ParseError(quinn::ParseError),
//     #[error(transparent)]
//     ConnectError(quinn::EndpointError),
//     #[error(transparent)]
//     CertificateError(quinn::crypto::rustls::TLSError),
//     #[error(transparent)]
//     InvalidKey(String),
// }
