use std::io;

#[derive(Debug)]
pub enum EncryptionError
{
    InvalidMessage(String),
    EncryptionFailed(String),
    DecryptionFailed(String),
    SerializeFailed(String),
}

#[derive(Debug)]
pub enum ValidationError
{
    WrongIp(String),
    IncorrectGroup(String),
    DeserializeFailed(String),
}

#[derive(Debug)]
pub enum ConnectionError
{
    IoError(io::Error),
    SocketError(std::net::AddrParseError),
    FailedToConnect(String),
    InvalidBuffer(String),
    NoPublic(String),
    InvalidProtocol(String),
    InvalidKey(String),
    ReceiveError(ValidationError),
    Encryption(EncryptionError),
    #[cfg(feature = "quin")]
    EndpointError(EndpointError),
    #[cfg(feature = "quin")]
    QuicConnection(quinn::ConnectionError),
    #[cfg(feature = "quin")]
    QuicWriteError(quinn::WriteError),
    #[cfg(feature = "quin")]
    QuicConnect(quinn::ConnectError),
    #[cfg(feature = "quin")]
    QuicReadError(quinn::ReadToEndError),
    #[cfg(feature = "quiche")]
    Http3(quiche::Error),
}

#[derive(Debug)]
pub enum CliError
{
    IoError(io::Error),
    ArgumentError(String),
    SocketError(std::net::AddrParseError),
    ConnectionError(ConnectionError),
    #[cfg(feature = "quinn")]
    KeyError(quinn::ParseError),
}

#[derive(Debug)]
pub enum ClipboardError
{
    IoError(io::Error),
    ConnectionError(ConnectionError),
    EncryptionError(EncryptionError),
    ValidationError(ValidationError),
    Invalid(String),
    Provider(String),
    Access(String),
}

#[cfg(feature = "quinn")]
#[derive(Debug)]
pub enum EndpointError
{
    IoError(io::Error),
    ParseError(quinn::ParseError),
    ConnectError(quinn::EndpointError),
    CertificateError(quinn::crypto::rustls::TLSError),
    InvalidKey(String),
}

#[cfg(feature = "quinn")]
impl From<io::Error> for EndpointError
{
    fn from(error: io::Error) -> Self
    {
        EndpointError::IoError(error)
    }
}

#[cfg(feature = "quinn")]
impl From<quinn::ParseError> for EndpointError
{
    fn from(error: quinn::ParseError) -> Self
    {
        EndpointError::ParseError(error)
    }
}

#[cfg(feature = "quinn")]
impl From<quinn::EndpointError> for EndpointError
{
    fn from(error: quinn::EndpointError) -> Self
    {
        EndpointError::ConnectError(error)
    }
}

#[cfg(feature = "quinn")]
impl From<quinn::crypto::rustls::TLSError> for EndpointError
{
    fn from(error: quinn::crypto::rustls::TLSError) -> Self
    {
        EndpointError::CertificateError(error)
    }
}

#[cfg(feature = "quinn")]
impl From<quinn::ReadToEndError> for ConnectionError
{
    fn from(error: quinn::ReadToEndError) -> Self
    {
        ConnectionError::QuicReadError(error)
    }
}

#[cfg(feature = "quiche")]
impl From<quiche::Error> for ConnectionError
{
    fn from(error: quiche::Error) -> Self
    {
        ConnectionError::Http3(error)
    }
}

impl From<ValidationError> for ClipboardError
{
    fn from(error: ValidationError) -> Self
    {
        ClipboardError::ValidationError(error)
    }
}

impl From<io::Error> for ClipboardError
{
    fn from(error: io::Error) -> Self
    {
        ClipboardError::IoError(error)
    }
}

impl From<ConnectionError> for ClipboardError
{
    fn from(error: ConnectionError) -> Self
    {
        ClipboardError::ConnectionError(error)
    }
}

impl From<EncryptionError> for ClipboardError
{
    fn from(error: EncryptionError) -> Self
    {
        ClipboardError::EncryptionError(error)
    }
}

#[cfg(feature = "quinn")]
impl From<EndpointError> for ConnectionError
{
    fn from(error: EndpointError) -> Self
    {
        ConnectionError::EndpointError(error)
    }
}

#[cfg(feature = "quinn")]
impl From<quinn::ConnectionError> for ConnectionError
{
    fn from(error: quinn::ConnectionError) -> Self
    {
        ConnectionError::QuicConnection(error)
    }
}

#[cfg(feature = "quinn")]
impl From<quinn::WriteError> for ConnectionError
{
    fn from(error: quinn::WriteError) -> Self
    {
        ConnectionError::QuicWriteError(error)
    }
}

#[cfg(feature = "quinn")]
impl From<quinn::ConnectError> for ConnectionError
{
    fn from(error: quinn::ConnectError) -> Self
    {
        ConnectionError::QuicConnect(error)
    }
}

impl From<std::net::AddrParseError> for ConnectionError
{
    fn from(error: std::net::AddrParseError) -> Self
    {
        ConnectionError::SocketError(error)
    }
}

impl From<ValidationError> for ConnectionError
{
    fn from(error: ValidationError) -> Self
    {
        ConnectionError::ReceiveError(error)
    }
}

impl From<EncryptionError> for ConnectionError
{
    fn from(error: EncryptionError) -> Self
    {
        ConnectionError::Encryption(error)
    }
}

#[cfg(feature = "quinn")]
impl From<quinn::ParseError> for CliError
{
    fn from(error: quinn::ParseError) -> Self
    {
        CliError::KeyError(error)
    }
}

impl From<std::net::AddrParseError> for CliError
{
    fn from(error: std::net::AddrParseError) -> Self
    {
        CliError::SocketError(error)
    }
}

impl From<io::Error> for CliError
{
    fn from(error: io::Error) -> Self
    {
        CliError::IoError(error)
    }
}

impl From<io::Error> for ConnectionError
{
    fn from(error: io::Error) -> Self
    {
        ConnectionError::IoError(error)
    }
}

impl From<ConnectionError> for CliError
{
    fn from(error: ConnectionError) -> Self
    {
        CliError::ConnectionError(error)
    }
}
