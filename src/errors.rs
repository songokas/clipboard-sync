use std::io;

#[derive(Debug)]
pub enum EncryptionError
{
    InvalidMessage(String),
    EncryptionFailed(String),
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

}

#[derive(Debug)]
pub enum CliError
{
    IoError(io::Error),
    ArgumentError(String),
    SocketError(std::net::AddrParseError),
    ConnectionError(ConnectionError),
    #[cfg(feature = "quic")]
    KeyError(quinn::ParseError)
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

#[cfg(feature = "quic")]
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

#[cfg(feature = "quic")]
impl From<quiche::Error> for ConnectionError
{
    fn from(error: quiche::Error) -> Self
    {
        ConnectionError::Http3(error)
    }
}

impl From<ConnectionError> for CliError
{
    fn from(error: ConnectionError) -> Self
    {
        CliError::ConnectionError(error)
    }
}
