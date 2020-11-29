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
    NoPublic(String),
}

#[derive(Debug)]
// @TODO remove
pub enum ConfigError
{
    IoError(io::Error),
    MissingFile(String),
}

#[derive(Debug)]
pub enum CliError
{
    IoError(io::Error),
    MissingFile(String),
    ArgumentError(String),
    SocketError(std::net::AddrParseError),
}

#[derive(Debug)]
pub enum ClipboardError
{
    IoError(io::Error),
    ConnectionError(ConnectionError),
    EncryptionError(EncryptionError),
    ValidationError(ValidationError),
    Provider(String),
    Access(String),
}

impl From<io::Error> for ConfigError
{
    fn from(error: io::Error) -> Self
    {
        ConfigError::IoError(error)
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

impl From<std::net::AddrParseError> for ConnectionError
{
    fn from(error: std::net::AddrParseError) -> Self
    {
        ConnectionError::SocketError(error)
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
