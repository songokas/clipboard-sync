use clipboard::ClipboardContext;
use clipboard::ClipboardProvider;
use rand::prelude::*;
use std::{thread, time};

use base64::encode;
use bincode;
use chacha20poly1305::aead::{Aead, NewAead, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce}; // Or `XChaCha20Poly1305`
use chrono::Utc;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::io;
use std::iter::Iterator;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::time::{sleep, Duration};

use clap::{load_yaml, App};
use env_logger::Env;
use futures::join;
use log::{debug, error, info, warn};
use std::net::SocketAddr;
use std::sync::atomic::AtomicBool;

mod serde_key
{
    use super::*;
    use serde::{de::Error, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(key: &Key, serializer: S) -> Result<S::Ok, S::Error>
    {
        serializer.serialize_bytes(key)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Key, D::Error>
    {
        let key_data: Vec<u8> = Deserialize::deserialize(deserializer)?;
        Ok(Key::from_slice(&key_data).clone())
    }
}

mod serde_nonce
{
    use super::*;
    use serde::{de::Error, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(nonce: &Nonce, serializer: S) -> Result<S::Ok, S::Error>
    {
        serializer.serialize_bytes(nonce)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Nonce, D::Error>
    {
        let nonce_data: Vec<u8> = Deserialize::deserialize(deserializer)?;
        Ok(Nonce::from_slice(&nonce_data).clone())
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Message
{
    #[serde(with = "serde_nonce")]
    nonce: Nonce,
    group: String,
    text: Vec<u8>,
}

impl Message
{
    fn from_additional(ad: &AdditionalData, text: Vec<u8>) -> Self
    {
        return Message {
            nonce: ad.nonce.clone(),
            group: ad.group.clone(),
            text,
        };
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct AdditionalData
{
    #[serde(with = "serde_nonce")]
    nonce: Nonce,
    group: String,
    identity: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Group
{
    name: String,
    allowed_hosts: Vec<SocketAddr>,
    #[serde(with = "serde_key")]
    key: Key,
}

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

impl From<io::Error> for ConnectionError
{
    fn from(error: io::Error) -> Self
    {
        ConnectionError::IoError(error)
    }
}

fn set_clipboard(contents: &str) -> Result<(), ClipboardError>
{
    let mut ctx: ClipboardContext =
        ClipboardProvider::new().map_err(|err| ClipboardError::Provider((*err).to_string()))?;
    ctx.set_contents(contents.to_owned())
        .map_err(|err| ClipboardError::Access((*err).to_string()))?;
    return Ok(());
}

fn validate(buffer: &[u8], groups: &[Group]) -> Result<(Message, Group), ValidationError>
{
    let message: Message = bincode::deserialize(buffer)
        .map_err(|err| ValidationError::DeserializeFailed((*err).to_string()))?;
    let group = match groups.iter().find(|group| group.name == message.group) {
        Some(group) => group,
        _ => {
            return Err(ValidationError::IncorrectGroup(format!(
                "Group {} does not exist",
                message.group
            )));
        }
    };
    return Ok((message, group.clone()));
}

fn encrypt(contents: &[u8], identity: &str, group: &Group) -> Result<Message, EncryptionError>
{
    let cipher = ChaCha20Poly1305::new(&group.key);

    let suffix = rand::thread_rng().gen::<[u8; 4]>();
    let ts: i64 = Utc::now().timestamp_nanos();
    let end = ts.to_ne_bytes();
    let nonce_data = vec![
        end[0], end[3], end[1], end[2], end[4], end[7], end[6], end[5], suffix[0], suffix[2],
        suffix[3], suffix[1],
    ];
    let nonce = Nonce::from_slice(&nonce_data);

    let add = AdditionalData {
        identity: identity.to_owned(),
        group: group.name.clone(),
        nonce: nonce.clone(),
    };
    let add_bytes = bincode::serialize(&add)
        .map_err(|err| EncryptionError::SerializeFailed((*err).to_string()))?;

    let msg = Payload {
        msg: contents,
        aad: &add_bytes,
    };
    let ciphertext = cipher
        .encrypt(nonce, msg)
        .map_err(|err| EncryptionError::EncryptionFailed(err.to_string()))?;
    return Ok(Message::from_additional(&add, ciphertext));
}

fn decrypt(message: &Message, identity: &str, group: &Group) -> Result<String, EncryptionError>
{
    let ad = AdditionalData {
        identity: identity.to_owned(),
        group: message.group.clone(),
        nonce: message.nonce,
    };
    let add_bytes = bincode::serialize(&ad)
        .map_err(|err| EncryptionError::SerializeFailed((*err).to_string()))?;
    let enc_msg = Payload {
        msg: &message.text,
        aad: &add_bytes,
    };

    let cipher = ChaCha20Poly1305::new(&group.key);
    let plaintext = cipher
        .decrypt(&message.nonce, enc_msg)
        .map_err(|err| EncryptionError::EncryptionFailed(err.to_string()))?;
    return Ok(String::from_utf8_lossy(&plaintext).to_string());
}

fn on_receive(buffer: &[u8], identity: &str, groups: &[Group]) -> Result<(), ClipboardError>
{
    let (message, group) = validate(buffer, groups)?;
    let contents = decrypt(&message, identity, &group)?;
    set_clipboard(&contents)?;
    Ok(())
}

async fn send(data: &[u8], remote_addr: &SocketAddr) -> Result<usize, ConnectionError>
{
    debug!("Send to {}", remote_addr);
    let local_address = "0.0.0.0:0".parse::<SocketAddr>()?;
    let sock = UdpSocket::bind(local_address).await?;
    sock.connect(remote_addr).await?;
    let len = sock.send(data).await?;
    return Ok(len);
}

async fn on_clipboard_change(contents: &str, groups: &[Group]) -> Result<usize, ClipboardError>
{
    let mut sent = 0;
    for group in groups {
        for addr in &group.allowed_hosts {
            let message = encrypt(&contents.as_bytes(), &addr.to_string(), group)?;
            let bytes = bincode::serialize(&message)
                .map_err(|err| EncryptionError::SerializeFailed((*err).to_string()))?;
            sent += send(&bytes, addr).await?;
        }
    }
    Ok(sent)
}

async fn wait_on_receive(
    local_address: SocketAddr,
    running: Arc<AtomicBool>,
    groups: &[Group],
) -> Result<(), io::Error>
{
    let sock = UdpSocket::bind(local_address).await?;
    let mut buf = [0; 1024];
    while running.load(Ordering::Relaxed) {
        let (len, addr) = sock.recv_from(&mut buf).await?;
        debug!("Packet received from {} length {}", addr, len);
        let result = on_receive(&buf[..len], &addr.ip().to_string(), groups);
        match result {
            Err(err) => error!("{:?}", err),
            _ => {}
        };
        sock.send_to(b"thanks", addr).await?;
    }
    Ok(())
}

async fn wait_on_clipboard(running: Arc<AtomicBool>, groups: &[Group])
{
    let mut clipboard: ClipboardContext = ClipboardProvider::new().unwrap();
    let mut current_contents: String = "".to_owned();
    while running.load(Ordering::Relaxed) {
        sleep(Duration::from_millis(500)).await;
        let contents = match clipboard.get_contents() {
            Ok(contents) => contents,
            _ => {
                debug!("Failed to retrieve contents");
                continue;
            }
        };
        debug!("Clipboard {}", &contents);
        if contents != current_contents {
            debug!("Clipboard changed {}", &contents);
            match on_clipboard_change(&contents, groups).await {
                Ok(sent) => debug!("Sent bytes {}", sent),
                Err(err) => error!("{:?}", err),
            }
            current_contents = contents;
        }
    }
}

pub fn load_groups(file_path: &str) -> Result<Vec<Group>, CliError>
{
    return Err(CliError::MissingFile("config not implemented".to_owned()));
}

#[tokio::main]
async fn main() -> Result<(), CliError>
{
    let yaml = load_yaml!("cli.yml");
    let matches = App::from_yaml(yaml).get_matches();
    let verbosity: u8 = matches.occurrences_of("verbose") as u8;
    let config_path = matches.value_of("config");

    let local_address = matches.value_of("bind-address").unwrap_or("127.0.0.1:8920");
    let group = matches.value_of("group").unwrap_or("default");

    let allowed_host = matches.value_of("allowed-host").unwrap_or("");
    let key_data = matches.value_of("key").unwrap_or("");

    if config_path.is_none() {
        if allowed_host == "" || key_data.len() != 32 {
            return Err(CliError::ArgumentError(
                "Please provide allowed-host and key".to_owned(),
            ));
        }
    }

    let socket_address = local_address
        .parse::<SocketAddr>()
        .map_err(|err| CliError::ArgumentError(err.to_string()))?;

    let create_groups = || -> Result<Vec<Group>, CliError> {
        let allowed_host_addr = allowed_host.parse::<SocketAddr>()?;
        let key = Key::from_slice(key_data.as_bytes());
        Ok(vec![Group {
            name: group.to_owned(),
            allowed_hosts: vec![allowed_host_addr],
            key: key.clone(),
        }])
    };

    let groups = config_path
        .map(|config_path| load_groups(&config_path))
        .unwrap_or_else(create_groups)?;

    let running = Arc::new(AtomicBool::new(true));

    env_logger::from_env(Env::default().default_filter_or(match verbosity {
        1 => "debug",
        2 => "trace",
        _ => "info",
    }))
    .init();

    join!(
        wait_on_receive(socket_address, Arc::clone(&running), &groups),
        wait_on_clipboard(Arc::clone(&running), &groups)
    );

    Ok(())
}
