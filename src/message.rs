use blake2::{Blake2b, Digest};
use chacha20poly1305::{Key, XNonce};
use indexmap::IndexSet;
use serde::{de, Deserialize, Serialize};
use std::convert::TryInto;
use std::net::SocketAddr;
use x25519_dalek::PublicKey;

#[cfg(test)]
use chrono::Utc;
#[cfg(test)]
use indexmap::indexset;

use crate::defaults::{KEY_SIZE, NONCE_SIZE};
use crate::protocols::Protocol;

mod serde_key_str
{
    use super::*;
    use serde::{Deserializer, Serializer};

    pub fn serialize<S: Serializer>(key: &Option<Key>, serializer: S) -> Result<S::Ok, S::Error>
    {
        match key {
            Some(v) => serializer.serialize_str(&String::from_utf8_lossy(v)),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D)
        -> Result<Option<Key>, D::Error>
    {
        let str_data: String = Deserialize::deserialize(deserializer)?;
        if str_data.len() != KEY_SIZE {
            return Err(de::Error::custom(format!(
                "Key size must be {} provided {} value {}",
                KEY_SIZE,
                str_data.len(),
                str_data
            )));
        }
        Ok(Some(*Key::from_slice(str_data.as_bytes())))
    }
}

mod serde_nonce
{
    use super::*;
    use serde::{Deserializer, Serializer};

    pub fn serialize<S: Serializer>(nonce: &XNonce, serializer: S) -> Result<S::Ok, S::Error>
    {
        serializer.serialize_bytes(nonce)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<XNonce, D::Error>
    {
        let nonce_data: Vec<u8> = Deserialize::deserialize(deserializer)?;
        if nonce_data.len() != NONCE_SIZE {
            return Err(de::Error::custom(format!(
                "Nonce size must be {} bytes. Provided {}",
                NONCE_SIZE,
                nonce_data.len(),
            )));
        }
        Ok(*XNonce::from_slice(&nonce_data))
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Copy, Eq, Hash)]
pub enum MessageType
{
    Text,
    File,
    Files,
    Directory,
    Frame,
    Handshake,
    Heartbeat,
}

impl std::fmt::Display for MessageType
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result
    {
        return match self {
            Self::Text => write!(f, "text"),
            Self::File => write!(f, "file"),
            Self::Files => write!(f, "files"),
            Self::Directory => write!(f, "directory"),
            Self::Frame => write!(f, "frame"),
            Self::Handshake => write!(f, "handshake"),
            Self::Heartbeat => write!(f, "heartbeat"),
        };
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Message
{
    #[serde(with = "serde_nonce")]
    pub nonce: XNonce,
    pub group: String,
    pub data: Vec<u8>,
    pub message_type: MessageType,
    pub time: u64,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct PublicMessage
{
    pub public_key: PublicKey,
    #[serde(with = "serde_nonce")]
    pub nonce: XNonce,
    pub data: Vec<u8>,
    pub time: u64,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct AdditionalData
{
    pub group: String,
    pub identity: String,
    pub message_type: MessageType,
}

pub type GroupId = [u8; 64];

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Relay
{
    pub host: String,
    pub public_key: PublicKey,
}

#[derive(Debug, Clone)]
pub struct Group
{
    pub name: String,
    pub allowed_hosts: IndexSet<String>,
    pub key: Key,
    pub visible_ip: Option<String>,
    pub send_using_address: IndexSet<SocketAddr>,
    pub clipboard: String,
    pub protocol: Protocol,
    pub heartbeat: u64,
    pub message_valid_for: u16,
    pub relay: Option<Relay>,
}

impl Group
{
    pub fn hash(&self) -> GroupId
    {
        return Blake2b::new()
            .chain(self.key.as_slice())
            .chain(self.name.clone())
            .finalize()
            .as_slice()
            .try_into()
            .expect("group id must match hash output");
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ConfigGroup
{
    pub allowed_hosts: Option<IndexSet<String>>,
    #[serde(default, with = "serde_key_str")]
    pub key: Option<Key>,
    pub visible_ip: Option<String>,
    pub send_using_address: Option<IndexSet<SocketAddr>>,
    pub clipboard: Option<String>,
    pub protocol: Option<String>,
    #[serde(default)]
    pub heartbeat: u64,
    pub message_valid_for: Option<u16>,
    pub relay: Option<Relay>,
}

#[cfg(test)]
impl Message
{
    pub fn from_group(name: &str) -> Self
    {
        return Message {
            nonce: XNonce::from_slice(b"123456789101123456789101").clone(),
            group: name.to_owned(),
            data: [1, 2, 4].to_vec(),
            message_type: MessageType::Text,
            time: Utc::now().timestamp() as u64,
        };
    }
}

#[cfg(test)]
impl Group
{
    pub fn from_name(name: &str) -> Self
    {
        return Group {
            name: name.to_owned(),
            allowed_hosts: IndexSet::new(),
            key: Key::from_slice(b"23232323232323232323232323232323").clone(),
            visible_ip: None,
            send_using_address: indexset! {"127.0.0.1:2993".parse::<SocketAddr>().unwrap()},
            clipboard: "/tmp/_test_clip_sync".to_owned(),
            protocol: Protocol::Basic,
            heartbeat: 0,
            message_valid_for: 0,
            relay: None,
        };
    }

    pub fn from_addr(name: &str, send_address: &str, allowed_host: &str) -> Self
    {
        return Group {
            name: name.to_owned(),
            allowed_hosts: indexset! {allowed_host.to_owned()},
            key: Key::from_slice(b"23232323232323232323232323232323").clone(),
            visible_ip: None,
            send_using_address: indexset! {send_address.parse().unwrap()},
            clipboard: "/tmp/_test_clip_sync".to_owned(),
            protocol: Protocol::Basic,
            heartbeat: 0,
            message_valid_for: 0,
            relay: None,
        };
    }

    pub fn from_visible(name: &str, visible_ip: &str) -> Self
    {
        let mut group = Group::from_name(name);
        group.visible_ip = Some(visible_ip.to_owned());
        return group;
    }
}

#[cfg(test)]
mod messagetest
{
    use super::*;

    #[derive(Serialize, Deserialize, Debug)]
    struct TestNonce
    {
        #[serde(with = "serde_nonce")]
        pub nonce: XNonce,
    }

    #[derive(Serialize, Deserialize, Debug)]
    struct TestKey
    {
        #[serde(with = "serde_key_str")]
        pub key: Option<Key>,
    }

    #[test]
    fn test_key_serialize()
    {
        let key_data = "12345678123456781234567812345678";
        let key = Key::from_slice(key_data.as_bytes());
        let data = TestKey {
            key: Some(key.clone()),
        };
        let result = bincode::serialize(&data);
        assert!(result.is_ok());
    }

    #[test]
    fn test_key_deserialize()
    {
        let key_data = [
            32, 0, 0, 0, 0, 0, 0, 0, 49, 50, 51, 52, 53, 54, 55, 56, 49, 50, 51, 52, 53, 54, 55,
            56, 49, 50, 51, 52, 53, 54, 55, 56, 49, 50, 51, 52, 53, 54, 55, 56,
        ];
        let result = bincode::deserialize::<TestKey>(&key_data);
        assert!(result.is_ok());

        let key_data = [
            32, 0, 0, 0, 0, 0, 0, 0, 49, 50, 51, 52, 53, 54, 55, 56, 49, 50, 51, 52, 53, 54, 55,
            56, 49, 50, 51, 52, 53, 54, 55, 56, 49, 50, 51, 52, 53, 54, 55, 56, 56, 49, 50, 51, 52,
            53, 54, 55, 56, 49, 50, 51, 52, 53, 54, 55, 56,
        ];
        let result = bincode::deserialize::<TestKey>(&key_data);
        assert!(result.is_ok());

        let key_data = [
            1, 0, 0, 0, 0, 0, 0, 0, 49, 50, 51, 52, 53, 54, 55, 56, 49, 50, 51, 52, 53, 54, 55, 56,
            49, 50, 51, 52, 53, 54, 55, 56, 49, 50, 51, 52, 53, 54, 55, 56,
        ];
        let result = bincode::deserialize::<TestKey>(&key_data);
        assert!(result.is_err());

        let key_data = [
            1, 0, 0, 0, 0, 0, 0, 0, 49, 50, 51, 52, 53, 54, 55, 56, 49, 50, 51, 52, 53, 54, 55, 56,
        ];
        let result = bincode::deserialize::<TestKey>(&key_data);
        assert!(result.is_err());

        let key_data = [];
        let result = bincode::deserialize::<TestKey>(&key_data);
        assert!(result.is_err());
    }

    #[test]
    fn test_nonce_serialize()
    {
        let nonce_data = "123456781234567812345678";
        let nonce = XNonce::from_slice(nonce_data.as_bytes());
        let data = TestNonce {
            nonce: nonce.clone(),
        };
        let result = bincode::serialize(&data);
        assert!(result.is_ok());
    }

    #[test]
    fn test_nonce_deserialize()
    {
        let data = [
            24, 0, 0, 0, 0, 0, 0, 0, 49, 50, 51, 52, 53, 54, 55, 56, 49, 50, 51, 52, 53, 54, 55,
            56, 49, 50, 51, 52, 53, 54, 55, 56,
        ];
        let result = bincode::deserialize::<TestNonce>(&data);
        assert!(result.is_ok());

        let data = [
            24, 0, 0, 0, 0, 0, 0, 0, 49, 50, 51, 52, 53, 54, 55, 56, 49, 50, 51, 52, 53, 54, 55,
            56, 49, 50, 51, 52, 53, 54, 55, 56, 56, 49, 50, 51, 52, 53, 54, 55, 56,
        ];
        let result = bincode::deserialize::<TestNonce>(&data);
        assert!(result.is_ok());

        let data = [
            0, 0, 0, 0, 0, 0, 0, 0, 49, 50, 51, 52, 53, 54, 55, 56, 49, 50, 51, 52, 53, 54, 55, 56,
            49, 50, 51, 52, 53, 54, 55, 56,
        ];
        let result = bincode::deserialize::<TestNonce>(&data);
        assert!(result.is_err());

        let data = [
            24, 0, 0, 0, 0, 0, 0, 0, 49, 50, 51, 52, 53, 54, 55, 56, 49, 50, 51, 52, 53, 54, 55,
        ];
        let result = bincode::deserialize::<TestNonce>(&data);
        assert!(result.is_err());

        let data = [];
        let result = bincode::deserialize::<TestNonce>(&data);
        assert!(result.is_err());
    }
}
