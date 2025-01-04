use blake2::{Blake2b, Digest};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use chacha20poly1305::{Key, XNonce};
use core::time::Duration;
use indexmap::{IndexMap, IndexSet};
use serde::{de, Deserialize, Serialize};
use std::net::SocketAddr;
use x25519_dalek::PublicKey;

use crate::defaults::NONCE_SIZE;
use crate::protocol::Protocol;

pub type GroupName = String;
pub type DestinationHost = String;
pub type ServerName = String;
pub type AllowedHosts = IndexMap<DestinationHost, Option<ServerName>>;

mod serde_nonce {
    use super::*;
    use serde::{Deserializer, Serializer};

    pub fn serialize<S: Serializer>(nonce: &XNonce, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(nonce)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<XNonce, D::Error> {
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

#[repr(u8)]
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Copy, Eq, Hash)]
pub enum MessageType {
    Text,
    File,
    Files,
    Directory,
    Handshake,
    Heartbeat,
    PublicKey,
}

impl TryFrom<u8> for MessageType {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        Ok(match value {
            0 => Self::Text,
            1 => Self::File,
            2 => Self::Files,
            3 => Self::Directory,
            4 => Self::Handshake,
            5 => Self::Heartbeat,
            6 => Self::PublicKey,
            _ => return Err(()),
        })
    }
}

impl std::fmt::Display for MessageType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Text => write!(f, "text"),
            Self::File => write!(f, "file"),
            Self::Files => write!(f, "files"),
            Self::Directory => write!(f, "directory"),
            Self::Handshake => write!(f, "handshake"),
            Self::Heartbeat => write!(f, "heartbeat"),
            Self::PublicKey => write!(f, "public_key"),
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Message {
    pub message_type: MessageType,
    #[serde(with = "serde_nonce")]
    pub nonce: XNonce,
    pub time: u64,
    pub group: GroupName,
    pub data: Vec<u8>,
}

impl From<Message> for Bytes {
    fn from(value: Message) -> Bytes {
        let mut bytes = BytesMut::new();
        bytes.put_u8(value.message_type as u8);
        bytes.put(Bytes::from(value.nonce.to_vec()));
        bytes.put_u64(value.time);
        bytes.put_u32(value.group.len() as u32);
        bytes.put(Bytes::from(value.group));
        bytes.put(Bytes::from(value.data));
        bytes.into()
    }
}

impl From<Message> for Vec<u8> {
    fn from(value: Message) -> Self {
        let bytes: Bytes = value.into();
        bytes.into()
    }
}

impl TryFrom<Vec<u8>> for Message {
    type Error = ();

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        let mut bytes = Bytes::from(value);

        if bytes.remaining() < 1 {
            return Err(());
        }

        let message_type = bytes.get_u8().try_into()?;

        if bytes.remaining() < NONCE_SIZE {
            return Err(());
        }

        let nonce_bytes = bytes.copy_to_bytes(NONCE_SIZE);

        let nonce = *XNonce::from_slice(&nonce_bytes);

        if bytes.remaining() < size_of::<u64>() {
            return Err(());
        }

        let time = bytes.get_u64();

        if bytes.remaining() < size_of::<u32>() {
            return Err(());
        }

        let group_len = bytes.get_u32();

        if bytes.remaining() < group_len as usize {
            return Err(());
        }

        let group_bytes = bytes.copy_to_bytes(group_len as usize);
        let group = String::from_utf8_lossy(&group_bytes).to_string();
        let data = bytes.copy_to_bytes(bytes.remaining());
        Ok(Self {
            message_type,
            nonce,
            time,
            group,
            data: data.into(),
        })
    }
}

#[derive(Debug)]
pub struct RelayMessage {
    pub public_key: PublicKey,
    pub nonce: XNonce,
    pub time: u64,
    pub data: Vec<u8>,
}

impl From<RelayMessage> for Bytes {
    fn from(value: RelayMessage) -> Self {
        let mut bytes = BytesMut::new();
        bytes.put(Bytes::from(value.public_key.to_bytes().to_vec()));
        bytes.put(Bytes::from(value.nonce.to_vec()));
        bytes.put_u64(value.time);
        bytes.put(Bytes::from(value.data));
        bytes.into()
    }
}

impl TryFrom<&[u8]> for RelayMessage {
    type Error = ();

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let mut index = 0;
        let mut end = size_of::<PublicKey>();
        let public_key: [u8; 32] = value
            .get(index..end)
            .ok_or(())?
            .try_into()
            .map_err(|_| ())?;
        let public_key = PublicKey::from(public_key);
        index = end;
        end += NONCE_SIZE;
        let nonce = *XNonce::from_slice(value.get(index..end).ok_or(())?);
        index = end;
        end += size_of::<u64>();
        let time = u64::from_be_bytes(
            value
                .get(index..end)
                .ok_or(())?
                .try_into()
                .map_err(|_| ())?,
        );

        index = end;
        let id = value.get(index..).ok_or(())?.to_vec();

        Ok(RelayMessage {
            public_key,
            nonce,
            time,
            data: id,
        })
    }
}

#[derive(Debug)]
pub struct AdditionalData {
    pub message_type: MessageType,
    pub identity: String,
    pub group: String,
}

impl From<AdditionalData> for Bytes {
    fn from(value: AdditionalData) -> Self {
        let mut bytes = BytesMut::new();
        bytes.put_u8(value.message_type as u8);
        bytes.put_u16(value.identity.len() as u16);
        bytes.put(Bytes::from(value.identity));
        bytes.put_u16(value.group.len() as u16);
        bytes.put(Bytes::from(value.group));
        bytes.into()
    }
}

pub type GroupId = [u8; 64];

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Relay {
    pub host: String,
    pub public_key: PublicKey,
}

#[derive(Debug, Clone)]
pub struct Group {
    pub name: GroupName,
    pub allowed_hosts: AllowedHosts,
    pub key: Key,
    pub visible_ip: Option<String>,
    pub send_using_address: IndexSet<SocketAddr>,
    pub clipboard: String,
    pub protocol: Protocol,
    pub heartbeat: Option<Duration>,
    pub message_valid_for: Option<Duration>,
    pub relay: Option<Relay>,
}

impl From<Group> for SendGroup {
    fn from(group: Group) -> Self {
        Self {
            allowed_hosts: group.allowed_hosts,
            name: group.name,
            key: group.key,
            visible_ip: group.visible_ip,
            heartbeat: group.heartbeat,
            message_valid_for: group.message_valid_for,
            relay: group.relay,
        }
    }
}

impl From<Group> for GroupHosts {
    fn from(group: Group) -> Self {
        Self {
            local_addresses: group.send_using_address,
            remote_addresses: group.allowed_hosts,
            protocol: group.protocol,
            heartbeat: group.heartbeat,
        }
    }
}

pub struct GroupHosts {
    pub local_addresses: IndexSet<SocketAddr>,
    pub remote_addresses: AllowedHosts,
    pub protocol: Protocol,
    pub heartbeat: Option<Duration>,
}

#[cfg_attr(test, derive(serde::Deserialize))]
#[derive(Debug, Clone)]
pub struct SendGroup {
    pub name: GroupName,
    pub allowed_hosts: AllowedHosts,
    #[cfg_attr(test, serde(skip, default = "default_key"))]
    pub key: Key,
    pub visible_ip: Option<String>,
    pub heartbeat: Option<Duration>,
    pub message_valid_for: Option<Duration>,
    pub relay: Option<Relay>,
}

impl SendGroup {
    pub fn hash(&self) -> GroupId {
        let mut hasher = Blake2b::new();
        hasher.update(self.key.as_slice());
        hasher.update(self.name.as_bytes());
        let result = hasher.finalize();
        result.into()
    }
}

#[cfg(test)]
fn default_key() -> Key {
    *Key::from_slice(b"23232323232323232323232323232323")
}

#[cfg(test)]
impl Message {
    pub fn from_group(name: &str) -> Self {
        return Message {
            nonce: *XNonce::from_slice(b"123456789101123456789101"),
            group: name.to_owned(),
            data: [1, 2, 4].to_vec(),
            message_type: MessageType::Text,
            time: chrono::Utc::now().timestamp() as u64,
        };
    }
}

#[cfg(test)]
impl SendGroup {
    pub fn from_name(name: &str) -> Self {
        return SendGroup {
            name: name.to_owned(),
            allowed_hosts: IndexMap::new(),
            key: *Key::from_slice(b"23232323232323232323232323232323"),
            visible_ip: None,
            heartbeat: None,
            message_valid_for: None,
            relay: None,
        };
    }

    pub fn from_addr(name: &str, allowed_host: &str) -> Self {
        return SendGroup {
            name: name.to_owned(),
            allowed_hosts: indexmap::indexmap! {allowed_host.to_owned() => None},
            key: *Key::from_slice(b"23232323232323232323232323232323"),
            visible_ip: None,
            heartbeat: None,
            message_valid_for: None,
            relay: None,
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Serialize, Deserialize, Debug)]
    struct TestNonce {
        #[serde(with = "serde_nonce")]
        pub nonce: XNonce,
    }

    #[test]
    fn test_nonce_serialize() {
        let nonce_data = "123456781234567812345678";
        let nonce = XNonce::from_slice(nonce_data.as_bytes());
        let data = TestNonce { nonce: *nonce };
        let result = bincode::serialize(&data);
        assert!(result.is_ok());
    }

    #[test]
    fn test_nonce_deserialize() {
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
