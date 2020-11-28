use chacha20poly1305::{Key, Nonce};
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

mod serde_key_str
{
    use super::*;
    use serde::{Deserializer, Serializer};

    pub fn serialize<S: Serializer>(key: &Key, serializer: S) -> Result<S::Ok, S::Error>
    {
        serializer.serialize_str(&String::from_utf8_lossy(key))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Key, D::Error>
    {
        let str_data: String = Deserialize::deserialize(deserializer)?;
        Ok(Key::from_slice(&str_data.as_bytes()).clone())
    }
}

mod serde_key
{
    use super::*;
    use serde::{Deserializer, Serializer};

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
    use serde::{Deserializer, Serializer};

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
    pub nonce: Nonce,
    pub group: String,
    pub text: Vec<u8>,
}

impl Message
{
    pub fn from_additional(ad: &AdditionalData, text: Vec<u8>) -> Self
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
    pub nonce: Nonce,
    pub group: String,
    pub identity: String,
}

pub fn serde_default_socket() -> SocketAddr
{
    return SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0);
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Group
{
    #[serde(default)]
    pub name: String,
    #[serde(skip)]
    pub allowed_hosts: Vec<SocketAddr>,
    #[serde(with = "serde_key_str")]
    pub key: Key,
    pub public_ip: Option<IpAddr>,
    #[serde(default = "serde_default_socket")]
    pub send_using_address: SocketAddr,
}
