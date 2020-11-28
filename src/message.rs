use chacha20poly1305::{Key, Nonce};
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr};

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

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Group
{
    pub name: String,
    pub allowed_hosts: Vec<SocketAddr>,
    #[serde(with = "serde_key")]
    pub key: Key,
    pub public_ip: Option<IpAddr>,
    pub send_using_address: SocketAddr
}