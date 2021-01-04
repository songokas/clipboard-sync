use chacha20poly1305::{Key, Nonce};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

use crate::socket::Protocol;

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
    // not needed remove
    #[serde(with = "serde_nonce")]
    pub nonce: Nonce,
    pub group: String,
    pub identity: String,
}

#[derive(Debug, Clone)]
pub struct Group
{
    pub name: String,
    pub allowed_hosts: Vec<String>,
    pub key: Key,
    pub public_ip: Option<String>,
    pub send_using_address: SocketAddr,
    pub clipboard: String,
    pub protocol: Protocol,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ConfigGroup
{
    pub allowed_hosts: Option<Vec<String>>,
    #[serde(with = "serde_key_str")]
    pub key: Key,
    pub public_ip: Option<String>,
    pub send_using_address: Option<SocketAddr>,
    pub clipboard: Option<String>,
    pub protocol: Option<String>,
}

#[cfg(test)]
impl Message
{
    pub fn from_group(name: &str) -> Self
    {
        return Message {
            nonce: Nonce::from_slice(b"123456789101").clone(),
            group: name.to_owned(),
            text: [1, 2, 4].to_vec(),
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
            allowed_hosts: Vec::new(),
            key: Key::from_slice(b"23232323232323232323232323232323").clone(),
            public_ip: None,
            send_using_address: "127.0.0.1:2993".parse::<SocketAddr>().unwrap(),
            clipboard: "/tmp/_test_clip_sync".to_owned(),
            protocol: Protocol::Basic,
        };
    }

    pub fn from_addr(name: &str, send_address: &str, allowed_host: &str) -> Self
    {
        return Group {
            name: name.to_owned(),
            allowed_hosts: vec![allowed_host.to_owned()],
            key: Key::from_slice(b"23232323232323232323232323232323").clone(),
            public_ip: None,
            send_using_address: send_address.parse().unwrap(),
            clipboard: "/tmp/_test_clip_sync".to_owned(),
            protocol: Protocol::Basic,
        };
    }

    pub fn from_public(name: &str, public_ip: &str) -> Self
    {
        let mut group = Group::from_name(name);
        group.public_ip = Some(public_ip.to_owned());
        return group;
    }
}
