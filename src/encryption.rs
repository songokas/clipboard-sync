use bincode;
use chacha20poly1305::aead::{Aead, NewAead, Payload};
use chacha20poly1305::Key;
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use flate2::read::ZlibDecoder;
use flate2::write::ZlibEncoder;
use flate2::Compression;
use log::error;
use rand::{distributions::Alphanumeric, Rng};
use std::collections::hash_map::DefaultHasher;
use std::convert::TryInto;
use std::hash::Hasher;
use std::io::prelude::*;
use std::io::{self, Read};
use std::mem::size_of;
use std::net::SocketAddr;
use x25519_dalek::{PublicKey, SharedSecret, StaticSecret};

use crate::defaults::KEY_SIZE;
use crate::errors::*;
use crate::identity::Identity;
use crate::message::*;
use crate::socket::to_socket_address;
use crate::time::get_time;

pub trait DataEncryptor
{
    fn encrypt(
        &self,
        data: &[u8],
        group: &Group,
        identity: &Identity,
        message_type: &MessageType,
        destination: &SocketAddr,
    ) -> Result<Vec<u8>, ConnectionError>;
}

pub fn random(number_of_chars: usize) -> Vec<u8>
{
    (0..number_of_chars).map(|_| rand::random::<u8>()).collect()
}

pub fn random_alphanumeric(number_of_chars: usize) -> String
{
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(number_of_chars)
        .map(char::from)
        .collect()
}

pub fn encrypt(
    contents: &[u8],
    key: &Key,
    identity: &Identity,
    group: String,
    message_type: MessageType,
) -> Result<Message, EncryptionError>
{
    let cipher = XChaCha20Poly1305::new(key);
    let nonce_data = random(size_of::<XNonce>());
    let nonce = XNonce::from_slice(&nonce_data);

    let add = AdditionalData {
        identity: identity.to_string(),
        group: group.clone(),
        message_type,
    };

    // debug!("Encrypt additional data: {:?}", add);
    let add_bytes = bincode::serialize(&add)
        .map_err(|err| EncryptionError::SerializeFailed((*err).to_string()))?;

    let msg = Payload {
        msg: contents,
        aad: &add_bytes,
    };
    let ciphertext = cipher
        .encrypt(nonce, msg)
        .map_err(|err| EncryptionError::EncryptionFailed(err.to_string()))?;
    Ok(Message {
        nonce: *nonce,
        group,
        data: ciphertext,
        message_type,
        time: get_time(),
    })
}

pub fn encrypt_with_secret(
    contents: &[u8],
    encryption_key: &SharedSecret,
    public_key: PublicKey,
) -> Result<PublicMessage, EncryptionError>
{
    let cipher = XChaCha20Poly1305::new(Key::from_slice(encryption_key.as_bytes()));
    let nonce_data = random(size_of::<XNonce>());
    let nonce = XNonce::from_slice(&nonce_data);

    let msg = Payload {
        msg: contents,
        aad: public_key.as_bytes(),
    };
    let data = cipher
        .encrypt(nonce, msg)
        .map_err(|err| EncryptionError::EncryptionFailed(err.to_string()))?;
    let message = PublicMessage {
        public_key,
        nonce: *nonce,
        data,
        time: get_time(),
    };

    Ok(message)
}

pub fn decrypt_with_secret(
    message: PublicMessage,
    encryption_key: &SharedSecret,
) -> Result<Vec<u8>, EncryptionError>
{
    let cipher = XChaCha20Poly1305::new(Key::from_slice(encryption_key.as_bytes()));

    let msg = Payload {
        msg: &message.data,
        aad: message.public_key.as_bytes(),
    };
    cipher.decrypt(&message.nonce, msg).map_err(|err| {
        EncryptionError::DecryptionFailed(format!(
            "Failed to decrypt incorrect message {}",
            err.to_string()
        ))
    })
}

pub fn encrypt_serialize_to_bytes(
    contents: &[u8],
    identity: &Identity,
    group: &Group,
    message_type: &MessageType,
) -> Result<Vec<u8>, EncryptionError>
{
    let message = encrypt(
        contents,
        &group.key,
        identity,
        group.name.clone(),
        *message_type,
    )?;
    let bytes = bincode::serialize(&message)
        .map_err(|err| EncryptionError::SerializeFailed((*err).to_string()))?;
    Ok(bytes)
}

pub fn encrypt_group_to_bytes(
    contents: &[u8],
    identity: &Identity,
    group: &Group,
    message_type: &MessageType,
    destination: &SocketAddr,
) -> Result<Vec<u8>, EncryptionError>
{
    let bytes = encrypt_serialize_to_bytes(contents, identity, group, message_type)?;

    match relay_header(group, destination) {
        Ok(Some(mut h)) => {
            h.extend(bytes);
            Ok(h)
        }
        _ => Ok(bytes),
    }
}

pub fn relay_header(
    group: &Group,
    destination: &SocketAddr,
) -> Result<Option<Vec<u8>>, EncryptionError>
{
    let relay = match &group.relay {
        Some(relay) => relay,
        None => return Ok(None),
    };

    match to_socket_address(&relay.host) {
        Ok(relay_addr) if &relay_addr == destination => {
            let relay_bytes = encrypt_with_key(&group.hash(), &group.key, &relay.public_key)?;
            Ok(Some(relay_bytes))
        }
        _ => Ok(None),
    }
}

pub fn decrypt(
    message: &Message,
    identity: &Identity,
    group: &Group,
) -> Result<Vec<u8>, EncryptionError>
{
    let add = AdditionalData {
        identity: identity.to_string(),
        group: group.name.clone(),
        message_type: message.message_type,
    };

    // debug!("Decrypt additional data: {:?}", add);

    let add_bytes = bincode::serialize(&add)
        .map_err(|err| EncryptionError::SerializeFailed((*err).to_string()))?;
    let enc_msg = Payload {
        msg: &message.data,
        aad: &add_bytes,
    };

    let cipher = XChaCha20Poly1305::new(&group.key);
    cipher.decrypt(&message.nonce, enc_msg).map_err(|err| {
        EncryptionError::DecryptionFailed(format!(
            "Failed to decrypt incorrect message for group {} type {} from {} {}",
            message.group,
            message.message_type,
            identity,
            err.to_string()
        ))
    })
}

pub fn hash(bytes: &[u8]) -> String
{
    let mut hasher = DefaultHasher::new();
    hasher.write(bytes);
    let hex = hasher.finish();
    hex.to_string()
}

pub fn compress(data: &[u8]) -> io::Result<Vec<u8>>
{
    let mut e = ZlibEncoder::new(Vec::new(), Compression::default());
    e.write_all(data)?;
    e.finish()
}

pub fn uncompress(data: Vec<u8>) -> io::Result<Vec<u8>>
{
    let mut d = ZlibDecoder::new(&data[..]);
    let mut buffer = Vec::new();
    d.read_to_end(&mut buffer)?;
    Ok(buffer)
}

pub fn hex_dump(buf: &[u8]) -> String
{
    let vec: Vec<String> = buf.iter().map(|b| format!("{:02x}", b)).collect();
    vec.join("")
}

fn encrypt_with_key(
    hash: &[u8],
    key: &Key,
    endpoint_public_key: &PublicKey,
) -> Result<Vec<u8>, EncryptionError>
{
    let key: Result<[u8; KEY_SIZE], _> = key.as_slice().try_into();
    let secret = match key {
        Ok(k) => StaticSecret::from(k),
        Err(e) => {
            error!("Failed to convert key to static key {}", e);
            return Err(EncryptionError::EncryptionFailed(format!(
                "Failed to convert key to static key {}",
                e
            )));
        }
    };
    let shared_secret = secret.diffie_hellman(endpoint_public_key);
    let public_key = PublicKey::from(&secret);
    let relay_message = encrypt_with_secret(hash, &shared_secret, public_key)?;
    let relay_bytes = bincode::serialize(&relay_message)
        .map_err(|err| EncryptionError::SerializeFailed((*err).to_string()))?;
    Ok(relay_bytes)
}

#[cfg(test)]
mod encryptiontest
{
    use super::*;
    use crate::defaults::DEFAULT_MESSAGE_SIZE;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn test_encryption()
    {
        let group1 = Group::from_name("test1");
        let group2 = Group::from_name("test2");

        let sequences: Vec<(bool, Vec<u8>, IpAddr, &Group, IpAddr, &Group)> = vec![
            (
                true,
                b"content".to_vec(),
                IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
                &group1,
                IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
                &group1,
            ),
            (
                false,
                b"content".to_vec(),
                IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
                &group1,
                IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)),
                &group1,
            ),
            (
                false,
                b"content".to_vec(),
                IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
                &group1,
                IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
                &group2,
            ),
        ];

        for (expected, bytes, identity1, group1, identity2, group2) in sequences {
            let msg = encrypt(
                &bytes,
                &group1.key,
                &identity1.into(),
                group1.name.to_owned(),
                MessageType::Text,
            );
            let data = decrypt(&msg.unwrap(), &identity2.into(), group2);
            if expected {
                assert_eq!(bytes, data.unwrap());
            } else {
                assert_eq!(true, data.is_err());
            }
        }
    }

    #[test]
    fn test_encryption_with_secret()
    {
        let sequences: Vec<(bool, Vec<u8>)> = vec![(true, b"content".to_vec())];
        let key_data: [u8; 32] = random(32).try_into().unwrap();

        let secret = StaticSecret::from(key_data);
        let public_key = PublicKey::from(&secret);
        let encryption_key = secret.diffie_hellman(&public_key);

        for (expected, bytes) in sequences {
            let msg = encrypt_with_secret(&bytes, &encryption_key, public_key).unwrap();
            let data = decrypt_with_secret(msg, &encryption_key);
            if expected {
                assert_eq!(bytes, data.unwrap());
            } else {
                assert_eq!(true, data.is_err());
            }
        }
    }

    #[test]
    fn test_encryption_with_secret_size_match()
    {
        let key_data: [u8; 32] = random(32).try_into().unwrap();
        let secret = StaticSecret::from(key_data);
        let public_key = PublicKey::from(&secret);
        let group = Group::from_name("test1");
        let data =
            encrypt_with_key(&group.hash(), &Key::from_slice(&key_data), &public_key).unwrap();
        assert_eq!(data.len(), DEFAULT_MESSAGE_SIZE);
    }

    #[test]
    fn test_hash()
    {
        assert_eq!("12095268261750217435", hash("content".as_bytes()));
        assert_eq!("15130871412783076140", hash("".as_bytes()));
    }

    fn compress_data_provider() -> Vec<(Vec<u8>, &'static str)>
    {
        let data_t = vec![
            (
                vec![120, 156, 203, 40, 205, 77, 204, 3, 0, 6, 88, 2, 26],
                "human",
            ),
            (vec![120, 156, 3, 0, 0, 0, 0, 1], ""),
        ];
        return data_t;
    }

    #[test]
    fn test_compress()
    {
        for (expected, string_to_compress) in compress_data_provider() {
            let data = compress(string_to_compress.as_bytes()).unwrap();
            assert_eq!(expected, data);
        }
    }

    #[test]
    fn test_uncompress()
    {
        for (bytes_to_uncompress, expected) in compress_data_provider() {
            let data = uncompress(bytes_to_uncompress).unwrap();
            assert_eq!(expected, String::from_utf8_lossy(&data).to_string());
        }
    }

    #[test]
    fn test_random()
    {
        let r1 = random(3);
        assert_eq!(3, r1.len());
        let r2 = random(120);
        assert_eq!(120, r2.len());
        let r3 = random(0);
        assert_eq!(0, r3.len());
        let r4 = random(3);
        assert_ne!(r1, r4);
    }

    #[test]
    fn test_random_alphanumeric()
    {
        let r1 = random_alphanumeric(3);
        assert_eq!(3, r1.len());
        let r2 = random_alphanumeric(120);
        assert_eq!(120, r2.len());
        let r3 = random_alphanumeric(0);
        assert_eq!(0, r3.len());
        let r4 = random_alphanumeric(3);
        assert_ne!(r1, r4);
        let r5 = r2
            .chars()
            .filter(|c| c.is_alphanumeric())
            .collect::<String>();
        assert_eq!(r2, r5);
    }
}
