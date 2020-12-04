use bincode;
use chacha20poly1305::aead::{Aead, NewAead, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use chrono::Utc;
use flate2::read::ZlibDecoder;
use flate2::write::ZlibEncoder;
use flate2::Compression;
use log::debug;
use rand::prelude::*;
use std::collections::hash_map::DefaultHasher;
use std::hash::Hasher;
use std::io::prelude::*;
use std::io::{self, Read};

use crate::errors::*;
use crate::message::*;

pub fn encrypt(contents: &[u8], identity: &str, group: &Group) -> Result<Message, EncryptionError>
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
    return Ok(Message::from_additional(&add, ciphertext));
}

pub fn encrypt_to_bytes(
    contents: &[u8],
    identity: &str,
    group: &Group,
) -> Result<Vec<u8>, EncryptionError>
{
    let message = encrypt(contents, identity, group)?;
    let bytes = bincode::serialize(&message)
        .map_err(|err| EncryptionError::SerializeFailed((*err).to_string()))?;
    return Ok(bytes);
}

pub fn validate(buffer: &[u8], groups: &[Group]) -> Result<(Message, Group), ValidationError>
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

pub fn decrypt(message: &Message, identity: &str, group: &Group)
    -> Result<Vec<u8>, EncryptionError>
{
    let ad = AdditionalData {
        identity: identity.to_owned(),
        group: group.name.clone(),
        nonce: message.nonce,
    };

    // debug!("Decrypt additional data: {:?}", ad);

    let add_bytes = bincode::serialize(&ad)
        .map_err(|err| EncryptionError::SerializeFailed((*err).to_string()))?;
    let enc_msg = Payload {
        msg: &message.text,
        aad: &add_bytes,
    };

    let cipher = ChaCha20Poly1305::new(&group.key);
    return cipher
        .decrypt(&message.nonce, enc_msg)
        .map_err(|err| EncryptionError::EncryptionFailed(err.to_string()));
}

pub fn hash(bytes: &[u8]) -> String
{
    let mut hasher = DefaultHasher::new();
    hasher.write(bytes);
    let hex = hasher.finish();
    return hex.to_string();
}

pub fn compress(data: &[u8]) -> io::Result<Vec<u8>>
{
    let mut e = ZlibEncoder::new(Vec::new(), Compression::default());
    e.write_all(data)?;
    return e.finish();
}

pub fn uncompress(data: Vec<u8>) -> io::Result<Vec<u8>>
{
    let mut d = ZlibDecoder::new(&data[..]);
    let mut buffer = Vec::new();
    d.read_to_end(&mut buffer)?;
    return Ok(buffer);
}

#[cfg(test)]
mod encryptiontest
{
    use super::*;

    #[test]
    fn test_encryption()
    {
        let group1 = Group::from_name("test1");
        let group2 = Group::from_name("test2");

        let sequences: Vec<(bool, Vec<u8>, &str, &Group, &str, &Group)> = vec![
            (true, b"content".to_vec(), "1", &group1, "1", &group1),
            (false, b"content".to_vec(), "1", &group1, "2", &group1),
            (false, b"content".to_vec(), "1", &group1, "1", &group2),
        ];

        for (expected, bytes, identity1, group1, identity2, group2) in sequences {
            let msg = encrypt(&bytes, identity1, group1);
            let data = decrypt(&msg.unwrap(), identity2, group2);
            if expected {
                assert_eq!(bytes, data.unwrap());
            } else {
                assert_eq!(true, data.is_err());
            }
        }
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
            // println!("{:?}", data);
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
}
