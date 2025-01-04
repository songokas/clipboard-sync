use base64::prelude::BASE64_STANDARD;
use base64::{encoded_len, Engine};
use bytes::{BufMut, Bytes, BytesMut};
use chacha20poly1305::aead::AeadMutInPlace;
use chacha20poly1305::{Key, KeyInit};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use indexmap::indexset;
use log::{debug, error, trace};
use rand::{distributions::Alphanumeric, Rng};
use std::collections::hash_map::DefaultHasher;
use std::convert::TryInto;
use std::hash::Hasher;
use std::mem::size_of;
use std::net::SocketAddr;
use x25519_dalek::{PublicKey, SharedSecret, StaticSecret};

use crate::defaults::KEY_SIZE;
use crate::errors::*;
use crate::identity::Identity;
use crate::message::*;
use crate::socket::to_socket_address;
use crate::time::get_time;

pub fn random(number_of_chars: usize) -> Vec<u8> {
    (0..number_of_chars).map(|_| rand::random::<u8>()).collect()
}

pub fn random_alphanumeric(number_of_chars: usize) -> String {
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(number_of_chars)
        .map(char::from)
        .collect()
}

pub fn encrypt(
    mut data: Vec<u8>,
    key: &Key,
    identity: Identity,
    group: String,
    message_type: MessageType,
) -> Result<Message, EncryptionError> {
    let mut cipher = XChaCha20Poly1305::new(key);
    let nonce_data = random(size_of::<XNonce>());

    let nonce = XNonce::from_slice(&nonce_data);

    let add = AdditionalData {
        identity: identity.to_string(),
        group: group.clone(),
        message_type,
    };
    let add: Bytes = add.into();

    trace!("Encrypt using key={key:02x} nonce={nonce:02x} additional data: {add:?}");

    cipher
        .encrypt_in_place(nonce, &add, &mut data)
        .map_err(|err| EncryptionError::EncryptionFailed(err.to_string()))?;
    Ok(Message {
        nonce: (*nonce),
        group,
        data,
        message_type,
        time: get_time(),
    })
}

pub fn encrypt_with_secret(
    mut data: Vec<u8>,
    encryption_key: &SharedSecret,
    public_key: PublicKey,
) -> Result<RelayMessage, EncryptionError> {
    let mut cipher = XChaCha20Poly1305::new(Key::from_slice(encryption_key.as_bytes()));
    let nonce_data = random(size_of::<XNonce>());
    let nonce = XNonce::from_slice(&nonce_data);
    let time = get_time();
    let add = [time.to_be_bytes().as_slice(), public_key.as_bytes()].concat();

    cipher
        .encrypt_in_place(nonce, &add, &mut data)
        .map_err(|err| EncryptionError::EncryptionFailed(err.to_string()))?;
    let message = RelayMessage {
        public_key,
        nonce: *nonce,
        time,
        data,
    };

    Ok(message)
}

pub fn decrypt_with_secret(
    message: &mut RelayMessage,
    encryption_key: &SharedSecret,
) -> Result<(), EncryptionError> {
    let mut cipher = XChaCha20Poly1305::new(Key::from_slice(encryption_key.as_bytes()));

    let add = [
        message.time.to_be_bytes().as_slice(),
        message.public_key.as_bytes(),
    ]
    .concat();
    cipher
        .decrypt_in_place(&message.nonce, &add, &mut message.data)
        .map_err(|err| {
            EncryptionError::DecryptionFailed(format!(
                "Failed to decrypt incorrect message {}",
                err
            ))
        })
}

pub fn encrypt_serialize_to_bytes(
    contents: Vec<u8>,
    identity: Identity,
    group: &SendGroup,
    message_type: MessageType,
) -> Result<Bytes, EncryptionError> {
    let message = encrypt(
        contents,
        &group.key,
        identity,
        group.name.clone(),
        message_type,
    )?;
    Ok(message.into())
}

pub fn serialize_to_bytes(
    data: Vec<u8>,
    group: GroupName,
    message_type: MessageType,
) -> Result<Bytes, EncryptionError> {
    let message = Message {
        // dummy slice for quic
        nonce: *XNonce::from_slice(&[
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ]),
        group,
        time: get_time(),
        message_type,
        data,
    };
    Ok(message.into())
}

pub fn encrypt_group_to_bytes(
    data: Vec<u8>,
    identity: Identity,
    group: &SendGroup,
    message_type: MessageType,
    destination: SocketAddr,
) -> Result<Bytes, EncryptionError> {
    let bytes = encrypt_serialize_to_bytes(data, identity, group, message_type)?;

    match relay_header(identity.as_socket_addr(), group, destination) {
        Ok(Some(h)) => {
            debug!("Relay header added data_size={}", h.len());
            let mut relay_bytes = BytesMut::new();
            relay_bytes.put(h);
            relay_bytes.put(bytes);
            Ok(relay_bytes.into())
        }
        _ => Ok(bytes),
    }
}

pub fn relay_header(
    local_addr: SocketAddr,
    group: &SendGroup,
    destination: SocketAddr,
) -> Result<Option<Bytes>, EncryptionError> {
    let relay = match &group.relay {
        Some(relay) => relay,
        None => return Ok(None),
    };

    let local = indexset! { local_addr };

    match to_socket_address(&local, &relay.host) {
        Ok((_, relay_addr)) if relay_addr == destination => {
            let relay_bytes =
                encrypt_with_key(group.hash().to_vec(), &group.key, &relay.public_key)?;
            Ok(Some(relay_bytes))
        }
        _ => Ok(None),
    }
}

pub fn decrypt(
    message: &mut Message,
    identity: Identity,
    group: &SendGroup,
) -> Result<(), EncryptionError> {
    let add = AdditionalData {
        identity: identity.to_string(),
        group: group.name.clone(),
        message_type: message.message_type,
    };
    let add: Bytes = add.into();

    trace!(
        "Decrypt using key={:02x} nonce={:02x} additional data: {:?}",
        &group.key,
        message.nonce,
        add
    );

    let mut cipher = XChaCha20Poly1305::new(&group.key);
    cipher
        .decrypt_in_place(&message.nonce, &add, &mut message.data)
        .map_err(|err| {
            EncryptionError::DecryptionFailed(format!(
                "Incorrect message group={} message_type={} from={} {}",
                message.group, message.message_type, identity, err
            ))
        })?;
    Ok(())
    // message.data = Vec::new();
}

pub fn hash(bytes: &[u8]) -> String {
    let mut hasher = DefaultHasher::new();
    hasher.write(bytes);
    let hex = hasher.finish();
    hex.to_string()
}

pub fn hex_dump(buf: &[u8]) -> String {
    let vec: Vec<String> = buf.iter().map(|b| format!("{:02x}", b)).collect();
    vec.join("")
}

fn encrypt_with_key(
    data: Vec<u8>,
    key: &Key,
    endpoint_public_key: &PublicKey,
) -> Result<Bytes, EncryptionError> {
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
    let relay_message = encrypt_with_secret(data, &shared_secret, public_key)?;
    Ok(relay_message.into())
}

pub fn der_to_pem(der: &[u8]) -> Vec<u8> {
    let size = encoded_len(der.len(), true).expect("Encoded len");
    let mut b64 = vec![0; size];
    let written = BASE64_STANDARD
        .encode_slice(der, &mut b64)
        .expect("Der encoded");
    b64.truncate(written);
    let mut pem = Vec::new();
    pem.extend_from_slice(b"-----BEGIN CERTIFICATE-----\n");
    for chunk in b64.chunks(64) {
        pem.extend_from_slice(chunk);
        pem.extend_from_slice(b"\n");
    }
    pem.extend_from_slice(b"-----END CERTIFICATE-----\n");
    pem
}

#[cfg(test)]
mod tests {
    use test_data_file::test_data_file;

    use super::*;

    #[test_data_file(path = "tests/samples/encryption.json")]
    #[test]
    fn test_encryption_decryption(
        content: String,
        identity_to_encrypt: Identity,
        group_to_encrypt: SendGroup,
        identity_to_decrypt: Identity,
        group_to_decrypt: SendGroup,
        valid: bool,
    ) {
        let mut msg = encrypt(
            content.as_bytes().to_vec(),
            &group_to_encrypt.key,
            identity_to_encrypt,
            group_to_encrypt.name.to_owned(),
            MessageType::Text,
        )
        .unwrap();
        let result = decrypt(&mut msg, identity_to_decrypt, &group_to_decrypt);
        if valid {
            assert_eq!(content.as_bytes(), msg.data);
        } else {
            assert!(result.is_err());
        }
    }

    #[test]
    fn test_encryption_with_secret() {
        let sequences: Vec<(bool, Vec<u8>)> = vec![(true, b"content".to_vec())];
        let key_data: [u8; 32] = random(32).try_into().unwrap();

        let secret = StaticSecret::from(key_data);
        let public_key = PublicKey::from(&secret);
        let encryption_key = secret.diffie_hellman(&public_key);

        for (expected, bytes) in sequences {
            let mut msg = encrypt_with_secret(bytes.clone(), &encryption_key, public_key).unwrap();
            let result = decrypt_with_secret(&mut msg, &encryption_key);
            if expected {
                assert_eq!(bytes, msg.data);
            } else {
                assert!(result.is_err());
            }
        }
    }

    // #[test]
    // fn test_encryption_with_secret_size_match() {
    //     let key_data: [u8; 32] = random(32).try_into().unwrap();
    //     let secret = StaticSecret::from(key_data);
    //     let public_key = PublicKey::from(&secret);
    //     let group = Group::from_name("test1");
    //     let data =
    //         encrypt_with_key(&group.hash(), &Key::from_slice(&key_data), &public_key).unwrap();
    //     assert_eq!(data.len(), DEFAULT_MESSAGE_SIZE);
    // }

    #[test]
    fn test_hash() {
        assert_eq!("12095268261750217435", hash("content".as_bytes()));
        assert_eq!("15130871412783076140", hash("".as_bytes()));
    }

    #[test]
    fn test_random() {
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
    fn test_random_alphanumeric() {
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
