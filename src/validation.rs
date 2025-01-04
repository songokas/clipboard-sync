use core::time::Duration;
use log::debug;
use std::convert::TryInto;
use x25519_dalek::StaticSecret;

use crate::config::SendGroups;
use crate::encryption::decrypt_with_secret;
use crate::errors::{ConnectionError, ValidationError};
use crate::identity::identity_matching_hosts;
use crate::identity::Identity;
use crate::message::GroupId;
use crate::message::{Message, RelayMessage, SendGroup};
use crate::time::{get_time, validate_timestamp};

pub fn validate(
    raw_data: Vec<u8>,
    groups: &SendGroups,
    identity: Identity,
) -> Result<(Message, &SendGroup), ValidationError> {
    debug!("Validate data identity={identity}");
    let message = Message::try_from(raw_data)
        .map_err(|_| ValidationError::DeserializeFailed("Invalid message provided".to_string()))?;
    let group = match groups.iter().find(|(_, group)| group.name == message.group) {
        Some((_, group)) => group,
        _ => {
            return Err(ValidationError::IncorrectGroup(format!(
                "Group {} does not exist",
                message.group
            )));
        }
    };

    if let Some(d) = group.message_valid_for {
        validate_timestamp(get_time(), message.time, d)?;
    }

    if !identity_matching_hosts(
        group.allowed_hosts.iter().map(|(k, _)| k),
        identity,
        &group.relay.as_ref().map(|r| r.host.clone()),
    ) {
        return Err(ValidationError::IncorrectGroup(format!(
            "Group {} does not allow {}",
            group.name, identity
        )));
    }

    Ok((message, group))
}

#[allow(dead_code)]
pub fn get_group_id(
    data: &[u8],
    secret: &StaticSecret,
    valid_for: Duration,
) -> Result<GroupId, ConnectionError> {
    let mut message = validate_relay_message(data, valid_for)?;
    let key = secret.diffie_hellman(&message.public_key);
    decrypt_with_secret(&mut message, &key)?;
    match message.data.try_into() {
        Ok(v) => Ok(v),
        Err(_) => Err(ConnectionError::InvalidBuffer(
            "Expected group id does not match".into(),
        )),
    }
}

#[allow(dead_code)]
fn validate_relay_message(
    buffer: &[u8],
    valid_for: Duration,
) -> Result<RelayMessage, ValidationError> {
    let message: RelayMessage = RelayMessage::try_from(buffer).map_err(|_| {
        ValidationError::DeserializeFailed("Validation invalid data provided".to_string())
    })?;
    validate_timestamp(get_time(), message.time, valid_for)?;
    Ok(message)
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use chacha20poly1305::XNonce;
    use indexmap::indexmap;
    use x25519_dalek::PublicKey;

    use super::*;
    use crate::{
        defaults::DEFAULT_RELAY_MESSAGE_SIZE,
        encryption::{encrypt_with_secret, random},
    };
    use std::net::IpAddr;

    #[test]
    fn test_validate() {
        let groups = indexmap! {
            "test1".to_owned() => SendGroup::from_addr("test1", "127.0.0.1:8900"),
            "test2".to_owned() => SendGroup::from_name("test2"),
        };
        let sequences: Vec<(&'static str, Vec<u8>, IpAddr, bool)> = vec![
            (
                "group name and ip match",
                Message::from_group("test1").into(),
                "127.0.0.1".parse::<IpAddr>().unwrap(),
                true,
            ),
            (
                "group name doest not match",
                Message::from_group("none").into(),
                "127.0.0.1".parse::<IpAddr>().unwrap(),
                false,
            ),
            (
                "ip doest not match",
                Message::from_group("test1").into(),
                "127.0.0.2".parse::<IpAddr>().unwrap(),
                false,
            ),
            (
                "empty ip",
                Message::from_group("test1").into(),
                "0.0.0.0".parse::<IpAddr>().unwrap(),
                false,
            ),
            (
                "random1",
                [3, 3, 98].to_vec(),
                "0.0.0.0".parse::<IpAddr>().unwrap(),
                false,
            ),
            (
                "empty data",
                [].to_vec(),
                "0.0.0.0".parse::<IpAddr>().unwrap(),
                false,
            ),
        ];

        for (name, bytes, id, expected) in sequences {
            let result = validate(bytes, &groups, id.into());
            assert_eq!(result.is_ok(), expected, "{} {result:?}", name);
        }
    }

    #[test]
    fn test_validate_relay_message() {
        let data = random(64);
        let message = RelayMessage {
            public_key: PublicKey::from([
                1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4,
                5, 6, 7, 8,
            ]),
            nonce: *XNonce::from_slice(b"123456789101123456789101"),
            time: get_time(),
            data: data.clone(),
        };
        let message_data: Bytes = message.into();
        let valid_for = Duration::from_secs(60);
        let new_message = validate_relay_message(&message_data, valid_for).unwrap();
        assert_eq!(data, new_message.data);
    }

    #[test]
    fn test_get_group_id() {
        let key = [
            1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5,
            6, 7, 8,
        ];
        let public_key = PublicKey::from([
            1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5,
            6, 7, 8,
        ]);
        let secret = StaticSecret::from(key);
        let data = random(64);
        let encryption_key = secret.diffie_hellman(&public_key);
        let message = encrypt_with_secret(data.clone(), &encryption_key, public_key).unwrap();
        let message_data: Bytes = message.into();
        assert_eq!(message_data.len(), DEFAULT_RELAY_MESSAGE_SIZE);
        let secret = StaticSecret::from(key);
        let valid_for = Duration::from_secs(60);
        let group_id = get_group_id(&message_data, &secret, valid_for).unwrap();
        assert_eq!(&data, &group_id);
    }
}
