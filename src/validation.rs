use std::convert::TryInto;
use x25519_dalek::StaticSecret;

use crate::config::Groups;
use crate::encryption::decrypt_with_secret;
use crate::errors::{ConnectionError, ValidationError};
use crate::identity::identity_matching_hosts;
use crate::identity::Identity;
use crate::message::GroupId;
use crate::message::{Group, Message, PublicMessage};
use crate::time::{get_time, is_timestamp_valid};

pub fn validate<'a>(
    buffer: &[u8],
    groups: &'a Groups,
    identity: &Identity,
) -> Result<(Message, &'a Group), ValidationError>
{
    let message: Message = bincode::deserialize(buffer).map_err(|err| {
        ValidationError::DeserializeFailed(format!(
            "Validation invalid data provided: {}",
            (*err).to_string()
        ))
    })?;

    let group = match groups.iter().find(|(_, group)| group.name == message.group) {
        Some((_, group)) => group,
        _ => {
            return Err(ValidationError::IncorrectGroup(format!(
                "Group {} does not exist",
                message.group
            )));
        }
    };

    if !is_timestamp_valid(message.time, group.message_valid_for) {
        let now = get_time();
        let diff = if now >= message.time {
            now - message.time
        } else {
            message.time - now
        };
        return Err(ValidationError::InvalidTimestamp(
            diff,
            group.message_valid_for,
        ));
    }

    if !identity_matching_hosts(
        group.allowed_hosts.iter(),
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
pub fn validate_public(buffer: &[u8], valid_for: u16) -> Result<PublicMessage, ValidationError>
{
    let message: PublicMessage = bincode::deserialize(buffer).map_err(|err| {
        ValidationError::DeserializeFailed(format!(
            "Validation invalid data provided: {}",
            (*err).to_string()
        ))
    })?;

    if !is_timestamp_valid(message.time, valid_for) {
        let now = get_time();
        let diff = if now >= message.time {
            now - message.time
        } else {
            message.time - now
        };
        return Err(ValidationError::InvalidTimestamp(diff, valid_for));
    }
    Ok(message)
}

#[allow(dead_code)]
pub fn get_group_id(
    data: &[u8],
    secret: &StaticSecret,
    valid_for: u16,
) -> Result<GroupId, ConnectionError>
{
    let message = validate_public(data, valid_for)?;
    let key = secret.diffie_hellman(&message.public_key);
    let result = decrypt_with_secret(message, &key)?;
    match result.as_slice().try_into() {
        Ok(v) => Ok(v),
        Err(_) => Err(ConnectionError::InvalidBuffer(
            "Expected group id does not match".into(),
        )),
    }
}

#[cfg(test)]
mod validationtest
{
    use indexmap::indexmap;

    use super::*;
    use crate::{encryption::random, message::Group};
    use std::net::IpAddr;

    #[test]
    fn test_validate()
    {
        let groups = indexmap! {
            "test1".to_owned() => Group::from_addr("test1", "127.0.0.1:8900", "127.0.0.1:8900"),
            "test2".to_owned() => Group::from_name("test2"),
        };
        let sequences: Vec<(&'static str, Vec<u8>, IpAddr, bool)> = vec![
            (
                "group name and ip match",
                bincode::serialize(&Message::from_group("test1"))
                    .unwrap()
                    .to_vec(),
                "127.0.0.1".parse::<IpAddr>().unwrap(),
                true,
            ),
            (
                "group name doest not match",
                bincode::serialize(&Message::from_group("none"))
                    .unwrap()
                    .to_vec(),
                "127.0.0.1".parse::<IpAddr>().unwrap(),
                false,
            ),
            (
                "ip doest not match",
                bincode::serialize(&Message::from_group("test1"))
                    .unwrap()
                    .to_vec(),
                "127.0.0.2".parse::<IpAddr>().unwrap(),
                false,
            ),
            (
                "empty ip",
                bincode::serialize(&Message::from_group("test1"))
                    .unwrap()
                    .to_vec(),
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
            let result = validate(&bytes, &groups, &Identity::from(id));
            assert_eq!(result.is_ok(), expected, "{}", name);
        }
    }

    #[test]
    fn test_validate_public()
    {
        //@TODO success case
        let data = random(160);
        let valid_for = 60;
        let group_ip = validate_public(&data, valid_for);
        assert!(group_ip.is_err());
    }

    #[test]
    fn test_get_group_id()
    {
        //@TODO success case
        let data = random(160);
        let key = [
            1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5,
            6, 7, 8,
        ];
        let secret = StaticSecret::from(key);
        let valid_for = 60;
        let group_ip = get_group_id(&data, &secret, valid_for);
        assert!(group_ip.is_err());
    }
}
