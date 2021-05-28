use indexmap::indexmap;
use serde::{Deserialize, Serialize};

use crate::config::Groups;
use crate::encryption::{decrypt, encrypt_to_bytes, DataEncryptor};
use crate::errors::ConnectionError;
use crate::identity::{identity_matching_hosts, validate, Identity, IdentityVerifier};
use crate::message::{Group, MessageType};

#[derive(Serialize, Deserialize, Debug)]
pub struct Frame
{
    pub index: u32,
    pub total: u16,
    pub data: Vec<u8>,
}

pub trait FrameDecryptor
{
    fn decrypt_to_frame(
        &self,
        data: &[u8],
        identity: &Identity,
    ) -> Result<(Frame, Group), ConnectionError>;
    fn decrypt(
        &self,
        data: &[u8],
        identity: &Identity,
    ) -> Result<(Vec<u8>, Group), ConnectionError>;
}

pub trait FrameDataDecryptor
{
    fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>, ConnectionError>;
}

pub trait FrameEncryptor
{
    fn encrypt(
        &self,
        data: Vec<u8>,
        message_type: &MessageType,
    ) -> Result<Vec<u8>, ConnectionError>;
}

pub trait FrameIndexEncryptor
{
    fn encrypt_with_index(
        &self,
        data: &[u8],
        index: u32,
        max_payload: usize,
    ) -> Result<Vec<u8>, ConnectionError>;
}

//@TODO once trait_alias
// pub trait FragmentEncryptor =
// FrameEncryptor + FrameDataDecryptor + FrameIndexEncryptor + Send + Sync + Clone + 'static;

pub struct GroupsEncryptor
{
    groups: Groups,
}

impl GroupsEncryptor
{
    pub fn new(groups: Groups) -> Self
    {
        return Self { groups };
    }
}

impl FrameDecryptor for GroupsEncryptor
{
    fn decrypt(&self, data: &[u8], identity: &Identity)
        -> Result<(Vec<u8>, Group), ConnectionError>
    {
        let (message, group) = validate(&data, &self.groups, identity)?;
        let bytes = decrypt(&message, identity, &group)?;
        return Ok((bytes, group));
    }

    fn decrypt_to_frame(
        &self,
        data: &[u8],
        identity: &Identity,
    ) -> Result<(Frame, Group), ConnectionError>
    {
        let (bytes, group) = self.decrypt(data, identity)?;
        let frame: Frame = bincode::deserialize(&bytes)
            .map_err(|err| ConnectionError::InvalidBuffer((*err).to_string()))?;
        return Ok((frame, group));
    }
}

impl DataEncryptor for GroupsEncryptor
{
    fn encrypt(
        &self,
        data: &[u8],
        group: &Group,
        identity: &Identity,
        message_type: &MessageType,
    ) -> Result<Vec<u8>, ConnectionError>
    {
        let bytes = encrypt_to_bytes(data, identity, group, message_type)?;
        return Ok(bytes);
    }
}

impl IdentityVerifier for GroupsEncryptor
{
    fn verify(&self, identity: &Identity) -> Option<&Group>
    {
        self.groups
            .iter()
            .find_map(|(_, g)| identity_matching_hosts(&g.allowed_hosts, identity).then(|| g))
        // for group in self.groups {
        //     if identity_matching_hosts(group.allowed_hosts, identity)) {
        //         return true;
        //     }
        // }
        // return false;
    }
}

#[derive(Debug, Clone)]
pub struct IdentityEncryptor
{
    group: Group,
    identity: Identity,
}

impl IdentityEncryptor
{
    pub fn new(group: Group, identity: Identity) -> Self
    {
        return Self { group, identity };
    }
}

impl FrameEncryptor for IdentityEncryptor
{
    fn encrypt(&self, data: Vec<u8>, message_type: &MessageType)
        -> Result<Vec<u8>, ConnectionError>
    {
        let bytes = encrypt_to_bytes(&data, &self.identity, &self.group, message_type)?;
        return Ok(bytes);
    }
}

impl FrameIndexEncryptor for IdentityEncryptor
{
    fn encrypt_with_index(
        &self,
        data: &[u8],
        index: u32,
        max_payload: usize,
    ) -> Result<Vec<u8>, ConnectionError>
    {
        let frame = data_to_frame(index as u32, &data, max_payload)?;
        let bytes = encrypt_to_bytes(&frame, &self.identity, &self.group, &MessageType::Frame)?;
        return Ok(bytes);
    }
}

impl FrameDataDecryptor for IdentityEncryptor
{
    fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>, ConnectionError>
    {
        let groups = indexmap! { self.group.name.clone() => self.group.clone() };
        let (message, group) = validate(&data, &groups, &self.identity)?;
        let bytes = decrypt(&message, &self.identity, &group)?;
        return Ok(bytes);
    }
}

pub fn data_to_frame(
    index: u32,
    data: &[u8],
    max_payload: usize,
) -> Result<Vec<u8>, ConnectionError>
{
    let size = data.len();
    let indexes = size_to_indexes(size, max_payload);
    let from = index as usize * max_payload;
    let to = if from + max_payload > size {
        size
    } else {
        from + max_payload
    };

    let frame = Frame {
        index: index,
        total: indexes as u16,
        data: data[from..to].to_vec(),
    };

    let bytes = bincode::serialize(&frame)
        .map_err(|err| ConnectionError::InvalidBuffer((*err).to_string()))?;
    return Ok(bytes);
}

pub fn size_to_indexes(size: usize, max_payload: usize) -> usize
{
    let reminder = if size % max_payload > 0 { 1 } else { 0 };
    return (size / max_payload) + reminder;
}
