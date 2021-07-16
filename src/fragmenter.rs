use indexmap::indexmap;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

use crate::config::Groups;
use crate::encryption::{decrypt, encrypt_group_to_bytes, relay_header, DataEncryptor};
use crate::errors::{ConnectionError, EncryptionError};
use crate::identity::{identity_matching_hosts, Identity, IdentityVerifier};
use crate::message::{Group, MessageType};
use crate::validation::validate;

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
    ) -> Result<(Frame, &Group), ConnectionError>;
    fn decrypt(
        &self,
        data: &[u8],
        identity: &Identity,
    ) -> Result<(Vec<u8>, &Group), ConnectionError>;
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
        destination: &SocketAddr,
    ) -> Result<Vec<u8>, ConnectionError>;
}

pub trait FrameIndexEncryptor
{
    fn encrypt_with_index(
        &self,
        data: &[u8],
        index: u32,
        max_payload: usize,
        destination: &SocketAddr,
    ) -> Result<Vec<u8>, ConnectionError>;
}

pub trait RelayEncryptor
{
    fn relay_header(&self, destination: &SocketAddr) -> Result<Option<Vec<u8>>, EncryptionError>;
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
        Self { groups }
    }
}

impl FrameDecryptor for GroupsEncryptor
{
    fn decrypt(
        &self,
        data: &[u8],
        identity: &Identity,
    ) -> Result<(Vec<u8>, &Group), ConnectionError>
    {
        let (message, group) = validate(data, &self.groups, identity)?;
        let bytes = decrypt(&message, identity, group)?;
        Ok((bytes, group))
    }

    fn decrypt_to_frame(
        &self,
        data: &[u8],
        identity: &Identity,
    ) -> Result<(Frame, &Group), ConnectionError>
    {
        let (bytes, group) = self.decrypt(data, identity)?;
        let frame: Frame = bincode::deserialize(&bytes)
            .map_err(|err| ConnectionError::InvalidBuffer((*err).to_string()))?;
        Ok((frame, group))
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
        destination: &SocketAddr,
    ) -> Result<Vec<u8>, ConnectionError>
    {
        let bytes = encrypt_group_to_bytes(data, identity, group, message_type, destination)?;
        Ok(bytes)
    }
}

impl IdentityVerifier for GroupsEncryptor
{
    fn verify(&self, identity: &Identity) -> Option<&Group>
    {
        self.groups.iter().find_map(|(_, g)| {
            identity_matching_hosts(
                &g.allowed_hosts,
                identity,
                &g.relay.as_ref().map(|r| r.host.clone()),
            )
            .then(|| g)
        })
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
        Self { group, identity }
    }
}

impl FrameEncryptor for IdentityEncryptor
{
    fn encrypt(
        &self,
        data: Vec<u8>,
        message_type: &MessageType,
        destination: &SocketAddr,
    ) -> Result<Vec<u8>, ConnectionError>
    {
        let bytes = encrypt_group_to_bytes(
            &data,
            &self.identity,
            &self.group,
            message_type,
            destination,
        )?;
        Ok(bytes)
    }
}

impl RelayEncryptor for IdentityEncryptor
{
    fn relay_header(&self, destination: &SocketAddr) -> Result<Option<Vec<u8>>, EncryptionError>
    {
        relay_header(&self.group, destination)
    }
}

impl FrameIndexEncryptor for IdentityEncryptor
{
    fn encrypt_with_index(
        &self,
        data: &[u8],
        index: u32,
        max_payload: usize,
        destination: &SocketAddr,
    ) -> Result<Vec<u8>, ConnectionError>
    {
        let frame = data_to_frame(index as u32, data, max_payload)?;
        let bytes = encrypt_group_to_bytes(
            &frame,
            &self.identity,
            &self.group,
            &MessageType::Frame,
            destination,
        )?;
        Ok(bytes)
    }
}

impl FrameDataDecryptor for IdentityEncryptor
{
    fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>, ConnectionError>
    {
        let groups = indexmap! { self.group.name.clone() => self.group.clone() };
        let (message, group) = validate(data, &groups, &self.identity)?;
        let bytes = decrypt(&message, &self.identity, group)?;
        Ok(bytes)
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
        index,
        total: indexes as u16,
        data: data[from..to].to_vec(),
    };

    let bytes = bincode::serialize(&frame)
        .map_err(|err| ConnectionError::InvalidBuffer((*err).to_string()))?;
    Ok(bytes)
}

pub fn size_to_indexes(size: usize, max_payload: usize) -> usize
{
    let reminder = if size % max_payload > 0 { 1 } else { 0 };
    (size / max_payload) + reminder
}

#[cfg(test)]
pub struct NoRelayEncryptor {}

#[cfg(test)]
impl RelayEncryptor for NoRelayEncryptor
{
    fn relay_header(&self, _: &SocketAddr) -> Result<Option<Vec<u8>>, EncryptionError>
    {
        Ok(None)
    }
}
