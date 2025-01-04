use bytes::Bytes;
use indexmap::IndexMap;
use std::net::SocketAddr;

use crate::encryption::{decrypt, encrypt_group_to_bytes, serialize_to_bytes};
use crate::errors::EncryptionError;
use crate::identity::{identity_matching_hosts, retrieve_identity, Identity, IdentityVerifier};
use crate::message::{GroupName, MessageType, SendGroup};
use crate::protocols::ProtocolReadMessage;
use crate::validation::validate;

pub trait RelayEncryptor {
    fn relay_header(&self, destination: SocketAddr) -> Result<Option<Vec<u8>>, EncryptionError>;
}

pub trait MessageEncryptor {
    #[allow(async_fn_in_trait)]
    async fn encrypt_message(
        &self,
        data: Vec<u8>,
        group: &GroupName,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
        message_type: MessageType,
    ) -> Result<Bytes, EncryptionError>;
}

pub trait MessageDecryptor {
    fn decrypt_message(
        &self,
        data: Vec<u8>,
        identity: Identity,
    ) -> Result<ProtocolReadMessage, EncryptionError>;
}

pub trait MessageSerializer {
    #[allow(async_fn_in_trait)]
    async fn serialize_message(
        &self,
        data: Vec<u8>,
        group_name: GroupName,
        message_type: MessageType,
    ) -> Result<Bytes, EncryptionError>;
}

pub trait MessageDeserializer {
    fn deserialize_message(
        &self,
        data: Vec<u8>,
        identity: Identity,
    ) -> Result<ProtocolReadMessage, EncryptionError>;
}

pub struct GroupEncryptor {
    groups: IndexMap<GroupName, SendGroup>,
}

impl GroupEncryptor {
    pub fn new(groups: IndexMap<String, SendGroup>) -> Self {
        Self { groups }
    }
}

impl MessageEncryptor for GroupEncryptor {
    async fn encrypt_message(
        &self,
        data: Vec<u8>,
        group_name: &GroupName,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
        message_type: MessageType,
    ) -> Result<Bytes, EncryptionError> {
        let Some(group) = self.groups.get(group_name) else {
            return Err(EncryptionError::EncryptionFailed(format!(
                "Unknown group {group_name}"
            )));
        };
        let identity = retrieve_identity(local_addr, remote_addr, group)
            .await
            .map_err(|e| {
                EncryptionError::EncryptionFailed(format!("Could not retrieve identity: {e}"))
            })?;
        let bytes = encrypt_group_to_bytes(data, identity, group, message_type, remote_addr)?;
        Ok(bytes)
    }
}

impl MessageSerializer for GroupEncryptor {
    async fn serialize_message(
        &self,
        data: Vec<u8>,
        group_name: GroupName,
        message_type: MessageType,
    ) -> Result<Bytes, EncryptionError> {
        let Some(_) = self.groups.get(&group_name) else {
            return Err(EncryptionError::EncryptionFailed(format!(
                "Unknown group {group_name}"
            )));
        };
        serialize_to_bytes(data, group_name, message_type)
    }
}

impl MessageDeserializer for GroupEncryptor {
    fn deserialize_message(
        &self,
        data: Vec<u8>,
        identity: Identity,
    ) -> Result<ProtocolReadMessage, EncryptionError> {
        let (message, group) = validate(data, &self.groups, identity)?;
        Ok(ProtocolReadMessage {
            group: group.name.clone(),
            message_type: message.message_type,
            remote: identity,
            data: message.data,
        })
    }
}

impl MessageDecryptor for GroupEncryptor {
    fn decrypt_message(
        &self,
        data: Vec<u8>,
        identity: Identity,
    ) -> Result<ProtocolReadMessage, EncryptionError> {
        let (mut message, group) = validate(data, &self.groups, identity)?;
        decrypt(&mut message, identity, group)?;
        Ok(ProtocolReadMessage {
            group: group.name.clone(),
            message_type: message.message_type,
            remote: identity,
            data: message.data,
        })
    }
}

impl IdentityVerifier for GroupEncryptor {
    fn verify(&self, identity: Identity) -> Option<&GroupName> {
        self.groups.iter().find_map(|(_, g)| {
            identity_matching_hosts(
                g.allowed_hosts.iter().map(|(h, _)| h),
                identity,
                &g.relay.as_ref().map(|r| r.host.clone()),
            )
            .then_some(&g.name)
        })
    }
}

pub struct NoEncryptor {
    groups: IndexMap<GroupName, SendGroup>,
}

impl NoEncryptor {
    pub fn new(groups: IndexMap<String, SendGroup>) -> Self {
        Self { groups }
    }
}

impl MessageDecryptor for NoEncryptor {
    fn decrypt_message(
        &self,
        data: Vec<u8>,
        identity: Identity,
    ) -> Result<ProtocolReadMessage, EncryptionError> {
        let (message, group) = validate(data, &self.groups, identity)?;
        Ok(ProtocolReadMessage {
            group: group.name.clone(),
            message_type: message.message_type,
            remote: identity,
            data: message.data,
        })
    }
}

impl MessageSerializer for NoEncryptor {
    async fn serialize_message(
        &self,
        data: Vec<u8>,
        group_name: GroupName,
        message_type: MessageType,
    ) -> Result<Bytes, EncryptionError> {
        let Some(_) = self.groups.get(&group_name) else {
            return Err(EncryptionError::EncryptionFailed(format!(
                "Unknown group {group_name}"
            )));
        };
        serialize_to_bytes(data, group_name, message_type).map_err(Into::into)
    }
}

impl IdentityVerifier for NoEncryptor {
    fn verify(&self, identity: Identity) -> Option<&GroupName> {
        self.groups.iter().find_map(|(_, g)| {
            identity_matching_hosts(
                g.allowed_hosts.iter().map(|(h, _)| h),
                identity,
                &g.relay.as_ref().map(|r| r.host.clone()),
            )
            .then_some(&g.name)
        })
    }
}

#[cfg(test)]
pub struct NoRelayEncryptor {}

#[cfg(test)]
impl RelayEncryptor for NoRelayEncryptor {
    fn relay_header(&self, _: SocketAddr) -> Result<Option<Vec<u8>>, EncryptionError> {
        Ok(None)
    }
}
