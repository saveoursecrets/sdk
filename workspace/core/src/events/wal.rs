//! Event that can be stored in a write-ahead log.
//!
//! The variants in this type represent a subset of
//! the SyncEvent that are allowed in a write-ahead log.

use serde::{Deserialize, Serialize};
use serde_binary::{
    Decode, Deserializer, Encode, Error as BinaryError,
    Result as BinaryResult, Serializer,
};
use std::borrow::Cow;

use crate::{crypto::AeadPack, secret::SecretId, vault::VaultCommit, Error};

use super::{EventKind, SyncEvent};

/// Write ahead log event.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum WalEvent<'a> {
    /// Variant used for the Default implementation.
    Noop,

    /// Create a new vault.
    CreateVault(Cow<'a, [u8]>),

    /// Update the vault buffer.
    UpdateVault(Cow<'a, [u8]>),

    /// Set the vault name.
    SetVaultName(Cow<'a, str>),

    /// Set the vault meta data.
    SetVaultMeta(Cow<'a, Option<AeadPack>>),

    /// Create a secret.
    CreateSecret(SecretId, Cow<'a, VaultCommit>),

    /// Update a secret.
    UpdateSecret(SecretId, Cow<'a, VaultCommit>),

    /// Delete a secret.
    DeleteSecret(SecretId),
}

impl Default for WalEvent<'_> {
    fn default() -> Self {
        WalEvent::Noop
    }
}

impl WalEvent<'_> {
    /// Get the event kind for this event.
    fn event_kind(&self) -> EventKind {
        match self {
            WalEvent::Noop => EventKind::Noop,
            WalEvent::CreateVault(_) => EventKind::CreateVault,
            WalEvent::UpdateVault(_) => EventKind::UpdateVault,
            WalEvent::SetVaultName(_) => EventKind::SetVaultName,
            WalEvent::SetVaultMeta(_) => EventKind::SetVaultMeta,
            WalEvent::CreateSecret(_, _) => EventKind::CreateSecret,
            WalEvent::UpdateSecret(_, _) => EventKind::UpdateSecret,
            WalEvent::DeleteSecret(_) => EventKind::DeleteSecret,
        }
    }
}

impl<'a> Encode for WalEvent<'a> {
    fn encode(&self, ser: &mut Serializer) -> BinaryResult<()> {
        let op = self.event_kind();
        op.encode(&mut *ser)?;

        match self {
            WalEvent::Noop => panic!("WalEvent: attempt to encode a noop"),
            WalEvent::CreateVault(vault) | WalEvent::UpdateVault(vault) => {
                ser.writer.write_u32(vault.as_ref().len() as u32)?;
                ser.writer.write_bytes(vault.as_ref())?;
            }
            WalEvent::SetVaultName(name) => {
                ser.writer.write_string(name)?;
            }
            WalEvent::SetVaultMeta(meta) => {
                ser.writer.write_bool(meta.is_some())?;
                if let Some(meta) = meta.as_ref() {
                    meta.encode(&mut *ser)?;
                }
            }
            WalEvent::CreateSecret(uuid, value) => {
                uuid.serialize(&mut *ser)?;
                value.as_ref().encode(&mut *ser)?;
            }
            WalEvent::UpdateSecret(uuid, value) => {
                uuid.serialize(&mut *ser)?;
                value.as_ref().encode(&mut *ser)?;
            }
            WalEvent::DeleteSecret(uuid) => {
                uuid.serialize(&mut *ser)?;
            }
        }
        Ok(())
    }
}

impl<'a> Decode for WalEvent<'a> {
    fn decode(&mut self, de: &mut Deserializer) -> BinaryResult<()> {
        let mut op: EventKind = Default::default();
        op.decode(&mut *de)?;
        match op {
            EventKind::Noop => panic!("WalEvent: attempt to decode a noop"),
            EventKind::CreateVault => {
                let length = de.reader.read_u32()?;
                let buffer = de.reader.read_bytes(length as usize)?;
                *self = WalEvent::CreateVault(Cow::Owned(buffer));
            }
            EventKind::UpdateVault => {
                let length = de.reader.read_u32()?;
                let buffer = de.reader.read_bytes(length as usize)?;
                *self = WalEvent::UpdateVault(Cow::Owned(buffer));
            }

            EventKind::SetVaultName => {
                let name = de.reader.read_string()?;
                *self = WalEvent::SetVaultName(Cow::Owned(name));
            }
            EventKind::SetVaultMeta => {
                let has_meta = de.reader.read_bool()?;
                let aead_pack = if has_meta {
                    let mut aead_pack: AeadPack = Default::default();
                    aead_pack.decode(&mut *de)?;
                    Some(aead_pack)
                } else {
                    None
                };
                *self = WalEvent::SetVaultMeta(Cow::Owned(aead_pack));
            }
            EventKind::CreateSecret => {
                let id: SecretId = Deserialize::deserialize(&mut *de)?;
                let mut commit: VaultCommit = Default::default();
                commit.decode(&mut *de)?;
                *self = WalEvent::CreateSecret(id, Cow::Owned(commit));
            }
            EventKind::UpdateSecret => {
                let id: SecretId = Deserialize::deserialize(&mut *de)?;
                let mut commit: VaultCommit = Default::default();
                commit.decode(&mut *de)?;
                *self = WalEvent::UpdateSecret(id, Cow::Owned(commit));
            }
            EventKind::DeleteSecret => {
                let id: SecretId = Deserialize::deserialize(&mut *de)?;
                *self = WalEvent::DeleteSecret(id);
            }
            _ => {
                return Err(BinaryError::Boxed(Box::from(
                    Error::UnknownEventKind((&op).into()),
                )))
            }
        }
        Ok(())
    }
}

impl<'a> TryFrom<SyncEvent<'a>> for WalEvent<'a> {
    type Error = Error;
    fn try_from(value: SyncEvent<'a>) -> Result<Self, Self::Error> {
        match value {
            SyncEvent::CreateVault(value) => {
                Ok(WalEvent::CreateVault(value.clone()))
            }
            SyncEvent::UpdateVault(value) => {
                Ok(WalEvent::UpdateVault(value.clone()))
            }
            SyncEvent::SetVaultName(name) => {
                Ok(WalEvent::SetVaultName(name.clone()))
            }
            SyncEvent::SetVaultMeta(meta) => {
                Ok(WalEvent::SetVaultMeta(meta.clone()))
            }
            SyncEvent::CreateSecret(id, value) => {
                Ok(WalEvent::CreateSecret(id, value.clone()))
            }
            SyncEvent::UpdateSecret(id, value) => {
                Ok(WalEvent::UpdateSecret(id, value.clone()))
            }
            SyncEvent::DeleteSecret(id) => Ok(WalEvent::DeleteSecret(id)),
            _ => Err(Error::SyncWalConvert),
        }
    }
}
