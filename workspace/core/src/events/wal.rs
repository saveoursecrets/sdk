//! Event that can be stored in a write-ahead log.
//!
//! The variants in this type represent a subset of
//! the SyncEvent that are allowed in a write-ahead log.

use binary_stream::{
    BinaryError, BinaryReader, BinaryResult, BinaryWriter, Decode, Encode,
};
use serde::{Deserialize, Serialize};
use std::{borrow::Cow, cmp::Ordering};

use crate::{crypto::AeadPack, secret::SecretId, vault::VaultCommit, Error};

use super::{EventKind, SyncEvent};

/// Write ahead log event.
#[derive(Default, Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
pub enum WalEvent<'a> {
    /// Variant used for the Default implementation.
    #[default]
    Noop,

    /// Create a new vault.
    CreateVault(Cow<'a, [u8]>),

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

impl Ord for WalEvent<'_> {
    fn cmp(&self, other: &Self) -> Ordering {
        match (self, &other) {
            // NOTE: This sorting is important when we send a vault
            // NOTE: to the server and it is split into a header-only
            // NOTE: vault and WAL event records the sort order must
            // NOTE: match the client order otherwise the root hashes
            // NOTE: will be different.
            //
            // NOTE: We only care about the `CreateSecret` variant as
            // NOTE: we know in this scenario that it is the only variant
            // NOTE: in addition to the `CreateVault` start record.
            (WalEvent::CreateSecret(a, _), WalEvent::CreateSecret(b, _)) => {
                a.cmp(b)
            }
            _ => Ordering::Greater,
        }
    }
}

impl PartialOrd for WalEvent<'_> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl WalEvent<'_> {
    /// Get the event kind for this event.
    pub fn event_kind(&self) -> EventKind {
        match self {
            WalEvent::Noop => EventKind::Noop,
            WalEvent::CreateVault(_) => EventKind::CreateVault,
            WalEvent::SetVaultName(_) => EventKind::SetVaultName,
            WalEvent::SetVaultMeta(_) => EventKind::SetVaultMeta,
            WalEvent::CreateSecret(_, _) => EventKind::CreateSecret,
            WalEvent::UpdateSecret(_, _) => EventKind::UpdateSecret,
            WalEvent::DeleteSecret(_) => EventKind::DeleteSecret,
        }
    }
}

impl<'a> Encode for WalEvent<'a> {
    fn encode(&self, writer: &mut BinaryWriter) -> BinaryResult<()> {
        let op = self.event_kind();
        op.encode(&mut *writer)?;

        match self {
            WalEvent::Noop => panic!("WalEvent: attempt to encode a noop"),
            WalEvent::CreateVault(vault) => {
                writer.write_u32(vault.as_ref().len() as u32)?;
                writer.write_bytes(vault.as_ref())?;
            }
            WalEvent::SetVaultName(name) => {
                writer.write_string(name)?;
            }
            WalEvent::SetVaultMeta(meta) => {
                writer.write_bool(meta.is_some())?;
                if let Some(meta) = meta.as_ref() {
                    meta.encode(&mut *writer)?;
                }
            }
            WalEvent::CreateSecret(uuid, value) => {
                writer.write_bytes(uuid.as_bytes())?;
                value.as_ref().encode(&mut *writer)?;
            }
            WalEvent::UpdateSecret(uuid, value) => {
                writer.write_bytes(uuid.as_bytes())?;
                value.as_ref().encode(&mut *writer)?;
            }
            WalEvent::DeleteSecret(uuid) => {
                writer.write_bytes(uuid.as_bytes())?;
            }
        }
        Ok(())
    }
}

impl<'a> Decode for WalEvent<'a> {
    fn decode(&mut self, reader: &mut BinaryReader) -> BinaryResult<()> {
        let mut op: EventKind = Default::default();
        op.decode(&mut *reader)?;
        match op {
            EventKind::Noop => panic!("WalEvent: attempt to decode a noop"),
            EventKind::CreateVault => {
                let length = reader.read_u32()?;
                let buffer = reader.read_bytes(length as usize)?;
                *self = WalEvent::CreateVault(Cow::Owned(buffer));
            }
            EventKind::SetVaultName => {
                let name = reader.read_string()?;
                *self = WalEvent::SetVaultName(Cow::Owned(name));
            }
            EventKind::SetVaultMeta => {
                let has_meta = reader.read_bool()?;
                let aead_pack = if has_meta {
                    let mut aead_pack: AeadPack = Default::default();
                    aead_pack.decode(&mut *reader)?;
                    Some(aead_pack)
                } else {
                    None
                };
                *self = WalEvent::SetVaultMeta(Cow::Owned(aead_pack));
            }
            EventKind::CreateSecret => {
                let id = SecretId::from_bytes(
                    reader.read_bytes(16)?.as_slice().try_into()?,
                );
                let mut commit: VaultCommit = Default::default();
                commit.decode(&mut *reader)?;
                *self = WalEvent::CreateSecret(id, Cow::Owned(commit));
            }
            EventKind::UpdateSecret => {
                let id = SecretId::from_bytes(
                    reader.read_bytes(16)?.as_slice().try_into()?,
                );

                let mut commit: VaultCommit = Default::default();
                commit.decode(&mut *reader)?;
                *self = WalEvent::UpdateSecret(id, Cow::Owned(commit));
            }
            EventKind::DeleteSecret => {
                let id = SecretId::from_bytes(
                    reader.read_bytes(16)?.as_slice().try_into()?,
                );
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
