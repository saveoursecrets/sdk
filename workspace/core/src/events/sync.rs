//! Encoding of the vault operations so that local changes;
//! to an in-memory representation of a vault can be sent
//! to a remote server.
//!
//! These operations are also used to identify an action in
//! the audit logs.

use serde::{Deserialize, Serialize};
use serde_binary::{
    Decode, Deserializer, Encode, Error as BinaryError,
    Result as BinaryResult, Serializer,
};
use std::borrow::Cow;
use uuid::Uuid;

use crate::{
    address::AddressStr,
    crypto::AeadPack,
    secret::SecretId,
    signer::Signer,
    vault::{encode, VaultCommit},
    Error, Result,
};

use super::EventKind;

/// SyncEvent sent to a remote server.
///
/// When a payload is created on the client then we
/// can borrow the underlying data but when we need
/// it on the server side to make changes to a vault
/// we should decode to owned data hence the use of `Cow`
/// to distinguish between borrowed and owned.
#[derive(Serialize, Deserialize, Clone)]
pub enum SyncEvent<'a> {
    /// Default variant, should never be used.
    ///
    /// We need a variant so we can implement the Default
    /// trait which is required for decoding.
    Noop,

    /// SyncEvent used to indicate a vault was created.
    CreateVault(Cow<'a, [u8]>),

    /// SyncEvent used to indicate that a vault was read.
    ReadVault(u32),

    /// SyncEvent used to indicate that a vault was updated.
    UpdateVault(u32, Cow<'a, [u8]>),

    /// SyncEvent used to indicate a vault was deleted.
    DeleteVault(u32),

    /// Get the vault name.
    GetVaultName(u32),

    /// Set the vault name.
    SetVaultName(u32, Cow<'a, str>),

    /// Set the vault meta data.
    SetVaultMeta(u32, Cow<'a, Option<AeadPack>>),

    /// SyncEvent used to indicate that a secret should be
    /// created in a remote destination.
    ///
    /// The remote server must check the `change_seq` to
    /// determine if the change could be safely applied.
    CreateSecret(u32, SecretId, Cow<'a, VaultCommit>),

    /// SyncEvent used to determine that a secret has been read,
    /// defined for audit log purposes.
    ReadSecret(u32, SecretId),

    /// SyncEvent used to indicate that a secret should be
    /// updated in a remote destination.
    ///
    /// The remote server must check the `change_seq` to
    /// determine if the change could be safely applied.
    UpdateSecret(u32, SecretId, Cow<'a, VaultCommit>),

    /// Delete a secret.
    DeleteSecret(u32, SecretId),
}

impl Default for SyncEvent<'_> {
    fn default() -> Self {
        Self::Noop
    }
}

/// SyncEvent with an attached signature.
pub struct SignedSyncEvent([u8; 65], Vec<u8>);

impl SyncEvent<'_> {
    /// Append a signature to a payload.
    pub async fn sign(&self, signer: impl Signer) -> Result<SignedSyncEvent> {
        let encoded = encode(self)?;
        let signature = signer.sign(&encoded).await?;
        let signature_bytes: [u8; 65] = signature.to_bytes();
        Ok(SignedSyncEvent(signature_bytes, encoded))
    }

    /// Determine if this payload would mutate state.
    ///
    /// Some payloads are purely for auditing and do not
    /// mutate any data.
    pub fn is_mutation(&self) -> bool {
        match self {
            Self::Noop => false,
            Self::ReadVault(_) => false,
            Self::ReadSecret(_, _) => false,
            Self::GetVaultName(_) => false,
            _ => true,
        }
    }

    /// Get the change sequence for this payload.
    pub fn change_seq(&self) -> Option<&u32> {
        match self {
            Self::Noop => panic!("no change sequence for noop variant"),
            Self::CreateVault(_) => Some(&0),
            Self::ReadVault(change_seq) => Some(change_seq),
            Self::UpdateVault(change_seq, _) => Some(change_seq),
            Self::DeleteVault(change_seq) => Some(change_seq),
            Self::GetVaultName(change_seq) => Some(change_seq),
            Self::SetVaultName(change_seq, _) => Some(change_seq),
            Self::SetVaultMeta(change_seq, _) => Some(change_seq),
            Self::CreateSecret(change_seq, _, _) => Some(change_seq),
            Self::ReadSecret(change_seq, _) => Some(change_seq),
            Self::UpdateSecret(change_seq, _, _) => Some(change_seq),
            Self::DeleteSecret(change_seq, _) => Some(change_seq),
        }
    }

    /// Get the event kind for this event.
    pub fn event_kind(&self) -> EventKind {
        match self {
            SyncEvent::Noop => EventKind::Noop,
            SyncEvent::CreateVault(_) => EventKind::CreateVault,
            SyncEvent::ReadVault(_) => EventKind::ReadVault,
            SyncEvent::UpdateVault(_, _) => EventKind::UpdateVault,
            SyncEvent::DeleteVault(_) => EventKind::DeleteVault,
            SyncEvent::GetVaultName(_) => EventKind::GetVaultName,
            SyncEvent::SetVaultName(_, _) => EventKind::SetVaultName,
            SyncEvent::SetVaultMeta(_, _) => EventKind::SetVaultMeta,
            SyncEvent::CreateSecret(_, _, _) => EventKind::CreateSecret,
            SyncEvent::ReadSecret(_, _) => EventKind::ReadSecret,
            SyncEvent::UpdateSecret(_, _, _) => EventKind::UpdateSecret,
            SyncEvent::DeleteSecret(_, _) => EventKind::DeleteSecret,
        }
    }
}

impl<'a> Encode for SyncEvent<'a> {
    fn encode(&self, ser: &mut Serializer) -> BinaryResult<()> {
        let op = self.event_kind();
        op.encode(&mut *ser)?;

        match self {
            SyncEvent::Noop => panic!("SyncEvent: attempt to encode a noop"),
            SyncEvent::CreateVault(vault) => {
                ser.writer.write_u32(vault.as_ref().len() as u32)?;
                ser.writer.write_bytes(vault.as_ref())?;
            }
            SyncEvent::UpdateVault(change_seq, vault) => {
                ser.writer.write_u32(*change_seq)?;
                ser.writer.write_u32(vault.as_ref().len() as u32)?;
                ser.writer.write_bytes(vault.as_ref())?;
            }
            SyncEvent::ReadVault(change_seq)
            | SyncEvent::DeleteVault(change_seq)
            | SyncEvent::GetVaultName(change_seq) => {
                ser.writer.write_u32(*change_seq)?;
            }
            SyncEvent::SetVaultName(change_seq, name) => {
                ser.writer.write_u32(*change_seq)?;
                ser.writer.write_string(name)?;
            }
            SyncEvent::SetVaultMeta(change_seq, meta) => {
                ser.writer.write_u32(*change_seq)?;
                ser.writer.write_bool(meta.is_some())?;
                if let Some(meta) = meta.as_ref() {
                    meta.encode(&mut *ser)?;
                }
            }
            SyncEvent::CreateSecret(change_seq, uuid, value) => {
                ser.writer.write_u32(*change_seq)?;
                uuid.serialize(&mut *ser)?;
                value.as_ref().encode(&mut *ser)?;
            }
            SyncEvent::ReadSecret(change_seq, uuid) => {
                ser.writer.write_u32(*change_seq)?;
                uuid.serialize(&mut *ser)?;
            }
            SyncEvent::UpdateSecret(change_seq, uuid, value) => {
                ser.writer.write_u32(*change_seq)?;
                uuid.serialize(&mut *ser)?;
                value.as_ref().encode(&mut *ser)?;
            }
            SyncEvent::DeleteSecret(change_seq, uuid) => {
                ser.writer.write_u32(*change_seq)?;
                uuid.serialize(&mut *ser)?;
            }
        }
        Ok(())
    }
}

impl<'a> Decode for SyncEvent<'a> {
    fn decode(&mut self, de: &mut Deserializer) -> BinaryResult<()> {
        let mut op: EventKind = Default::default();
        op.decode(&mut *de)?;
        match op {
            EventKind::Noop => panic!("SyncEvent: attempt to decode a noop"),
            EventKind::CreateVault => {
                let length = de.reader.read_u32()?;
                let buffer = de.reader.read_bytes(length as usize)?;
                *self = SyncEvent::CreateVault(Cow::Owned(buffer))
            }
            EventKind::ReadVault => {
                let change_seq = de.reader.read_u32()?;
                *self = SyncEvent::ReadVault(change_seq);
            }
            EventKind::UpdateVault => {
                let change_seq = de.reader.read_u32()?;
                let length = de.reader.read_u32()?;
                let buffer = de.reader.read_bytes(length as usize)?;
                *self =
                    SyncEvent::UpdateVault(change_seq, Cow::Owned(buffer));
            }
            EventKind::DeleteVault => {
                let change_seq = de.reader.read_u32()?;
                *self = SyncEvent::DeleteVault(change_seq);
            }
            EventKind::GetVaultName => {
                let change_seq = de.reader.read_u32()?;
                *self = SyncEvent::GetVaultName(change_seq);
            }
            EventKind::SetVaultName => {
                let change_seq = de.reader.read_u32()?;
                let name = de.reader.read_string()?;
                *self = SyncEvent::SetVaultName(change_seq, Cow::Owned(name));
            }
            EventKind::SetVaultMeta => {
                let change_seq = de.reader.read_u32()?;
                let has_meta = de.reader.read_bool()?;
                let aead_pack = if has_meta {
                    let mut aead_pack: AeadPack = Default::default();
                    aead_pack.decode(&mut *de)?;
                    Some(aead_pack)
                } else {
                    None
                };
                *self = SyncEvent::SetVaultMeta(
                    change_seq,
                    Cow::Owned(aead_pack),
                );
            }
            EventKind::CreateSecret => {
                let change_seq = de.reader.read_u32()?;
                let id: SecretId = Deserialize::deserialize(&mut *de)?;
                let mut commit: VaultCommit = Default::default();
                commit.decode(&mut *de)?;
                //let mut meta_aead: AeadPack = Default::default();
                //meta_aead.decode(&mut *de)?;
                //let mut secret_aead: AeadPack = Default::default();
                //secret_aead.decode(&mut *de)?;
                *self = SyncEvent::CreateSecret(
                    change_seq,
                    id,
                    Cow::Owned(commit),
                );
            }
            EventKind::ReadSecret => {
                let change_seq = de.reader.read_u32()?;
                let id: SecretId = Deserialize::deserialize(&mut *de)?;
                *self = SyncEvent::ReadSecret(change_seq, id);
            }
            EventKind::UpdateSecret => {
                let change_seq = de.reader.read_u32()?;
                let id: SecretId = Deserialize::deserialize(&mut *de)?;
                let mut commit: VaultCommit = Default::default();
                commit.decode(&mut *de)?;

                //let mut meta_aead: AeadPack = Default::default();
                //meta_aead.decode(&mut *de)?;
                //let mut secret_aead: AeadPack = Default::default();
                //secret_aead.decode(&mut *de)?;
                *self = SyncEvent::UpdateSecret(
                    change_seq,
                    id,
                    Cow::Owned(commit),
                );
            }
            EventKind::DeleteSecret => {
                let change_seq = de.reader.read_u32()?;
                let id: SecretId = Deserialize::deserialize(&mut *de)?;
                *self = SyncEvent::DeleteSecret(change_seq, id);
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
