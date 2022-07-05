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

use crate::{
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
#[derive(Default, Debug, Serialize, Deserialize, Clone)]
pub enum SyncEvent<'a> {
    /// Default variant, should never be used.
    ///
    /// We need a variant so we can implement the Default
    /// trait which is required for decoding.
    #[default]
    Noop,

    /// SyncEvent used to indicate a vault was created.
    CreateVault(Cow<'a, [u8]>),

    /// SyncEvent used to indicate that a vault was read.
    ReadVault,

    /// SyncEvent used to indicate a vault was deleted.
    DeleteVault,

    /// Get the vault name.
    GetVaultName,

    /// Set the vault name.
    SetVaultName(Cow<'a, str>),

    /// Set the vault meta data.
    SetVaultMeta(Cow<'a, Option<AeadPack>>),

    /// SyncEvent used to indicate that a secret should be
    /// created in a remote destination.
    CreateSecret(SecretId, Cow<'a, VaultCommit>),

    /// SyncEvent used to determine that a secret has been read,
    /// defined for audit log purposes.
    ReadSecret(SecretId),

    /// SyncEvent used to indicate that a secret should be
    /// updated in a remote destination.
    UpdateSecret(SecretId, Cow<'a, VaultCommit>),

    /// Delete a secret.
    DeleteSecret(SecretId),
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
            Self::ReadVault => false,
            Self::ReadSecret(_) => false,
            Self::GetVaultName => false,
            _ => true,
        }
    }

    /// Get the event kind for this event.
    pub fn event_kind(&self) -> EventKind {
        match self {
            SyncEvent::Noop => EventKind::Noop,
            SyncEvent::CreateVault(_) => EventKind::CreateVault,
            SyncEvent::ReadVault => EventKind::ReadVault,
            SyncEvent::DeleteVault => EventKind::DeleteVault,
            SyncEvent::GetVaultName => EventKind::GetVaultName,
            SyncEvent::SetVaultName(_) => EventKind::SetVaultName,
            SyncEvent::SetVaultMeta(_) => EventKind::SetVaultMeta,
            SyncEvent::CreateSecret(_, _) => EventKind::CreateSecret,
            SyncEvent::ReadSecret(_) => EventKind::ReadSecret,
            SyncEvent::UpdateSecret(_, _) => EventKind::UpdateSecret,
            SyncEvent::DeleteSecret(_) => EventKind::DeleteSecret,
        }
    }

    /// Convert this sync event into an owned version
    /// converting any inner `Cow` values into owned data.
    ///
    /// This is required to appease the borrow checker in the
    /// shell client code.
    pub fn into_owned(self) -> SyncEvent<'static> {
        match self {
            SyncEvent::Noop => SyncEvent::Noop,
            SyncEvent::CreateVault(value) => {
                SyncEvent::CreateVault(Cow::Owned(value.into_owned()))
            }
            SyncEvent::ReadVault => SyncEvent::ReadVault,
            SyncEvent::DeleteVault => SyncEvent::DeleteVault,
            SyncEvent::GetVaultName => SyncEvent::GetVaultName,
            SyncEvent::SetVaultName(value) => {
                SyncEvent::SetVaultName(Cow::Owned(value.into_owned()))
            }
            SyncEvent::SetVaultMeta(value) => {
                SyncEvent::SetVaultMeta(Cow::Owned(value.into_owned()))
            }
            SyncEvent::CreateSecret(id, value) => {
                SyncEvent::CreateSecret(id, Cow::Owned(value.into_owned()))
            }
            SyncEvent::ReadSecret(id) => SyncEvent::ReadSecret(id),
            SyncEvent::UpdateSecret(id, value) => {
                SyncEvent::UpdateSecret(id, Cow::Owned(value.into_owned()))
            }
            SyncEvent::DeleteSecret(id) => SyncEvent::DeleteSecret(id),
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
            SyncEvent::ReadVault
            | SyncEvent::DeleteVault
            | SyncEvent::GetVaultName => {}
            SyncEvent::SetVaultName(name) => {
                ser.writer.write_string(name)?;
            }
            SyncEvent::SetVaultMeta(meta) => {
                ser.writer.write_bool(meta.is_some())?;
                if let Some(meta) = meta.as_ref() {
                    meta.encode(&mut *ser)?;
                }
            }
            SyncEvent::CreateSecret(uuid, value) => {
                uuid.serialize(&mut *ser)?;
                value.as_ref().encode(&mut *ser)?;
            }
            SyncEvent::ReadSecret(uuid) => {
                uuid.serialize(&mut *ser)?;
            }
            SyncEvent::UpdateSecret(uuid, value) => {
                uuid.serialize(&mut *ser)?;
                value.as_ref().encode(&mut *ser)?;
            }
            SyncEvent::DeleteSecret(uuid) => {
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
                *self = SyncEvent::ReadVault;
            }
            EventKind::DeleteVault => {
                *self = SyncEvent::DeleteVault;
            }
            EventKind::GetVaultName => {
                *self = SyncEvent::GetVaultName;
            }
            EventKind::SetVaultName => {
                let name = de.reader.read_string()?;
                *self = SyncEvent::SetVaultName(Cow::Owned(name));
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
                *self = SyncEvent::SetVaultMeta(Cow::Owned(aead_pack));
            }
            EventKind::CreateSecret => {
                let id: SecretId = Deserialize::deserialize(&mut *de)?;
                let mut commit: VaultCommit = Default::default();
                commit.decode(&mut *de)?;
                //let mut meta_aead: AeadPack = Default::default();
                //meta_aead.decode(&mut *de)?;
                //let mut secret_aead: AeadPack = Default::default();
                //secret_aead.decode(&mut *de)?;
                *self = SyncEvent::CreateSecret(id, Cow::Owned(commit));
            }
            EventKind::ReadSecret => {
                let id: SecretId = Deserialize::deserialize(&mut *de)?;
                *self = SyncEvent::ReadSecret(id);
            }
            EventKind::UpdateSecret => {
                let id: SecretId = Deserialize::deserialize(&mut *de)?;
                let mut commit: VaultCommit = Default::default();
                commit.decode(&mut *de)?;

                //let mut meta_aead: AeadPack = Default::default();
                //meta_aead.decode(&mut *de)?;
                //let mut secret_aead: AeadPack = Default::default();
                //secret_aead.decode(&mut *de)?;
                *self = SyncEvent::UpdateSecret(id, Cow::Owned(commit));
            }
            EventKind::DeleteSecret => {
                let id: SecretId = Deserialize::deserialize(&mut *de)?;
                *self = SyncEvent::DeleteSecret(id);
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
