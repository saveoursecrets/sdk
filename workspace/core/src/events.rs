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
use std::{borrow::Cow, fmt};
use uuid::Uuid;

use crate::{
    address::AddressStr,
    audit::{Log, LogData},
    crypto::AeadPack,
    secret::SecretId,
    signer::Signer,
    vault::{encode, SecretCommit},
    Error, Result,
};

/// Constants for the types of events.
mod types {
    /// Type identifier for a noop.
    pub const NOOP: u16 = 0x0;
    /// Type identifier for the create account operation.
    pub const CREATE_ACCOUNT: u16 = 0x01;
    /// Type identifier for the delete account operation.
    pub const DELETE_ACCOUNT: u16 = 0x02;
    /// Type identifier for the login challenge operation.
    pub const LOGIN_CHALLENGE: u16 = 0x03;
    /// Type identifier for the login response operation.
    pub const LOGIN_RESPONSE: u16 = 0x04;
    /// Type identifier for the create vault operation.
    pub const CREATE_VAULT: u16 = 0x05;
    /// Type identifier for the read vault operation.
    pub const READ_VAULT: u16 = 0x06;
    /// Type identifier for the update vault operation.
    pub const UPDATE_VAULT: u16 = 0x07;
    /// Type identifier for the delete vault operation.
    pub const DELETE_VAULT: u16 = 0x08;
    /// Type identifier for the get vault name operation.
    pub const GET_VAULT_NAME: u16 = 0x09;
    /// Type identifier for the set vault name operation.
    pub const SET_VAULT_NAME: u16 = 0x0A;
    /// Type identifier for the set vault meta operation.
    pub const SET_VAULT_META: u16 = 0x0B;
    /// Type identifier for the create secret operation.
    pub const CREATE_SECRET: u16 = 0x0C;
    /// Type identifier for the read secret operation.
    pub const READ_SECRET: u16 = 0x0D;
    /// Type identifier for the update secret operation.
    pub const UPDATE_SECRET: u16 = 0x0E;
    /// Type identifier for the delete secret operation.
    pub const DELETE_SECRET: u16 = 0x0F;
}

/// EventKind wraps an operation type identifier and
/// provides a `Display` implementation used for printing
/// audit logs.
#[derive(Debug, Serialize, Deserialize)]
pub enum EventKind {
    /// No operation.
    Noop,
    /// EventKind to create an account.
    CreateAccount,
    /// EventKind to delete an account.
    DeleteAccount,
    /// EventKind to create a login challenge.
    LoginChallenge,
    /// EventKind to create a login response.
    LoginResponse,
    /// EventKind to create a vault.
    CreateVault,
    /// EventKind to read a vault.
    ReadVault,
    /// EventKind to update a vault.
    UpdateVault,
    /// EventKind to get vault name.
    GetVaultName,
    /// EventKind to set vault name.
    SetVaultName,
    /// EventKind to set vault meta data.
    SetVaultMeta,
    /// EventKind to delete a vault.
    DeleteVault,
    /// EventKind to create a secret.
    CreateSecret,
    /// EventKind to read a secret.
    ReadSecret,
    /// EventKind to update a secret.
    UpdateSecret,
    /// EventKind to delete a secret.
    DeleteSecret,
}

impl Default for EventKind {
    fn default() -> Self {
        Self::Noop
    }
}

impl Encode for EventKind {
    fn encode(&self, ser: &mut Serializer) -> BinaryResult<()> {
        let value: u16 = self.into();
        ser.writer.write_u16(value)?;
        Ok(())
    }
}

impl Decode for EventKind {
    fn decode(&mut self, de: &mut Deserializer) -> BinaryResult<()> {
        let op = de.reader.read_u16()?;
        *self = op.try_into().map_err(|_| {
            BinaryError::Boxed(Box::from(Error::UnknownEventKind(op)))
        })?;
        Ok(())
    }
}

impl TryFrom<u16> for EventKind {
    type Error = Error;
    fn try_from(value: u16) -> std::result::Result<Self, Self::Error> {
        match value {
            types::NOOP => Ok(EventKind::Noop),
            types::CREATE_ACCOUNT => Ok(EventKind::CreateAccount),
            types::DELETE_ACCOUNT => Ok(EventKind::DeleteAccount),
            types::LOGIN_CHALLENGE => Ok(EventKind::LoginChallenge),
            types::LOGIN_RESPONSE => Ok(EventKind::LoginResponse),
            types::CREATE_VAULT => Ok(EventKind::CreateVault),
            types::READ_VAULT => Ok(EventKind::ReadVault),
            types::UPDATE_VAULT => Ok(EventKind::UpdateVault),
            types::DELETE_VAULT => Ok(EventKind::DeleteVault),
            types::GET_VAULT_NAME => Ok(EventKind::GetVaultName),
            types::SET_VAULT_NAME => Ok(EventKind::SetVaultName),
            types::SET_VAULT_META => Ok(EventKind::SetVaultMeta),
            types::CREATE_SECRET => Ok(EventKind::CreateSecret),
            types::READ_SECRET => Ok(EventKind::ReadSecret),
            types::UPDATE_SECRET => Ok(EventKind::UpdateSecret),
            types::DELETE_SECRET => Ok(EventKind::DeleteSecret),
            _ => Err(Error::UnknownEventKind(value)),
        }
    }
}

impl From<&EventKind> for u16 {
    fn from(value: &EventKind) -> Self {
        match value {
            EventKind::Noop => types::NOOP,
            EventKind::CreateAccount => types::CREATE_ACCOUNT,
            EventKind::DeleteAccount => types::DELETE_ACCOUNT,
            EventKind::LoginChallenge => types::LOGIN_CHALLENGE,
            EventKind::LoginResponse => types::LOGIN_RESPONSE,
            EventKind::CreateVault => types::CREATE_VAULT,
            EventKind::ReadVault => types::READ_VAULT,
            EventKind::UpdateVault => types::UPDATE_VAULT,
            EventKind::DeleteVault => types::DELETE_VAULT,
            EventKind::GetVaultName => types::GET_VAULT_NAME,
            EventKind::SetVaultName => types::SET_VAULT_NAME,
            EventKind::SetVaultMeta => types::SET_VAULT_META,
            EventKind::CreateSecret => types::CREATE_SECRET,
            EventKind::ReadSecret => types::READ_SECRET,
            EventKind::UpdateSecret => types::UPDATE_SECRET,
            EventKind::DeleteSecret => types::DELETE_SECRET,
        }
    }
}

impl fmt::Display for EventKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", {
            match self {
                EventKind::Noop => "NOOP",
                EventKind::CreateAccount => "CREATE_ACCOUNT",
                EventKind::DeleteAccount => "DELETE_ACCOUNT",
                EventKind::LoginChallenge => "LOGIN_CHALLENGE",
                EventKind::LoginResponse => "LOGIN_RESPONSE",
                EventKind::CreateVault => "CREATE_VAULT",
                EventKind::ReadVault => "READ_VAULT",
                EventKind::UpdateVault => "UPDATE_VAULT",
                EventKind::DeleteVault => "DELETE_VAULT",
                EventKind::GetVaultName => "GET_VAULT_NAME",
                EventKind::SetVaultName => "SET_VAULT_NAME",
                EventKind::SetVaultMeta => "SET_VAULT_META",
                EventKind::CreateSecret => "CREATE_SECRET",
                EventKind::ReadSecret => "READ_SECRET",
                EventKind::UpdateSecret => "UPDATE_SECRET",
                EventKind::DeleteSecret => "DELETE_SECRET",
            }
        })
    }
}

/// Payload sent to a remote server.
///
/// When a payload is created on the client then we
/// can borrow the underlying data but when we need
/// it on the server side to make changes to a vault
/// we should decode to owned data hence the use of `Cow`
/// to distinguish between borrowed and owned.
#[derive(Serialize, Deserialize, Clone)]
pub enum Payload<'a> {
    /// Payload used to indicate a vault was created.
    CreateVault,

    /// Payload used to indicate that a vault was read.
    ReadVault(u32),

    /// Payload used to indicate that a vault was updated.
    UpdateVault(u32),

    /// Payload used to indicate a vault was deleted.
    DeleteVault(u32),

    /// Get the vault name.
    GetVaultName(u32),

    /// Set the vault name.
    SetVaultName(u32, Cow<'a, str>),

    /// Set the vault meta data.
    SetVaultMeta(u32, Cow<'a, Option<AeadPack>>),

    /// Payload used to indicate that a secret should be
    /// created in a remote destination.
    ///
    /// The remote server must check the `change_seq` to
    /// determine if the change could be safely applied.
    CreateSecret(u32, SecretId, Cow<'a, SecretCommit>),

    /// Payload used to determine that a secret has been read,
    /// defined for audit log purposes.
    ReadSecret(u32, SecretId),

    /// Payload used to indicate that a secret should be
    /// updated in a remote destination.
    ///
    /// The remote server must check the `change_seq` to
    /// determine if the change could be safely applied.
    UpdateSecret(u32, SecretId, Cow<'a, SecretCommit>),

    /// Delete a secret.
    DeleteSecret(u32, SecretId),
}

impl Default for Payload<'_> {
    fn default() -> Self {
        Self::CreateVault
    }
}

/// Payload with an attached signature.
pub struct SignedPayload([u8; 65], Vec<u8>);

impl<'a> Payload<'a> {
    /// Append a signature to a payload.
    pub async fn sign(&self, signer: impl Signer) -> Result<SignedPayload> {
        let encoded = encode(self)?;
        let signature = signer.sign(&encoded).await?;
        let signature_bytes: [u8; 65] = signature.to_bytes();
        Ok(SignedPayload(signature_bytes, encoded))
    }

    /// Determine if this payload would mutate state.
    ///
    /// Some payloads are purely for auditing and do not
    /// mutate any data.
    pub fn is_mutation(&self) -> bool {
        match self {
            Self::ReadVault(_) => false,
            Self::ReadSecret(_, _) => false,
            Self::GetVaultName(_) => false,
            _ => true,
        }
    }

    /// Get the change sequence for this payload.
    pub fn change_seq(&self) -> Option<&u32> {
        match self {
            Self::CreateVault => Some(&0),
            Self::ReadVault(change_seq) => Some(change_seq),
            Self::UpdateVault(change_seq) => Some(change_seq),
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

    /// Get the operation corresponding to this payload.
    pub fn operation(&self) -> EventKind {
        match self {
            Payload::CreateVault => EventKind::CreateVault,
            Payload::ReadVault(_) => EventKind::ReadVault,
            Payload::UpdateVault(_) => EventKind::UpdateVault,
            Payload::DeleteVault(_) => EventKind::DeleteVault,
            Payload::GetVaultName(_) => EventKind::GetVaultName,
            Payload::SetVaultName(_, _) => EventKind::SetVaultName,
            Payload::SetVaultMeta(_, _) => EventKind::SetVaultMeta,
            Payload::CreateSecret(_, _, _) => EventKind::CreateSecret,
            Payload::ReadSecret(_, _) => EventKind::ReadSecret,
            Payload::UpdateSecret(_, _, _) => EventKind::UpdateSecret,
            Payload::DeleteSecret(_, _) => EventKind::DeleteSecret,
        }
    }

    /// Convert this payload into an audit log.
    pub fn into_audit_log(&self, address: AddressStr, vault_id: Uuid) -> Log {
        let log_data = match self {
            Payload::CreateVault
            | Payload::ReadVault(_)
            | Payload::DeleteVault(_)
            | Payload::UpdateVault(_)
            | Payload::GetVaultName(_)
            | Payload::SetVaultName(_, _)
            | Payload::SetVaultMeta(_, _) => LogData::Vault(vault_id),
            Payload::CreateSecret(_, secret_id, _) => {
                LogData::Secret(vault_id, *secret_id)
            }
            Payload::ReadSecret(_, secret_id) => {
                LogData::Secret(vault_id, *secret_id)
            }
            Payload::UpdateSecret(_, secret_id, _) => {
                LogData::Secret(vault_id, *secret_id)
            }
            Payload::DeleteSecret(_, secret_id) => {
                LogData::Secret(vault_id, *secret_id)
            }
        };
        Log::new(self.operation(), address, Some(log_data))
    }
}

impl<'a> Encode for Payload<'a> {
    fn encode(&self, ser: &mut Serializer) -> BinaryResult<()> {
        let op = self.operation();
        op.encode(&mut *ser)?;

        match self {
            Payload::CreateVault => {}
            Payload::ReadVault(change_seq)
            | Payload::UpdateVault(change_seq)
            | Payload::DeleteVault(change_seq)
            | Payload::GetVaultName(change_seq) => {
                ser.writer.write_u32(*change_seq)?;
            }
            Payload::SetVaultName(change_seq, name) => {
                ser.writer.write_u32(*change_seq)?;
                ser.writer.write_string(name)?;
            }
            Payload::SetVaultMeta(change_seq, meta) => {
                ser.writer.write_u32(*change_seq)?;
                ser.writer.write_bool(meta.is_some())?;
                if let Some(meta) = meta.as_ref() {
                    meta.encode(&mut *ser)?;
                }
            }
            Payload::CreateSecret(change_seq, uuid, value) => {
                //let (meta_aead, secret_aead) = value.as_ref();
                ser.writer.write_u32(*change_seq)?;
                uuid.serialize(&mut *ser)?;
                value.as_ref().encode(&mut *ser)?;

                /*
                meta_aead.encode(&mut *ser)?;
                secret_aead.encode(&mut *ser)?;
                */
            }
            Payload::ReadSecret(change_seq, uuid) => {
                ser.writer.write_u32(*change_seq)?;
                uuid.serialize(&mut *ser)?;
            }
            Payload::UpdateSecret(change_seq, uuid, value) => {
                //let (meta_aead, secret_aead) = value.as_ref();
                ser.writer.write_u32(*change_seq)?;
                uuid.serialize(&mut *ser)?;
                value.as_ref().encode(&mut *ser)?;

                /*
                meta_aead.encode(&mut *ser)?;
                secret_aead.encode(&mut *ser)?;
                */
            }
            Payload::DeleteSecret(change_seq, uuid) => {
                ser.writer.write_u32(*change_seq)?;
                uuid.serialize(&mut *ser)?;
            }
        }
        Ok(())
    }
}

impl<'a> Decode for Payload<'a> {
    fn decode(&mut self, de: &mut Deserializer) -> BinaryResult<()> {
        let mut op: EventKind = Default::default();
        op.decode(&mut *de)?;
        match op {
            EventKind::CreateVault => {}
            EventKind::ReadVault => {
                let change_seq = de.reader.read_u32()?;
                *self = Payload::ReadVault(change_seq);
            }
            EventKind::UpdateVault => {
                let change_seq = de.reader.read_u32()?;
                *self = Payload::UpdateVault(change_seq);
            }
            EventKind::DeleteVault => {
                let change_seq = de.reader.read_u32()?;
                *self = Payload::DeleteVault(change_seq);
            }
            EventKind::GetVaultName => {
                let change_seq = de.reader.read_u32()?;
                *self = Payload::GetVaultName(change_seq);
            }
            EventKind::SetVaultName => {
                let change_seq = de.reader.read_u32()?;
                let name = de.reader.read_string()?;
                *self = Payload::SetVaultName(change_seq, Cow::Owned(name));
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
                *self =
                    Payload::SetVaultMeta(change_seq, Cow::Owned(aead_pack));
            }
            EventKind::CreateSecret => {
                let change_seq = de.reader.read_u32()?;
                let id: SecretId = Deserialize::deserialize(&mut *de)?;
                let mut commit: SecretCommit = Default::default();
                commit.decode(&mut *de)?;
                //let mut meta_aead: AeadPack = Default::default();
                //meta_aead.decode(&mut *de)?;
                //let mut secret_aead: AeadPack = Default::default();
                //secret_aead.decode(&mut *de)?;
                *self =
                    Payload::CreateSecret(change_seq, id, Cow::Owned(commit));
            }
            EventKind::ReadSecret => {
                let change_seq = de.reader.read_u32()?;
                let id: SecretId = Deserialize::deserialize(&mut *de)?;
                *self = Payload::ReadSecret(change_seq, id);
            }
            EventKind::UpdateSecret => {
                let change_seq = de.reader.read_u32()?;
                let id: SecretId = Deserialize::deserialize(&mut *de)?;
                let mut commit: SecretCommit = Default::default();
                commit.decode(&mut *de)?;

                //let mut meta_aead: AeadPack = Default::default();
                //meta_aead.decode(&mut *de)?;
                //let mut secret_aead: AeadPack = Default::default();
                //secret_aead.decode(&mut *de)?;
                *self =
                    Payload::UpdateSecret(change_seq, id, Cow::Owned(commit));
            }
            EventKind::DeleteSecret => {
                let change_seq = de.reader.read_u32()?;
                let id: SecretId = Deserialize::deserialize(&mut *de)?;
                *self = Payload::DeleteSecret(change_seq, id);
            }
            _ => {
                return Err(BinaryError::Boxed(Box::from(
                    Error::UnknownPayloadEventKind(op),
                )))
            }
        }
        Ok(())
    }
}
