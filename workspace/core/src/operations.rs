//! Encoding of the vault operations so that local changes;
//! to an in-memory representation of a vault can be sent
//! to a remote server.
//!
//! These operations are also use to identify an action in
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
    vault::{encode, Summary},
    Error, Result,
};

/// Constants for the types of operations.
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

/// Operation wraps an operation type identifier and
/// provides a `Display` implementation used for printing
/// audit logs.
#[derive(Debug, Serialize, Deserialize)]
pub enum Operation {
    /// No operation.
    Noop,
    /// Operation to create an account.
    CreateAccount,
    /// Operation to delete an account.
    DeleteAccount,
    /// Operation to create a login challenge.
    LoginChallenge,
    /// Operation to create a login response.
    LoginResponse,
    /// Operation to create a vault.
    CreateVault,
    /// Operation to read a vault.
    ReadVault,
    /// Operation to update a vault.
    UpdateVault,
    /// Operation to get vault name.
    GetVaultName,
    /// Operation to set vault name.
    SetVaultName,
    /// Operation to set vault meta data.
    SetVaultMeta,
    /// Operation to delete a vault.
    DeleteVault,
    /// Operation to create a secret.
    CreateSecret,
    /// Operation to read a secret.
    ReadSecret,
    /// Operation to update a secret.
    UpdateSecret,
    /// Operation to delete a secret.
    DeleteSecret,
}

impl Default for Operation {
    fn default() -> Self {
        Self::Noop
    }
}

impl Encode for Operation {
    fn encode(&self, ser: &mut Serializer) -> BinaryResult<()> {
        let value: u16 = self.into();
        ser.writer.write_u16(value)?;
        Ok(())
    }
}

impl Decode for Operation {
    fn decode(&mut self, de: &mut Deserializer) -> BinaryResult<()> {
        let op = de.reader.read_u16()?;
        *self = op.try_into().map_err(|_| {
            BinaryError::Boxed(Box::from(Error::UnknownOperation(op)))
        })?;
        Ok(())
    }
}

impl TryFrom<u16> for Operation {
    type Error = Error;
    fn try_from(value: u16) -> std::result::Result<Self, Self::Error> {
        match value {
            types::NOOP => Ok(Operation::Noop),
            types::CREATE_ACCOUNT => Ok(Operation::CreateAccount),
            types::DELETE_ACCOUNT => Ok(Operation::DeleteAccount),
            types::LOGIN_CHALLENGE => Ok(Operation::LoginChallenge),
            types::LOGIN_RESPONSE => Ok(Operation::LoginResponse),
            types::CREATE_VAULT => Ok(Operation::CreateVault),
            types::READ_VAULT => Ok(Operation::ReadVault),
            types::UPDATE_VAULT => Ok(Operation::UpdateVault),
            types::DELETE_VAULT => Ok(Operation::DeleteVault),
            types::GET_VAULT_NAME => Ok(Operation::GetVaultName),
            types::SET_VAULT_NAME => Ok(Operation::SetVaultName),
            types::SET_VAULT_META => Ok(Operation::SetVaultMeta),
            types::CREATE_SECRET => Ok(Operation::CreateSecret),
            types::READ_SECRET => Ok(Operation::ReadSecret),
            types::UPDATE_SECRET => Ok(Operation::UpdateSecret),
            types::DELETE_SECRET => Ok(Operation::DeleteSecret),
            _ => Err(Error::UnknownOperation(value)),
        }
    }
}

impl From<&Operation> for u16 {
    fn from(value: &Operation) -> Self {
        match value {
            Operation::Noop => types::NOOP,
            Operation::CreateAccount => types::CREATE_ACCOUNT,
            Operation::DeleteAccount => types::DELETE_ACCOUNT,
            Operation::LoginChallenge => types::LOGIN_CHALLENGE,
            Operation::LoginResponse => types::LOGIN_RESPONSE,
            Operation::CreateVault => types::CREATE_VAULT,
            Operation::ReadVault => types::READ_VAULT,
            Operation::UpdateVault => types::UPDATE_VAULT,
            Operation::DeleteVault => types::DELETE_VAULT,
            Operation::GetVaultName => types::GET_VAULT_NAME,
            Operation::SetVaultName => types::SET_VAULT_NAME,
            Operation::SetVaultMeta => types::SET_VAULT_META,
            Operation::CreateSecret => types::CREATE_SECRET,
            Operation::ReadSecret => types::READ_SECRET,
            Operation::UpdateSecret => types::UPDATE_SECRET,
            Operation::DeleteSecret => types::DELETE_SECRET,
        }
    }
}

impl fmt::Display for Operation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", {
            match self {
                Operation::Noop => "NOOP",
                Operation::CreateAccount => "CREATE_ACCOUNT",
                Operation::DeleteAccount => "DELETE_ACCOUNT",
                Operation::LoginChallenge => "LOGIN_CHALLENGE",
                Operation::LoginResponse => "LOGIN_RESPONSE",
                Operation::CreateVault => "CREATE_VAULT",
                Operation::ReadVault => "READ_VAULT",
                Operation::UpdateVault => "UPDATE_VAULT",
                Operation::DeleteVault => "DELETE_VAULT",
                Operation::GetVaultName => "GET_VAULT_NAME",
                Operation::SetVaultName => "SET_VAULT_NAME",
                Operation::SetVaultMeta => "SET_VAULT_META",
                Operation::CreateSecret => "CREATE_SECRET",
                Operation::ReadSecret => "READ_SECRET",
                Operation::UpdateSecret => "UPDATE_SECRET",
                Operation::DeleteSecret => "DELETE_SECRET",
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
#[derive(Serialize, Deserialize)]
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
    CreateSecret(u32, SecretId, Cow<'a, (AeadPack, AeadPack)>),

    /// Payload used to determine that a secret has been read,
    /// defined for audit log purposes.
    ReadSecret(u32, SecretId),

    /// Payload used to indicate that a secret should be
    /// updated in a remote destination.
    ///
    /// The remote server must check the `change_seq` to
    /// determine if the change could be safely applied.
    UpdateSecret(u32, SecretId, Cow<'a, (AeadPack, AeadPack)>),

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
    pub fn operation(&self) -> Operation {
        match self {
            Payload::CreateVault => Operation::CreateVault,
            Payload::ReadVault(_) => Operation::ReadVault,
            Payload::UpdateVault(_) => Operation::UpdateVault,
            Payload::DeleteVault(_) => Operation::DeleteVault,
            Payload::GetVaultName(_) => Operation::GetVaultName,
            Payload::SetVaultName(_, _) => Operation::SetVaultName,
            Payload::SetVaultMeta(_, _) => Operation::SetVaultMeta,
            Payload::CreateSecret(_, _, _) => Operation::CreateSecret,
            Payload::ReadSecret(_, _) => Operation::ReadSecret,
            Payload::UpdateSecret(_, _, _) => Operation::UpdateSecret,
            Payload::DeleteSecret(_, _) => Operation::DeleteSecret,
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
                let (meta_aead, secret_aead) = value.as_ref();
                ser.writer.write_u32(*change_seq)?;
                uuid.serialize(&mut *ser)?;
                meta_aead.encode(&mut *ser)?;
                secret_aead.encode(&mut *ser)?;
            }
            Payload::ReadSecret(change_seq, uuid) => {
                ser.writer.write_u32(*change_seq)?;
                uuid.serialize(&mut *ser)?;
            }
            Payload::UpdateSecret(change_seq, uuid, value) => {
                let (meta_aead, secret_aead) = value.as_ref();
                ser.writer.write_u32(*change_seq)?;
                uuid.serialize(&mut *ser)?;
                meta_aead.encode(&mut *ser)?;
                secret_aead.encode(&mut *ser)?;
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
        let mut op: Operation = Default::default();
        op.decode(&mut *de)?;
        match op {
            Operation::CreateVault => {}
            Operation::ReadVault => {
                let change_seq = de.reader.read_u32()?;
                *self = Payload::ReadVault(change_seq);
            }
            Operation::UpdateVault => {
                let change_seq = de.reader.read_u32()?;
                *self = Payload::UpdateVault(change_seq);
            }
            Operation::DeleteVault => {
                let change_seq = de.reader.read_u32()?;
                *self = Payload::DeleteVault(change_seq);
            }
            Operation::GetVaultName => {
                let change_seq = de.reader.read_u32()?;
                *self = Payload::GetVaultName(change_seq);
            }
            Operation::SetVaultName => {
                let change_seq = de.reader.read_u32()?;
                let name = de.reader.read_string()?;
                *self = Payload::SetVaultName(change_seq, Cow::Owned(name));
            }
            Operation::SetVaultMeta => {
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
            Operation::CreateSecret => {
                let change_seq = de.reader.read_u32()?;
                let id: SecretId = Deserialize::deserialize(&mut *de)?;
                let mut meta_aead: AeadPack = Default::default();
                meta_aead.decode(&mut *de)?;
                let mut secret_aead: AeadPack = Default::default();
                secret_aead.decode(&mut *de)?;
                *self = Payload::CreateSecret(
                    change_seq,
                    id,
                    Cow::Owned((meta_aead, secret_aead)),
                );
            }
            Operation::ReadSecret => {
                let change_seq = de.reader.read_u32()?;
                let id: SecretId = Deserialize::deserialize(&mut *de)?;
                *self = Payload::ReadSecret(change_seq, id);
            }
            Operation::UpdateSecret => {
                let change_seq = de.reader.read_u32()?;
                let id: SecretId = Deserialize::deserialize(&mut *de)?;
                let mut meta_aead: AeadPack = Default::default();
                meta_aead.decode(&mut *de)?;
                let mut secret_aead: AeadPack = Default::default();
                secret_aead.decode(&mut *de)?;
                *self = Payload::UpdateSecret(
                    change_seq,
                    id,
                    Cow::Owned((meta_aead, secret_aead)),
                );
            }
            Operation::DeleteSecret => {
                let change_seq = de.reader.read_u32()?;
                let id: SecretId = Deserialize::deserialize(&mut *de)?;
                *self = Payload::DeleteSecret(change_seq, id);
            }
            _ => {
                return Err(BinaryError::Boxed(Box::from(
                    Error::UnknownPayloadOperation(op),
                )))
            }
        }
        Ok(())
    }
}
