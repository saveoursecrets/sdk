//! Constants for the type of events.

use crate::Error;
use serde::{Deserialize, Serialize};
use serde_binary::{
    Decode, Deserializer, Encode, Error as BinaryError,
    Result as BinaryResult, Serializer,
};
use std::fmt;

/// Type identifier for a noop.
pub const NOOP: u16 = 0;
/// Type identifier for the create account operation.
pub const CREATE_ACCOUNT: u16 = 1;
/// Type identifier for the delete account operation.
pub const DELETE_ACCOUNT: u16 = 2;
/// Type identifier for the login challenge operation.
pub const LOGIN_CHALLENGE: u16 = 3;
/// Type identifier for the login response operation.
pub const LOGIN_RESPONSE: u16 = 4;
/// Type identifier for the create vault operation.
pub const CREATE_VAULT: u16 = 5;
/// Type identifier for the read vault operation.
pub const READ_VAULT: u16 = 6;
/// Type identifier for the update vault operation.
pub const UPDATE_VAULT: u16 = 7;
/// Type identifier for the delete vault operation.
pub const DELETE_VAULT: u16 = 8;
/// Type identifier for the get vault name operation.
pub const GET_VAULT_NAME: u16 = 9;
/// Type identifier for the set vault name operation.
pub const SET_VAULT_NAME: u16 = 10;
/// Type identifier for the set vault meta operation.
pub const SET_VAULT_META: u16 = 11;
/// Type identifier for the create secret operation.
pub const CREATE_SECRET: u16 = 12;
/// Type identifier for the read secret operation.
pub const READ_SECRET: u16 = 13;
/// Type identifier for the update secret operation.
pub const UPDATE_SECRET: u16 = 14;
/// Type identifier for the delete secret operation.
pub const DELETE_SECRET: u16 = 15;

/// Type identifier for the read WAL operation.
pub const READ_WAL: u16 = 16;

/// EventKind wraps an event type identifier and
/// provides a `Display` implementation used for printing.
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

    /// EventKind to read a WAL log.
    ReadWal,
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
            NOOP => Ok(EventKind::Noop),
            CREATE_ACCOUNT => Ok(EventKind::CreateAccount),
            DELETE_ACCOUNT => Ok(EventKind::DeleteAccount),
            LOGIN_CHALLENGE => Ok(EventKind::LoginChallenge),
            LOGIN_RESPONSE => Ok(EventKind::LoginResponse),
            CREATE_VAULT => Ok(EventKind::CreateVault),
            READ_VAULT => Ok(EventKind::ReadVault),
            UPDATE_VAULT => Ok(EventKind::UpdateVault),
            DELETE_VAULT => Ok(EventKind::DeleteVault),
            GET_VAULT_NAME => Ok(EventKind::GetVaultName),
            SET_VAULT_NAME => Ok(EventKind::SetVaultName),
            SET_VAULT_META => Ok(EventKind::SetVaultMeta),
            CREATE_SECRET => Ok(EventKind::CreateSecret),
            READ_SECRET => Ok(EventKind::ReadSecret),
            UPDATE_SECRET => Ok(EventKind::UpdateSecret),
            DELETE_SECRET => Ok(EventKind::DeleteSecret),
            READ_WAL => Ok(EventKind::ReadWal),
            _ => Err(Error::UnknownEventKind(value)),
        }
    }
}

impl From<&EventKind> for u16 {
    fn from(value: &EventKind) -> Self {
        match value {
            EventKind::Noop => NOOP,
            EventKind::CreateAccount => CREATE_ACCOUNT,
            EventKind::DeleteAccount => DELETE_ACCOUNT,
            EventKind::LoginChallenge => LOGIN_CHALLENGE,
            EventKind::LoginResponse => LOGIN_RESPONSE,
            EventKind::CreateVault => CREATE_VAULT,
            EventKind::ReadVault => READ_VAULT,
            EventKind::UpdateVault => UPDATE_VAULT,
            EventKind::DeleteVault => DELETE_VAULT,
            EventKind::GetVaultName => GET_VAULT_NAME,
            EventKind::SetVaultName => SET_VAULT_NAME,
            EventKind::SetVaultMeta => SET_VAULT_META,
            EventKind::CreateSecret => CREATE_SECRET,
            EventKind::ReadSecret => READ_SECRET,
            EventKind::UpdateSecret => UPDATE_SECRET,
            EventKind::DeleteSecret => DELETE_SECRET,
            EventKind::ReadWal => READ_WAL,
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
                EventKind::ReadWal => "READ_WAL",
            }
        })
    }
}
