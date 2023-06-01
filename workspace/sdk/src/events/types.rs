//! Event types for audit and log events.

use crate::Error;
use serde::{Deserialize, Serialize};

use std::fmt;

/// Type identifier for a noop.
const NOOP: u16 = 0;
/// Type identifier for the create account operation.
const CREATE_ACCOUNT: u16 = 1;
/// Type identifier for the delete account operation.
const DELETE_ACCOUNT: u16 = 2;
/// Type identifier for the login response operation.
#[deprecated]
const LOGIN_RESPONSE: u16 = 3;
/// Type identifier for the create vault operation.
const CREATE_VAULT: u16 = 4;
/// Type identifier for the read vault operation.
const READ_VAULT: u16 = 5;
/// Type identifier for the update vault operation.
const UPDATE_VAULT: u16 = 6;
/// Type identifier for the delete vault operation.
const DELETE_VAULT: u16 = 7;
/// Type identifier for the get vault name operation.
const GET_VAULT_NAME: u16 = 8;
/// Type identifier for the set vault name operation.
const SET_VAULT_NAME: u16 = 9;
/// Type identifier for the set vault meta operation.
const SET_VAULT_META: u16 = 10;
/// Type identifier for the create secret operation.
const CREATE_SECRET: u16 = 11;
/// Type identifier for the read secret operation.
const READ_SECRET: u16 = 12;
/// Type identifier for the update secret operation.
const UPDATE_SECRET: u16 = 13;
/// Type identifier for the delete secret operation.
const DELETE_SECRET: u16 = 14;
/// Type identifier for the move secret operation.
const MOVE_SECRET: u16 = 15;
/// Type identifier for the read log event.
const READ_EVENT_LOG: u16 = 16;

/// EventKind wraps an event type identifier and
/// provides a `Display` implementation.
#[derive(Debug, Serialize, Deserialize, Copy, Clone, Eq, PartialEq)]
pub enum EventKind {
    /// No operation.
    Noop,
    /// Event to create an account.
    CreateAccount,
    /// Event to delete an account.
    DeleteAccount,
    /// Event to create a login response.
    LoginResponse,
    /// Event to create a vault.
    CreateVault,
    /// Event to read a vault.
    ReadVault,
    /// Event to update a vault.
    UpdateVault,
    /// Event to get vault name.
    GetVaultName,
    /// Event to set vault name.
    SetVaultName,
    /// Event to set vault meta data.
    SetVaultMeta,
    /// Event to delete a vault.
    DeleteVault,
    /// Event to create a secret.
    CreateSecret,
    /// Event to read a secret.
    ReadSecret,
    /// Event to update a secret.
    UpdateSecret,
    /// Event to delete a secret.
    DeleteSecret,
    /// Event to move a secret.
    MoveSecret,
    /// Event to read a log.
    ReadEventLog,
}

impl Default for EventKind {
    fn default() -> Self {
        Self::Noop
    }
}

impl TryFrom<u16> for EventKind {
    type Error = Error;
    fn try_from(value: u16) -> std::result::Result<Self, Self::Error> {
        match value {
            NOOP => Ok(EventKind::Noop),
            CREATE_ACCOUNT => Ok(EventKind::CreateAccount),
            DELETE_ACCOUNT => Ok(EventKind::DeleteAccount),
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
            MOVE_SECRET => Ok(EventKind::MoveSecret),
            READ_EVENT_LOG => Ok(EventKind::ReadEventLog),
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
            EventKind::MoveSecret => MOVE_SECRET,
            EventKind::ReadEventLog => READ_EVENT_LOG,
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
                EventKind::MoveSecret => "MOVE_SECRET",
                EventKind::ReadEventLog => "READ_EVENT_LOG",
            }
        })
    }
}
