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
/// Type identifier for a list vaults operation.
const LIST_VAULTS: u16 = 3;
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
/// Type identifier for the read log event (remote only).
const READ_EVENT_LOG: u16 = 16;
/// Type identifier for the export vault operation.
const EXPORT_VAULT: u16 = 17;
/// Type identifier for export account archive.
const EXPORT_BACKUP_ARCHIVE: u16 = 18;
/// Type identifier for restore account archive.
const IMPORT_BACKUP_ARCHIVE: u16 = 19;
/// Type identifier for exporting unencrypted secrets.
const EXPORT_UNSAFE: u16 = 20;
/// Type identifier for importing unencrypted secrets.
const IMPORT_UNSAFE: u16 = 21;
/// Type identifier for exporting contacts.
const EXPORT_CONTACTS: u16 = 22;
/// Type identifier for importing contacts.
const IMPORT_CONTACTS: u16 = 23;
/// Type identifier for creating a file.
const CREATE_FILE: u16 = 24;
/// Type identifier for moving a file.
const MOVE_FILE: u16 = 25;
/// Type identifier for deleting a file.
const DELETE_FILE: u16 = 26;
/// Type identifier for vault event compaction.
const COMPACT_VAULT: u16 = 27;
/// Type identifier for changing a password.
const CHANGE_PASSWORD: u16 = 28;
/// Type identifier for trusting a device.
const TRUST_DEVICE: u16 = 29;
/// Type identifier for revoking a device.
const REVOKE_DEVICE: u16 = 30;
/// Type identifier for updating an identity folder.
const UPDATE_IDENTITY: u16 = 31;
/// Type identifier for renaming an account.
const RENAME_ACCOUNT: u16 = 32;

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
    /// Event to represent a sign in.
    ListVaults,
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
    /// Event to export a vault.
    ExportVault,
    /// Event to export an account archive.
    ExportBackupArchive,
    /// Event to import an account archive.
    ImportBackupArchive,
    /// Event to export unencrypted secrets.
    ExportUnsafe,
    /// Event to import unencrypted secrets.
    ImportUnsafe,
    /// Event to export contacts.
    ExportContacts,
    /// Event to import contacts.
    ImportContacts,
    /// Event for creating a file.
    CreateFile,
    /// Event for moving a file.
    MoveFile,
    /// Event for deleting a file.
    DeleteFile,
    /// Event for vault compaction.
    CompactVault,
    /// Event for changing a password.
    ChangePassword,
    /// Event for trusting a device.
    TrustDevice,
    /// Event for revoking a device.
    RevokeDevice,
    /// Event for when an identity folder is updated.
    UpdateIdentity,
    /// Event for when an account is renamed.
    RenameAccount,
}

impl Default for EventKind {
    fn default() -> Self {
        Self::Noop
    }
}

impl TryFrom<u16> for EventKind {
    type Error = Error;
    fn try_from(value: u16) -> std::result::Result<Self, Self::Error> {
        Ok(match value {
            NOOP => EventKind::Noop,
            CREATE_ACCOUNT => EventKind::CreateAccount,
            DELETE_ACCOUNT => EventKind::DeleteAccount,
            LIST_VAULTS => EventKind::ListVaults,
            CREATE_VAULT => EventKind::CreateVault,
            READ_VAULT => EventKind::ReadVault,
            UPDATE_VAULT => EventKind::UpdateVault,
            DELETE_VAULT => EventKind::DeleteVault,
            GET_VAULT_NAME => EventKind::GetVaultName,
            SET_VAULT_NAME => EventKind::SetVaultName,
            SET_VAULT_META => EventKind::SetVaultMeta,
            CREATE_SECRET => EventKind::CreateSecret,
            READ_SECRET => EventKind::ReadSecret,
            UPDATE_SECRET => EventKind::UpdateSecret,
            DELETE_SECRET => EventKind::DeleteSecret,
            MOVE_SECRET => EventKind::MoveSecret,
            READ_EVENT_LOG => EventKind::ReadEventLog,
            EXPORT_VAULT => EventKind::ExportVault,
            EXPORT_BACKUP_ARCHIVE => EventKind::ExportBackupArchive,
            IMPORT_BACKUP_ARCHIVE => EventKind::ImportBackupArchive,
            EXPORT_UNSAFE => EventKind::ExportUnsafe,
            IMPORT_UNSAFE => EventKind::ImportUnsafe,
            EXPORT_CONTACTS => EventKind::ExportContacts,
            IMPORT_CONTACTS => EventKind::ImportContacts,
            CREATE_FILE => EventKind::CreateFile,
            MOVE_FILE => EventKind::MoveFile,
            DELETE_FILE => EventKind::DeleteFile,
            COMPACT_VAULT => EventKind::CompactVault,
            CHANGE_PASSWORD => EventKind::ChangePassword,
            TRUST_DEVICE => EventKind::TrustDevice,
            REVOKE_DEVICE => EventKind::RevokeDevice,
            UPDATE_IDENTITY => EventKind::UpdateIdentity,
            RENAME_ACCOUNT => EventKind::RenameAccount,
            _ => return Err(Error::UnknownEventKind(value)),
        })
    }
}

impl From<&EventKind> for u16 {
    fn from(value: &EventKind) -> Self {
        match value {
            EventKind::Noop => NOOP,
            EventKind::CreateAccount => CREATE_ACCOUNT,
            EventKind::DeleteAccount => DELETE_ACCOUNT,
            EventKind::ListVaults => LIST_VAULTS,
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
            EventKind::ExportVault => EXPORT_VAULT,
            EventKind::ExportBackupArchive => EXPORT_BACKUP_ARCHIVE,
            EventKind::ImportBackupArchive => IMPORT_BACKUP_ARCHIVE,
            EventKind::ExportUnsafe => EXPORT_UNSAFE,
            EventKind::ImportUnsafe => IMPORT_UNSAFE,
            EventKind::ExportContacts => EXPORT_CONTACTS,
            EventKind::ImportContacts => IMPORT_CONTACTS,
            EventKind::CreateFile => CREATE_FILE,
            EventKind::MoveFile => MOVE_FILE,
            EventKind::DeleteFile => DELETE_FILE,
            EventKind::CompactVault => COMPACT_VAULT,
            EventKind::ChangePassword => CHANGE_PASSWORD,
            EventKind::TrustDevice => TRUST_DEVICE,
            EventKind::RevokeDevice => REVOKE_DEVICE,
            EventKind::UpdateIdentity => UPDATE_IDENTITY,
            EventKind::RenameAccount => RENAME_ACCOUNT,
        }
    }
}

impl From<EventKind> for u16 {
    fn from(value: EventKind) -> Self {
        (&value).into()
    }
}

impl fmt::Display for EventKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", {
            match self {
                EventKind::Noop => "NOOP",
                EventKind::CreateAccount => "CREATE_ACCOUNT",
                EventKind::DeleteAccount => "DELETE_ACCOUNT",
                EventKind::ListVaults => "LIST_FOLDERS",
                EventKind::CreateVault => "CREATE_FOLDER",
                EventKind::ReadVault => "READ_FOLDER",
                EventKind::UpdateVault => "UPDATE_FOLDER",
                EventKind::DeleteVault => "DELETE_FOLDER",
                EventKind::GetVaultName => "GET_FOLDER_NAME",
                EventKind::SetVaultName => "SET_FOLDER_NAME",
                EventKind::SetVaultMeta => "SET_FOLDER_META",
                EventKind::CreateSecret => "CREATE_SECRET",
                EventKind::ReadSecret => "READ_SECRET",
                EventKind::UpdateSecret => "UPDATE_SECRET",
                EventKind::DeleteSecret => "DELETE_SECRET",
                EventKind::MoveSecret => "MOVE_SECRET",
                EventKind::ReadEventLog => "READ_EVENT_LOG",
                EventKind::ExportVault => "EXPORT_FOLDER",
                EventKind::ExportBackupArchive => "EXPORT_BACKUP_ARCHIVE",
                EventKind::ImportBackupArchive => "IMPORT_BACKUP_ARCHIVE",
                EventKind::ExportUnsafe => "EXPORT_UNSAFE",
                EventKind::ImportUnsafe => "IMPORT_UNSAFE",
                EventKind::ExportContacts => "EXPORT_CONTACTS",
                EventKind::ImportContacts => "IMPORT_CONTACTS",
                EventKind::CreateFile => "CREATE_FILE",
                EventKind::MoveFile => "MOVE_FILE",
                EventKind::DeleteFile => "DELETE_FILE",
                EventKind::CompactVault => "COMPACT_FOLDER",
                EventKind::ChangePassword => "CHANGE_PASSWORD",
                EventKind::TrustDevice => "TRUST_DEVICE",
                EventKind::RevokeDevice => "REVOKE_DEVICE",
                EventKind::UpdateIdentity => "UPDATE_IDENTITY",
                EventKind::RenameAccount => "RENAME_ACCOUNT",
            }
        })
    }
}
