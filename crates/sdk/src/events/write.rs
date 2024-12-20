//! Folder write operations.
use crate::{
    crypto::AeadPack,
    vault::{secret::SecretId, VaultCommit, VaultFlags},
};
use serde::{Deserialize, Serialize};

use super::{EventKind, LogEvent};

/// Write operations.
#[derive(Default, Serialize, Deserialize, Debug, Clone, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
pub enum WriteEvent {
    /// Default variant, should never be used.
    ///
    /// We need a variant so we can implement the Default
    /// trait which is required for decoding.
    #[default]
    #[doc(hidden)]
    Noop,

    /// Event used to indicate a vault was created.
    ///
    /// The buffer is the initial state of the vault,
    /// if the vault contains secrets they should be
    /// separated using an [FolderReducer::split]() beforehand
    /// and appended to the event log as create secret events.
    CreateVault(#[serde(skip)] Vec<u8>),

    /// Event used to indicate the vault name was set.
    SetVaultName(String),

    /// Event used to indicate the vault flags were set.
    SetVaultFlags(VaultFlags),

    /// Event used to indicate the vault meta data was set.
    SetVaultMeta(#[serde(skip)] AeadPack),

    /// Event used to indicate a secret was created.
    CreateSecret(SecretId, #[serde(skip)] VaultCommit),

    /// Event used to indicate a secret was updated.
    UpdateSecret(SecretId, #[serde(skip)] VaultCommit),

    /// Event used to indicate a secret was deleted.
    DeleteSecret(SecretId),
}

impl LogEvent for WriteEvent {
    fn event_kind(&self) -> EventKind {
        match self {
            WriteEvent::Noop => EventKind::Noop,
            WriteEvent::CreateVault(_) => EventKind::CreateVault,
            WriteEvent::SetVaultName(_) => EventKind::SetVaultName,
            WriteEvent::SetVaultFlags(_) => EventKind::SetVaultFlags,
            WriteEvent::SetVaultMeta(_) => EventKind::SetVaultMeta,
            WriteEvent::CreateSecret(_, _) => EventKind::CreateSecret,
            WriteEvent::UpdateSecret(_, _) => EventKind::UpdateSecret,
            WriteEvent::DeleteSecret(_) => EventKind::DeleteSecret,
        }
    }
}
