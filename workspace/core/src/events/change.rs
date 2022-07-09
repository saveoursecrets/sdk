//! Events emitted over the server-sent events channel to
//! notify connected clients that changes have been made.
use serde::{Deserialize, Serialize};

use crate::{address::AddressStr, secret::SecretId, vault::VaultId};

use super::SyncEvent;

/// Encapsulates a collection of change events.
///
/// Used so that we can group multiple changes into a
/// single notification to connected clients.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ChangeNotification {
    /// The owner address.
    #[serde(skip)]
    address: AddressStr,
    /// The vault identifier.
    vault_id: VaultId,
    /// Collection of change events.
    changes: Vec<ChangeEvent>,
}

impl ChangeNotification {
    /// Create a new change notification.
    pub fn new(
        address: &AddressStr,
        vault_id: &VaultId,
        changes: Vec<ChangeEvent>,
    ) -> Self {
        Self {
            address: *address,
            vault_id: *vault_id,
            changes,
        }
    }

    /// Address of the owner that made the changes.
    pub fn address(&self) -> &AddressStr {
        &self.address
    }

    /// The identifier of the vault that was modified.
    pub fn vault_id(&self) -> &VaultId {
        &self.vault_id
    }

    /// The collection of change events.
    pub fn changes(&self) -> &[ChangeEvent] {
        &self.changes
    }
}

/// Server notifications sent over the server sent events stream.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum ChangeEvent {
    /// Event emitted when a vault is created.
    CreateVault,
    /// Event emitted when a vault is deleted.
    DeleteVault,
    /// Event emitted when a vault name is set.
    SetVaultName(String),
    /// Event emitted when vault meta data is set.
    SetVaultMeta,
    /// Event emitted when a secret is created.
    CreateSecret(SecretId),
    /// Event emitted when a secret is updated.
    UpdateSecret(SecretId),
    /// Event emitted when a secret is deleted.
    DeleteSecret(SecretId),
}

impl ChangeEvent {
    /// Convert from a sync event.
    pub fn from_sync_event(event: &SyncEvent<'_>) -> Option<Self> {
        match event {
            SyncEvent::CreateVault(_) => Some(ChangeEvent::CreateVault),
            SyncEvent::DeleteVault => Some(ChangeEvent::DeleteVault),
            SyncEvent::SetVaultName(name) => {
                Some(ChangeEvent::SetVaultName(name.to_string()))
            }
            SyncEvent::SetVaultMeta(_) => Some(ChangeEvent::SetVaultMeta),
            SyncEvent::CreateSecret(secret_id, _) => {
                Some(ChangeEvent::CreateSecret(*secret_id))
            }
            SyncEvent::UpdateSecret(secret_id, _) => {
                Some(ChangeEvent::UpdateSecret(*secret_id))
            }
            SyncEvent::DeleteSecret(secret_id) => {
                Some(ChangeEvent::DeleteSecret(*secret_id))
            }
            _ => None,
        }
    }
}
