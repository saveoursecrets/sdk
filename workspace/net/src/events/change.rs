//! Events emitted over by the server to
//! notify connected clients that changes have been made.
use serde::{Deserialize, Serialize};

use sos_sdk::{
    commit::CommitProof,
    events::{Event, WriteEvent},
    signer::ecdsa::Address,
    vault::{secret::SecretId, VaultId},
};

use crate::{Error, Result};

/// Encapsulates a collection of change events.
///
/// Used so that we can group multiple changes into a
/// single notification to connected clients.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ChangeNotification {
    /// The owner address.
    address: Address,
    /// The public key of the caller.
    public_key: Vec<u8>,
    /// The vault identifier.
    vault_id: VaultId,
    /// The commit proof.
    proof: CommitProof,
    /// Collection of change events.
    changes: Vec<ChangeEvent>,
}

impl ChangeNotification {
    /// Create a new change notification.
    pub fn new(
        address: &Address,
        public_key: &[u8],
        vault_id: &VaultId,
        proof: CommitProof,
        changes: Vec<ChangeEvent>,
    ) -> Self {
        Self {
            address: *address,
            public_key: public_key.to_vec(),
            vault_id: *vault_id,
            proof,
            changes,
        }
    }

    /// Address of the owner that made the changes.
    pub fn address(&self) -> &Address {
        &self.address
    }

    /// The public key that made the change.
    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    /// The identifier of the vault that was modified.
    pub fn vault_id(&self) -> &VaultId {
        &self.vault_id
    }

    /// The commit proof after the change.
    pub fn proof(&self) -> &CommitProof {
        &self.proof
    }

    /// The collection of change events.
    pub fn changes(&self) -> &[ChangeEvent] {
        &self.changes
    }
}

/// Server notifications sent over the server sent events stream.
#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
pub enum ChangeEvent {
    /// Event emitted when a folder is created.
    CreateFolder(Event),
    /// Event emitted when a vault is updated.
    ///
    /// This event can occur when a vault is imported
    /// that overwrites an existing vault or if the
    /// vault is compacted or the password changed (which
    /// requires re-writing the event log).
    UpdateFolder(Event),
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
    /// Convert from a write operation.
    pub async fn try_from_write_event(event: &WriteEvent) -> Result<Self> {
        match event {
            WriteEvent::SetVaultName(name) => {
                Ok(ChangeEvent::SetVaultName(name.to_string()))
            }
            WriteEvent::SetVaultMeta(_) => Ok(ChangeEvent::SetVaultMeta),
            WriteEvent::CreateSecret(secret_id, _) => {
                Ok(ChangeEvent::CreateSecret(*secret_id))
            }
            WriteEvent::UpdateSecret(secret_id, _) => {
                Ok(ChangeEvent::UpdateSecret(*secret_id))
            }
            WriteEvent::DeleteSecret(secret_id) => {
                Ok(ChangeEvent::DeleteSecret(*secret_id))
            }
            _ => Err(Error::NoChangeEvent),
        }
    }
}

/// Action corresponding to a change event.
#[derive(Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum ChangeAction {
    /// Pull updates from a remote node.
    Pull(VaultId),

    /// Vaults was created on a remote node and the
    /// local node has fetched the vault summary
    /// and added it to it's local state.
    CreateFolder(Event),

    /// Vault was updated on a remote node and the
    /// local node has fetched the vault summary
    /// and added it to it's local state.
    UpdateFolder(Event),

    /// Vault was removed on a remote node and
    /// the local node has removed it from it's
    /// local cache.
    ///
    /// UI implementations should close an open
    /// vault if the removed vault is open and
    /// update the list of vaults.
    Remove(VaultId),
}
