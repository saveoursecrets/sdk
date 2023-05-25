//! Events emitted over the server-sent events channel to
//! notify connected clients that changes have been made.
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use web3_address::ethereum::Address;

use crate::{
    commit::CommitProof,
    events::{Event, WriteEvent},
    vault::{secret::SecretId, Header, Summary, VaultId},
};

/// Encapsulates a collection of change events.
///
/// Used so that we can group multiple changes into a
/// single notification to connected clients.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ChangeNotification {
    /// The owner address.
    address: Address,
    /// The session identifier.
    session_id: Uuid,
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
        session_id: &Uuid,
        vault_id: &VaultId,
        proof: CommitProof,
        changes: Vec<ChangeEvent>,
    ) -> Self {
        Self {
            address: *address,
            session_id: *session_id,
            vault_id: *vault_id,
            proof,
            changes,
        }
    }

    /// Address of the owner that made the changes.
    pub fn address(&self) -> &Address {
        &self.address
    }

    /// The session identifier that made the change.
    pub fn session_id(&self) -> &Uuid {
        &self.session_id
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
    /// Event emitted when a vault is created.
    CreateVault(Summary),
    /// Event emitted when a vault is updated.
    ///
    /// This occurs when the passphrase for a vault
    /// has been changed.
    UpdateVault,
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
    pub fn from_sync_event(event: &Event<'_>) -> Option<Self> {
        match event {
            Event::Write(_, event) => match event {
                WriteEvent::CreateVault(vault) => {
                    let summary = Header::read_summary_slice(vault)
                        .expect("failed to read summary from vault");
                    Some(ChangeEvent::CreateVault(summary))
                }
                WriteEvent::DeleteVault => Some(ChangeEvent::DeleteVault),
                WriteEvent::SetVaultName(name) => {
                    Some(ChangeEvent::SetVaultName(name.to_string()))
                }
                WriteEvent::SetVaultMeta(_) => {
                    Some(ChangeEvent::SetVaultMeta)
                }
                WriteEvent::CreateSecret(secret_id, _) => {
                    Some(ChangeEvent::CreateSecret(*secret_id))
                }
                WriteEvent::UpdateSecret(secret_id, _) => {
                    Some(ChangeEvent::UpdateSecret(*secret_id))
                }
                WriteEvent::DeleteSecret(secret_id) => {
                    Some(ChangeEvent::DeleteSecret(*secret_id))
                }
                _ => None,
            },
            _ => None,
        }
    }
}

/// Action corresponding to a change event.
#[derive(Debug, Hash, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum ChangeAction {
    /// Pull updates from a remote node.
    Pull(VaultId),

    /// Vaults was created on a remote node and the
    /// local node has fetched the vault summary
    /// and added it to it's local state.
    Create(Summary),

    /// Vault was removed on a remote node and
    /// the local node has removed it from it's
    /// local cache.
    ///
    /// UI implementations should close an open
    /// vault if the removed vault is open and
    /// update the list of vaults.
    Remove(VaultId),
}
