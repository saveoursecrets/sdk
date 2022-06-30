//! Events emitted over the server-sent events channel to
//! notify connected clients that changes have been made.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::address::AddressStr;

use super::SyncEvent;

/// Server notifications sent over the server sent events stream.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum ChangeEvent {
    /// Event emitted when a vault is created.
    CreateVault {
        /// The owner address.
        #[serde(skip)]
        address: AddressStr,
        /// The vault identifier.
        vault_id: Uuid,
    },
    /// Event emitted when a vault is updated.
    UpdateVault {
        /// The owner address.
        #[serde(skip)]
        address: AddressStr,
        /// The vault identifier.
        vault_id: Uuid,
    },
    /// Event emitted when a vault is deleted.
    DeleteVault {
        /// The owner address.
        #[serde(skip)]
        address: AddressStr,
        /// The vault identifier.
        vault_id: Uuid,
    },
    /// Event emitted when a vault name is set.
    SetVaultName {
        /// The owner address.
        #[serde(skip)]
        address: AddressStr,
        /// The vault identifier.
        vault_id: Uuid,
        /// The vault name.
        name: String,
    },
    /// Event emitted when vault meta data is set.
    SetVaultMeta {
        /// The owner address.
        #[serde(skip)]
        address: AddressStr,
        /// The vault identifier.
        vault_id: Uuid,
    },
    /// Event emitted when a secret is created.
    CreateSecret {
        #[serde(skip)]
        /// The owner address.
        address: AddressStr,
        /// The vault identifier.
        vault_id: Uuid,
        /// The secret identifier.
        secret_id: Uuid,
    },
    /// Event emitted when a secret is updated.
    UpdateSecret {
        /// The owner address.
        #[serde(skip)]
        address: AddressStr,
        /// The vault identifier.
        vault_id: Uuid,
        /// The secret identifier.
        secret_id: Uuid,
    },
    /// Event emitted when a secret is deleted.
    DeleteSecret {
        /// The owner address.
        #[serde(skip)]
        address: AddressStr,
        /// The vault identifier.
        vault_id: Uuid,
        /// The secret identifier.
        secret_id: Uuid,
    },
}

impl ChangeEvent {
    /// Name for the server sent event.
    pub fn event_name(&self) -> &str {
        match self {
            Self::CreateVault { .. } => "createVault",
            Self::UpdateVault { .. } => "updateVault",
            Self::DeleteVault { .. } => "deleteVault",
            Self::SetVaultName { .. } => "setVaultName",
            Self::SetVaultMeta { .. } => "setVaultMeta",
            Self::CreateSecret { .. } => "createSecret",
            Self::UpdateSecret { .. } => "updateSecret",
            Self::DeleteSecret { .. } => "deleteSecret",
        }
    }

    /// Address of the client that triggered the event.
    pub fn address(&self) -> &AddressStr {
        match self {
            Self::CreateVault { address, .. } => address,
            Self::UpdateVault { address, .. } => address,
            Self::DeleteVault { address, .. } => address,
            Self::SetVaultName { address, .. } => address,
            Self::SetVaultMeta { address, .. } => address,
            Self::CreateSecret { address, .. } => address,
            Self::UpdateSecret { address, .. } => address,
            Self::DeleteSecret { address, .. } => address,
        }
    }
}

impl<'u, 'a, 'e> From<(&'u Uuid, &'a AddressStr, &'e SyncEvent<'e>)>
    for ChangeEvent
{
    fn from(value: (&'u Uuid, &'a AddressStr, &'e SyncEvent<'e>)) -> Self {
        let (vault_id, address, payload) = value;
        match payload {
            SyncEvent::CreateVault(_) => ChangeEvent::CreateVault {
                address: *address,
                vault_id: *vault_id,
            },
            SyncEvent::UpdateVault(_) => ChangeEvent::UpdateVault {
                address: *address,
                vault_id: *vault_id,
            },
            SyncEvent::DeleteVault => ChangeEvent::DeleteVault {
                address: *address,
                vault_id: *vault_id,
            },
            SyncEvent::SetVaultName(name) => ChangeEvent::SetVaultName {
                address: *address,
                vault_id: *vault_id,
                name: name.to_string(),
            },
            SyncEvent::CreateSecret(secret_id, _) => {
                ChangeEvent::CreateSecret {
                    address: *address,
                    vault_id: *vault_id,
                    secret_id: *secret_id,
                }
            }
            SyncEvent::UpdateSecret(secret_id, _) => {
                ChangeEvent::UpdateSecret {
                    address: *address,
                    vault_id: *vault_id,
                    secret_id: *secret_id,
                }
            }
            SyncEvent::DeleteSecret(secret_id) => ChangeEvent::DeleteSecret {
                address: *address,
                vault_id: *vault_id,
                secret_id: *secret_id,
            },
            _ => unreachable!(),
        }
    }
}
