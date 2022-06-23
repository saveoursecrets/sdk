//! Type for change events emitted by the server.
//!
//! Declared in this crate as this type is also used
//! by the client for the monitor command.
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{address::AddressStr, operations::Payload};

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
        /// The change sequence.
        change_seq: u32,
    },
    /// Event emitted when a vault is deleted.
    DeleteVault {
        /// The owner address.
        #[serde(skip)]
        address: AddressStr,
        /// The vault identifier.
        vault_id: Uuid,
        /// The change sequence.
        change_seq: u32,
    },
    /// Event emitted when a vault name is set.
    SetVaultName {
        /// The owner address.
        #[serde(skip)]
        address: AddressStr,
        /// The vault identifier.
        vault_id: Uuid,
        /// The change sequence.
        change_seq: u32,
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
        /// The change sequence.
        change_seq: u32,
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
        /// The change sequence.
        change_seq: u32,
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
        /// The change sequence.
        change_seq: u32,
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
        /// The change sequence.
        change_seq: u32,
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

impl<'u, 'a, 'p> From<(&'u Uuid, &'a AddressStr, &'p Payload<'p>)>
    for ChangeEvent
{
    fn from(value: (&'u Uuid, &'a AddressStr, &'p Payload<'p>)) -> Self {
        let (vault_id, address, payload) = value;
        match payload {
            Payload::CreateVault => ChangeEvent::CreateVault {
                address: address.clone(),
                vault_id: *vault_id,
            },
            Payload::UpdateVault(change_seq) => ChangeEvent::UpdateVault {
                address: address.clone(),
                change_seq: *change_seq,
                vault_id: *vault_id,
            },
            Payload::DeleteVault(change_seq) => ChangeEvent::DeleteVault {
                address: address.clone(),
                change_seq: *change_seq,
                vault_id: *vault_id,
            },
            Payload::SetVaultName(change_seq, name) => {
                ChangeEvent::SetVaultName {
                    address: address.clone(),
                    change_seq: *change_seq,
                    vault_id: *vault_id,
                    name: name.to_string(),
                }
            }
            Payload::CreateSecret(change_seq, secret_id, _) => {
                ChangeEvent::CreateSecret {
                    address: address.clone(),
                    change_seq: *change_seq,
                    vault_id: *vault_id,
                    secret_id: *secret_id,
                }
            }
            Payload::UpdateSecret(change_seq, secret_id, _) => {
                ChangeEvent::UpdateSecret {
                    address: address.clone(),
                    change_seq: *change_seq,
                    vault_id: *vault_id,
                    secret_id: *secret_id,
                }
            }
            Payload::DeleteSecret(change_seq, secret_id) => {
                ChangeEvent::DeleteSecret {
                    address: address.clone(),
                    change_seq: *change_seq,
                    vault_id: *vault_id,
                    secret_id: *secret_id,
                }
            }
            _ => unreachable!(),
        }
    }
}
