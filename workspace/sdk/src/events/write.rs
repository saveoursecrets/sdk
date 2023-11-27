//! Write operations.

use serde::{Deserialize, Serialize};
use std::cmp::Ordering;

use crate::{
    crypto::AeadPack,
    vault::{secret::SecretId, VaultCommit},
};

use super::EventKind;

/// Write operations.
#[derive(Default, Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
pub enum WriteEvent {
    /// Default variant, should never be used.
    ///
    /// We need a variant so we can implement the Default
    /// trait which is required for decoding.
    #[default]
    #[doc(hidden)]
    Noop,

    /// Event used to indicate a vault was created.
    CreateVault(Vec<u8>),

    /// Event used to indicate a vault was updated.
    ///
    /// This occurs when the passphrase for a vault
    /// has been changed.
    UpdateVault(Vec<u8>),

    /// Event used to indicate a vault was deleted.
    DeleteVault,

    /// Event used to indicate the vault name was set.
    SetVaultName(String),

    /// Event used to indicate the vault meta data was set.
    SetVaultMeta(Option<AeadPack>),

    /// Event used to indicate a secret was created.
    CreateSecret(SecretId, VaultCommit),

    /// Event used to indicate a secret was updated.
    UpdateSecret(SecretId, VaultCommit),

    /// Event used to indicate a secret was deleted.
    DeleteSecret(SecretId),
}

impl Ord for WriteEvent {
    fn cmp(&self, other: &Self) -> Ordering {
        match (self, &other) {
            // NOTE: This sorting is important when we send a vault
            // NOTE: to the server and it is split into a header-only
            // NOTE: vault and event log event records the sort order must
            // NOTE: match the client order otherwise the root hashes
            // NOTE: will be different.
            //
            // NOTE: We only care about the `CreateSecret` variant as
            // NOTE: we know in this scenario that it is the only variant
            // NOTE: in addition to the `CreateVault` start record.
            (
                WriteEvent::CreateSecret(a, _),
                WriteEvent::CreateSecret(b, _),
            ) => a.cmp(b),
            _ => Ordering::Greater,
        }
    }
}

impl PartialOrd for WriteEvent {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl WriteEvent {
    /// Get the event kind for this event.
    pub fn event_kind(&self) -> EventKind {
        match self {
            WriteEvent::Noop => EventKind::Noop,
            WriteEvent::CreateVault(_) => EventKind::CreateVault,
            WriteEvent::UpdateVault(_) => EventKind::UpdateVault,
            WriteEvent::DeleteVault => EventKind::DeleteVault,
            WriteEvent::SetVaultName(_) => EventKind::SetVaultName,
            WriteEvent::SetVaultMeta(_) => EventKind::SetVaultMeta,
            WriteEvent::CreateSecret(_, _) => EventKind::CreateSecret,
            WriteEvent::UpdateSecret(_, _) => EventKind::UpdateSecret,
            WriteEvent::DeleteSecret(_) => EventKind::DeleteSecret,
        }
    }
}
