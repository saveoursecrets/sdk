//! Write operations.

use serde::{Deserialize, Serialize};
use std::{borrow::Cow, cmp::Ordering};

use crate::{
    crypto::AeadPack,
    vault::{secret::SecretId, VaultCommit},
};

use super::EventKind;

/// Write operations.
#[derive(Default, Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
pub enum WriteEvent<'a> {
    /// Default variant, should never be used.
    ///
    /// We need a variant so we can implement the Default
    /// trait which is required for decoding.
    #[default]
    #[doc(hidden)]
    Noop,

    /// Event used to indicate a vault was created.
    CreateVault(Cow<'a, [u8]>),

    /// Event used to indicate a vault was updated.
    ///
    /// This occurs when the passphrase for a vault
    /// has been changed.
    UpdateVault(Cow<'a, [u8]>),

    /// Event used to indicate a vault was deleted.
    DeleteVault,

    /// Event used to indicate the vault name was set.
    SetVaultName(Cow<'a, str>),

    /// Event used to indicate the vault meta data was set.
    SetVaultMeta(Cow<'a, Option<AeadPack>>),

    /// Event used to indicate a secret was created.
    CreateSecret(SecretId, Cow<'a, VaultCommit>),

    /// Event used to indicate a secret was updated.
    UpdateSecret(SecretId, Cow<'a, VaultCommit>),

    /// Event used to indicate a secret was deleted.
    DeleteSecret(SecretId),
}

impl Ord for WriteEvent<'_> {
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

impl PartialOrd for WriteEvent<'_> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl WriteEvent<'_> {
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

    /// Convert this event into an owned version.
    pub fn into_owned(self) -> WriteEvent<'static> {
        match self {
            WriteEvent::Noop => WriteEvent::Noop,
            WriteEvent::CreateVault(value) => {
                WriteEvent::CreateVault(Cow::Owned(value.into_owned()))
            }
            WriteEvent::UpdateVault(value) => {
                WriteEvent::UpdateVault(Cow::Owned(value.into_owned()))
            }
            WriteEvent::DeleteVault => WriteEvent::DeleteVault,
            WriteEvent::SetVaultName(value) => {
                WriteEvent::SetVaultName(Cow::Owned(value.into_owned()))
            }
            WriteEvent::SetVaultMeta(value) => {
                WriteEvent::SetVaultMeta(Cow::Owned(value.into_owned()))
            }
            WriteEvent::CreateSecret(secret_id, value) => {
                WriteEvent::CreateSecret(
                    secret_id,
                    Cow::Owned(value.into_owned()),
                )
            }
            WriteEvent::UpdateSecret(secret_id, value) => {
                WriteEvent::UpdateSecret(
                    secret_id,
                    Cow::Owned(value.into_owned()),
                )
            }
            WriteEvent::DeleteSecret(secret_id) => {
                WriteEvent::DeleteSecret(secret_id)
            }
        }
    }
}
