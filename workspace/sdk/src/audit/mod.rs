//! Audit logging.
use async_trait::async_trait;

use bitflags::bitflags;
use serde::{Deserialize, Serialize};

use crate::{
    events::{Event, EventKind, LogEvent, ReadEvent, WriteEvent},
    signer::ecdsa::Address,
    UtcDateTime,
    vault::{secret::SecretId, VaultId},
};

use crate::events::AccountEvent;

mod log_file;
pub use log_file::AuditLogFile;

bitflags! {
    /// Bit flags for associated data.
    pub struct AuditLogFlags: u16 {
        /// Indicates whether associated data is present.
        const DATA =        0b00000001;
        /// Indicates the data has a vault identifier.
        const DATA_VAULT =  0b00000010;
        /// Indicates the data has a secret identifier.
        const DATA_SECRET = 0b00000100;
        /// Indicates the data has a move event.
        const MOVE_SECRET = 0b00001000;
    }
}

/// Trait for types that append to an audit log.
#[async_trait]
pub trait AuditProvider {
    /// Error type for this implementation.
    type Error;

    /// Append audit log records to a destination.
    async fn append_audit_events(
        &mut self,
        events: Vec<AuditEvent>,
    ) -> std::result::Result<(), Self::Error>;
}

/// Audit log record.
///
/// An audit log record with no associated data is 36 bytes.
///
/// When associated data is available an additional 16 bytes is used
/// for events on a vault and 32 bytes for events on a secret and for a
/// move event 64 bytes is used.
///
/// The maximum size of a log record is thus 100 bytes.
///
/// * 2 bytes for bit flags.
/// * 8 bytes for the timestamp seconds.
/// * 4 bytes for the timestamp nanoseconds.
/// * 2 bytes for the event kind identifier.
/// * 20 bytes for the public address.
/// * 16, 32 or 64 bytes for the context data (one, two or four UUIDs).
#[derive(Clone, Debug, Default, Serialize, Deserialize, Eq, PartialEq)]
pub struct AuditEvent {
    /// The time the event was created.
    pub(crate) time: UtcDateTime,
    /// The event being logged.
    pub(crate) event_kind: EventKind,
    /// The address of the client performing the event.
    pub(crate) address: Address,
    /// Context data about the event.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) data: Option<AuditData>,
}

impl AuditEvent {
    /// Create a new audit log event.
    pub fn new(
        event_kind: EventKind,
        address: Address,
        data: Option<AuditData>,
    ) -> Self {
        Self {
            time: Default::default(),
            event_kind,
            address,
            data,
        }
    }

    /// Get the address for this audit event.
    pub fn address(&self) -> &Address {
        &self.address
    }

    /// Get the timestamp for this audit event.
    pub fn time(&self) -> &UtcDateTime {
        &self.time
    }

    /// Get the event kind for this audit event.
    pub fn event_kind(&self) -> EventKind {
        self.event_kind
    }

    /// Get the data for this audit event.
    pub fn data(&self) -> Option<&AuditData> {
        self.data.as_ref()
    }

    pub(crate) fn log_flags(&self) -> AuditLogFlags {
        if let Some(data) = &self.data {
            let mut flags = AuditLogFlags::empty();
            flags.set(AuditLogFlags::DATA, true);
            match data {
                AuditData::Vault(_) => {
                    flags.set(AuditLogFlags::DATA_VAULT, true);
                }
                AuditData::Secret(_, _) => {
                    flags.set(AuditLogFlags::DATA_VAULT, true);
                    flags.set(AuditLogFlags::DATA_SECRET, true);
                }
                AuditData::MoveSecret { .. } => {
                    flags.set(AuditLogFlags::MOVE_SECRET, true);
                }
            }
            flags
        } else {
            AuditLogFlags::empty()
        }
    }
}

impl From<(&Address, &Event)> for AuditEvent {
    fn from(value: (&Address, &Event)) -> Self {
        let (address, event) = value;
        match event {
            Event::CreateAccount(address) => {
                AuditEvent::new(EventKind::CreateAccount, *address, None)
            }
            Event::MoveSecret(_, _, _) => {
                panic!("move secret audit event must be constructed")
            }
            Event::DeleteAccount(address) => {
                AuditEvent::new(EventKind::DeleteAccount, *address, None)
            }
            _ => {
                let audit_data = match event {
                    Event::Account(event) => {
                        event.folder_id().map(AuditData::Vault)
                    }
                    Event::Folder(event, _) => {
                        event.folder_id().map(AuditData::Vault)
                    }
                    Event::Read(vault_id, event) => match event {
                        ReadEvent::ReadVault => {
                            Some(AuditData::Vault(*vault_id))
                        }
                        ReadEvent::ReadSecret(secret_id) => {
                            Some(AuditData::Secret(*vault_id, *secret_id))
                        }
                        ReadEvent::Noop => None,
                    },
                    Event::Write(vault_id, event) => match event {
                        WriteEvent::CreateVault(_)
                        | WriteEvent::SetVaultName(_)
                        | WriteEvent::SetVaultMeta(_) => {
                            Some(AuditData::Vault(*vault_id))
                        }
                        WriteEvent::CreateSecret(secret_id, _) => {
                            Some(AuditData::Secret(*vault_id, *secret_id))
                        }
                        WriteEvent::UpdateSecret(secret_id, _) => {
                            Some(AuditData::Secret(*vault_id, *secret_id))
                        }
                        WriteEvent::DeleteSecret(secret_id) => {
                            Some(AuditData::Secret(*vault_id, *secret_id))
                        }
                        WriteEvent::Noop => None,
                    },
                    _ => None,
                };

                if let Some(audit_data) = audit_data {
                    AuditEvent::new(
                        event.event_kind(),
                        *address,
                        Some(audit_data),
                    )
                } else {
                    unreachable!("{:#?}", event);
                }
            }
        }
    }
}

impl From<(&Address, &AccountEvent)> for AuditEvent {
    fn from(value: (&Address, &AccountEvent)) -> Self {
        let (address, event) = value;
        let audit_data = event.folder_id().map(AuditData::Vault);
        if let Some(audit_data) = audit_data {
            AuditEvent::new(event.event_kind(), *address, Some(audit_data))
        } else {
            unreachable!();
        }
    }
}

/// Associated data for an audit log record.
#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum AuditData {
    /// Data for an associated vault.
    Vault(VaultId),
    /// Data for an associated secret.
    Secret(VaultId, SecretId),
    /// Data for a move secret event.
    MoveSecret {
        /// Moved from vault.
        from_vault_id: VaultId,
        /// Old secret identifier.
        from_secret_id: SecretId,
        /// Moved to vault.
        to_vault_id: VaultId,
        /// New secret identifier.
        to_secret_id: SecretId,
    },
}

impl Default for AuditData {
    fn default() -> Self {
        let zero = [0u8; 16];
        Self::Vault(VaultId::from_bytes(zero))
    }
}
