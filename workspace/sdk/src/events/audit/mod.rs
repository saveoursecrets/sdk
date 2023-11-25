//! Audit logging.
use async_trait::async_trait;

use bitflags::bitflags;
use serde::{Deserialize, Serialize};

use uuid::Uuid;
use web3_address::ethereum::Address;

use crate::{
    events::{Event, EventKind, ReadEvent, WriteEvent, AccountEvent},
    timestamp::Timestamp,
    vault::{secret::SecretId, VaultId},
};

mod log_file;
pub use log_file::AuditLogFile;

bitflags! {
    /// Bit flags for associated data.
    pub struct LogFlags: u16 {
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
#[cfg_attr(target_arch="wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
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
    pub(crate) time: Timestamp,
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
    pub fn time(&self) -> &Timestamp {
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

    pub(crate) fn log_flags(&self) -> LogFlags {
        if let Some(data) = &self.data {
            let mut flags = LogFlags::empty();
            flags.set(LogFlags::DATA, true);
            match data {
                AuditData::Vault(_) => {
                    flags.set(LogFlags::DATA_VAULT, true);
                }
                AuditData::Secret(_, _) => {
                    flags.set(LogFlags::DATA_VAULT, true);
                    flags.set(LogFlags::DATA_SECRET, true);
                }
                AuditData::MoveSecret { .. } => {
                    flags.set(LogFlags::MOVE_SECRET, true);
                }
            }
            flags
        } else {
            LogFlags::empty()
        }
    }

    /*
    /// Convert from a sync event to an audit event.
    pub fn from_sync_event(
        event: &Event,
        address: &Address,
        _vault_id: &Uuid,
    ) -> AuditEvent {
        let audit_data = match event {
            Event::Read(vault_id, event) => match event {
                ReadEvent::ReadVault => AuditData::Vault(*vault_id),
                ReadEvent::ReadSecret(secret_id) => {
                    AuditData::Secret(*vault_id, *secret_id)
                }
                ReadEvent::Noop => unreachable!(),
            },
            Event::Write(vault_id, event) => match event {
                WriteEvent::CreateVault(_)
                | WriteEvent::UpdateVault(_)
                | WriteEvent::DeleteVault
                | WriteEvent::SetVaultName(_)
                | WriteEvent::SetVaultMeta(_) => AuditData::Vault(*vault_id),
                WriteEvent::CreateSecret(secret_id, _) => {
                    AuditData::Secret(*vault_id, *secret_id)
                }
                WriteEvent::UpdateSecret(secret_id, _) => {
                    AuditData::Secret(*vault_id, *secret_id)
                }
                WriteEvent::DeleteSecret(secret_id) => {
                    AuditData::Secret(*vault_id, *secret_id)
                }
                WriteEvent::Noop => unreachable!(),
            },
        };
        AuditEvent::new(event.event_kind(), *address, Some(audit_data))
    }
    */
}

impl<'a> From<(&Address, &Event<'a>)> for AuditEvent {
    fn from(value: (&Address, &Event)) -> Self {
        let (address, event) = value;
        match event {
            Event::CreateAccount(event) => event.clone(),
            Event::MoveSecret(_, _, _) => {
                panic!("move secret audit event must be constructed")
            }
            Event::DeleteAccount(event) => event.clone(),
            _ => {
                let audit_data = match event {
                    Event::Account(event) => match event {
                        AccountEvent::CreateFolder(vault_id)
                        | AccountEvent::UpdateFolder(vault_id)
                        | AccountEvent::DeleteFolder(vault_id) => {
                            Some(AuditData::Vault(*vault_id))
                        }
                        AccountEvent::Noop => None,
                    },
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
                        | WriteEvent::UpdateVault(_)
                        | WriteEvent::DeleteVault
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
                    unreachable!();
                }
            }
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
        Self::Vault(Uuid::from_bytes(zero))
    }
}
