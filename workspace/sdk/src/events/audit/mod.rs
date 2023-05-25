//! Audit logging.
use async_trait::async_trait;

use bitflags::bitflags;
use serde::{Deserialize, Serialize};

use uuid::Uuid;
use web3_address::ethereum::Address;

use crate::{
    events::{Event, EventKind, ReadEvent, WriteEvent},
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
        events: &[AuditEvent],
    ) -> std::result::Result<(), Self::Error>;
}

/// Audit log record.
///
/// An audit log record with no associated data is 36 bytes.
///
/// When associated data is available an additional 16 bytes is used
/// for events on a vault and 32 bytes for events on a secret.
///
/// The maximum size of a log record is thus 68 bytes.
///
/// * 2 bytes for bit flags.
/// * 8 bytes for the timestamp seconds.
/// * 4 bytes for the timestamp nanoseconds.
/// * 2 bytes for the event kind identifier.
/// * 20 bytes for the public address.
/// * 16 or 32 bytes for the context data (one or two UUIDs).
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct AuditEvent {
    /// The time the log was created.
    pub(crate) time: Timestamp,
    /// The event_kind being performed.
    pub(crate) event_kind: EventKind,
    /// The address of the client performing the event_kind.
    pub(crate) address: Address,
    /// Context data about the event_kind.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) data: Option<AuditData>,
}

impl AuditEvent {
    /// Create a new audit log entry.
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
    pub fn event_kind(&self) -> &EventKind {
        &self.event_kind
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
}

/// Associated data for an audit log record.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuditData {
    /// Data for an associated vault.
    Vault(VaultId),
    /// Data for an associated secret.
    Secret(VaultId, SecretId),
}

impl Default for AuditData {
    fn default() -> Self {
        let zero = [0u8; 16];
        Self::Vault(Uuid::from_bytes(zero))
    }
}
