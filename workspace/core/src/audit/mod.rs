//! Event for audit log records.
use async_trait::async_trait;
use binary_stream::{
    BinaryError, BinaryReader, BinaryResult, BinaryWriter, Decode, Encode,
};
use bitflags::bitflags;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use web3_address::ethereum::Address;

use crate::{
    events::{EventKind, SyncEvent},
    secret::SecretId,
    timestamp::Timestamp,
    vault::VaultId,
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
    time: Timestamp,
    /// The event_kind being performed.
    event_kind: EventKind,
    /// The address of the client performing the event_kind.
    address: Address,
    /// Context data about the event_kind.
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<AuditData>,
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

    fn log_flags(&self) -> LogFlags {
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

    /// Convert from a sync event to an audit event.
    pub fn from_sync_event(
        event: &SyncEvent,
        address: Address,
        vault_id: Uuid,
    ) -> AuditEvent {
        let audit_data = match event {
            SyncEvent::Noop => {
                panic!("noop variant cannot be an audit event")
            }
            SyncEvent::CreateVault(_)
            | SyncEvent::UpdateVault(_)
            | SyncEvent::ReadVault
            | SyncEvent::DeleteVault
            | SyncEvent::SetVaultName(_)
            | SyncEvent::SetVaultMeta(_) => AuditData::Vault(vault_id),
            SyncEvent::CreateSecret(secret_id, _) => {
                AuditData::Secret(vault_id, *secret_id)
            }
            SyncEvent::ReadSecret(secret_id) => {
                AuditData::Secret(vault_id, *secret_id)
            }
            SyncEvent::UpdateSecret(secret_id, _) => {
                AuditData::Secret(vault_id, *secret_id)
            }
            SyncEvent::DeleteSecret(secret_id) => {
                AuditData::Secret(vault_id, *secret_id)
            }
        };
        AuditEvent::new(event.event_kind(), address, Some(audit_data))
    }
}

impl Encode for AuditEvent {
    fn encode(&self, writer: &mut BinaryWriter) -> BinaryResult<()> {
        // Context bit flags
        let flags = self.log_flags();
        writer.write_u16(flags.bits())?;
        // Time - the when
        self.time.encode(&mut *writer)?;
        // EventKind - the what
        self.event_kind.encode(&mut *writer)?;
        // Address - by whom
        writer.write_bytes(self.address.as_ref())?;
        // Data - context
        if flags.contains(LogFlags::DATA) {
            let data = self.data.as_ref().unwrap();
            data.encode(&mut *writer)?;
        }
        Ok(())
    }
}

impl Decode for AuditEvent {
    fn decode(&mut self, reader: &mut BinaryReader) -> BinaryResult<()> {
        // Context bit flags
        let bits = reader.read_u16()?;
        // Time - the when
        let mut timestamp: Timestamp = Default::default();
        timestamp.decode(&mut *reader)?;
        // EventKind - the what
        self.event_kind.decode(&mut *reader)?;
        // Address - by whom
        let address = reader.read_bytes(20)?;
        let address: [u8; 20] = address.as_slice().try_into()?;
        self.address = address.into();
        // Data - context
        if let Some(flags) = LogFlags::from_bits(bits) {
            if flags.contains(LogFlags::DATA)
                && flags.contains(LogFlags::DATA_VAULT)
            {
                let vault_id: [u8; 16] =
                    reader.read_bytes(16)?.as_slice().try_into()?;
                if !flags.contains(LogFlags::DATA_SECRET) {
                    self.data =
                        Some(AuditData::Vault(Uuid::from_bytes(vault_id)));
                } else {
                    let secret_id: [u8; 16] =
                        reader.read_bytes(16)?.as_slice().try_into()?;
                    self.data = Some(AuditData::Secret(
                        Uuid::from_bytes(vault_id),
                        Uuid::from_bytes(secret_id),
                    ));
                }
            }
        } else {
            return Err(BinaryError::Custom(
                "log data flags has bad bits".to_string(),
            ));
        }
        Ok(())
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

impl Encode for AuditData {
    fn encode(&self, writer: &mut BinaryWriter) -> BinaryResult<()> {
        match self {
            AuditData::Vault(vault_id) => {
                writer.write_bytes(vault_id.as_bytes())?;
            }
            AuditData::Secret(vault_id, secret_id) => {
                writer.write_bytes(vault_id.as_bytes())?;
                writer.write_bytes(secret_id.as_bytes())?;
            }
        }
        Ok(())
    }
}
