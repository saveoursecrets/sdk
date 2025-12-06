//! Audit trail event.
use bitflags::bitflags;
use serde::{Deserialize, Serialize};
use sos_core::device::DevicePublicKey;
use sos_core::events::{
    AccountEvent, Event, EventKind, ReadEvent, WriteEvent,
};
use sos_core::{AccountId, SecretId, UtcDateTime, VaultId, events::LogEvent};

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
        /// Indicates the data is for a device event.
        const DEVICE = 0b00010000;
    }
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
/// * 20 bytes for the public account_id.
/// * 16, 32 or 64 bytes for the context data (one, two or four UUIDs).
#[derive(Clone, Debug, Default, Serialize, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct AuditEvent {
    /// Time the event was created.
    pub(crate) time: UtcDateTime,
    /// Event being logged.
    #[serde(rename = "type")]
    pub(crate) event_kind: EventKind,
    /// Account identifier of the client performing the event.
    pub(crate) account_id: AccountId,
    /// Context data about the event.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) data: Option<AuditData>,
}

impl AuditEvent {
    /// Create a new audit log event.
    pub fn new(
        date_time: UtcDateTime,
        event_kind: EventKind,
        account_id: AccountId,
        data: Option<AuditData>,
    ) -> Self {
        Self {
            time: date_time,
            event_kind,
            account_id,
            data,
        }
    }

    /// Account identifier for this audit event.
    pub fn account_id(&self) -> &AccountId {
        &self.account_id
    }

    /// Date and time for this audit event.
    pub fn time(&self) -> &UtcDateTime {
        &self.time
    }

    /// Event kind for this audit event.
    pub fn event_kind(&self) -> EventKind {
        self.event_kind
    }

    /// Associated data for this audit event.
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
                AuditData::Device { .. } => {
                    flags.set(AuditLogFlags::DEVICE, true);
                }
            }
            flags
        } else {
            AuditLogFlags::empty()
        }
    }
}

impl From<(&AccountId, &Event)> for AuditEvent {
    fn from(value: (&AccountId, &Event)) -> Self {
        let (account_id, event) = value;
        match event {
            Event::CreateAccount(account_id) => AuditEvent::new(
                Default::default(),
                EventKind::CreateAccount,
                *account_id,
                None,
            ),
            Event::MoveSecret(_, _, _) => {
                panic!("move secret audit event must be constructed")
            }
            Event::DeleteAccount(account_id) => AuditEvent::new(
                Default::default(),
                EventKind::DeleteAccount,
                *account_id,
                None,
            ),
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
                        | WriteEvent::SetVaultFlags(_)
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
                        Default::default(),
                        event.event_kind(),
                        *account_id,
                        Some(audit_data),
                    )
                } else {
                    unreachable!("{:#?}", event);
                }
            }
        }
    }
}

impl From<(&AccountId, &AccountEvent)> for AuditEvent {
    fn from(value: (&AccountId, &AccountEvent)) -> Self {
        let (account_id, event) = value;
        let audit_data = event.folder_id().map(AuditData::Vault);
        AuditEvent::new(
            Default::default(),
            event.event_kind(),
            *account_id,
            audit_data,
        )
    }
}

/// Associated data for an audit log record.
#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
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
    /// Device trust or revoke events.
    Device(DevicePublicKey),
}

impl Default for AuditData {
    fn default() -> Self {
        let zero = [0u8; 16];
        Self::Vault(VaultId::from_bytes(zero))
    }
}
