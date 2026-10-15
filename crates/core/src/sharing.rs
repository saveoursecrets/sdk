//! Types for public key infrastructure (PKI) and folder sharing.
use crate::{Error, Result, UtcDateTime, VaultId};
use serde::{Deserialize, Serialize};

/// Recipient is a participant in a shared folder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Recipient {
    /// Recipient name.
    pub name: String,
    /// Optional email.
    pub email: Option<String>,
    /// Public key.
    pub public_key: age::x25519::Recipient,
}

/// Status of a folder invite.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum InviteStatus {
    /// Pending invite.
    Pending = 0,
    /// Accepted invite.
    Accepted = 1,
    /// Declined invite.
    Declined = 2,
}

// For database INTEGER type.
impl TryFrom<i64> for InviteStatus {
    type Error = Error;

    fn try_from(value: i64) -> Result<Self> {
        Ok(match value {
            0 => Self::Pending,
            1 => Self::Accepted,
            2 => Self::Declined,
            _ => return Err(Error::UnknownInviteStatus(value)),
        })
    }
}

// For protobuf enum type.
impl TryFrom<i32> for InviteStatus {
    type Error = Error;

    fn try_from(value: i32) -> Result<Self> {
        (value as i64).try_into()
    }
}

/// Invite to share a folder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FolderInvite {
    /// Created date and time.
    pub created_at: UtcDateTime,
    /// Modified date and time.
    pub modified_at: UtcDateTime,
    /// Invite status.
    pub invite_status: InviteStatus,
    /// Folder identifier.
    pub folder_id: VaultId,
    /// Folder name.
    pub folder_name: String,
    /// Recipient name (from/to depending on context).
    pub recipient_name: String,
    /// Recipient email (from/to depending on context).
    pub recipient_email: Option<String>,
    /// Recipient public key (from/to depending on context).
    pub recipient_public_key: age::x25519::Recipient,
}
