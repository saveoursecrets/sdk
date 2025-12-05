use crate::{Error, Result};
use async_sqlite::rusqlite::{Error as SqlError, Row};
use sos_core::{InviteStatus, UtcDateTime};
use std::result::Result as StdResult;

/// Represents an invite to a shared folder.
pub(super) struct FolderInviteRow {
    folder_invite_id: i64,
    created_at: String,
    modified_at: String,
    from_recipient_id: i64,
    to_recipient_id: i64,
    folder_id: i64,
    invite_status: i64,
    folder_name: String,
    recipient_name: String,
    recipient_email: Option<String>,
    recipient_public_key: String,
}

impl<'a> TryFrom<&Row<'a>> for FolderInviteRow {
    type Error = SqlError;
    fn try_from(row: &Row<'a>) -> StdResult<Self, Self::Error> {
        Ok(FolderInviteRow {
            folder_invite_id: row.get(0)?,
            created_at: row.get(1)?,
            modified_at: row.get(2)?,
            from_recipient_id: row.get(3)?,
            to_recipient_id: row.get(4)?,
            folder_id: row.get(5)?,
            invite_status: row.get(6)?,
            folder_name: row.get(7)?,
            recipient_name: row.get(8)?,
            recipient_email: row.get(9)?,
            recipient_public_key: row.get(10)?,
        })
    }
}

#[derive(Debug)]
pub struct FolderInviteRecord {
    /// Row identifier.
    pub row_id: i64,
    /// Created date and time.
    pub created_at: UtcDateTime,
    /// Modified date and time.
    pub modified_at: UtcDateTime,
    /// From recipient id.
    #[allow(dead_code)]
    pub(super) from_recipient_id: i64,
    /// To recipient id.
    #[allow(dead_code)]
    pub(super) to_recipient_id: i64,
    /// Folder id.
    #[allow(dead_code)]
    pub(super) folder_id: i64,
    /// Invite status.
    pub invite_status: InviteStatus,
    /// Folder name.
    pub folder_name: String,
    /// Recipient name (from/to depending on context).
    pub recipient_name: String,
    /// Recipient email (from/to depending on context).
    pub recipient_email: Option<String>,
    /// Recipient public key (from/to depending on context).
    pub recipient_public_key: String,
}

impl TryFrom<FolderInviteRow> for FolderInviteRecord {
    type Error = Error;

    fn try_from(value: FolderInviteRow) -> Result<Self> {
        Ok(Self {
            row_id: value.folder_invite_id,
            created_at: UtcDateTime::parse_rfc3339(&value.created_at)?,
            modified_at: UtcDateTime::parse_rfc3339(&value.modified_at)?,
            from_recipient_id: value.from_recipient_id,
            to_recipient_id: value.to_recipient_id,
            folder_id: value.folder_id,
            invite_status: value.invite_status.try_into()?,
            folder_name: value.folder_name,
            recipient_name: value.recipient_name,
            recipient_email: value.recipient_email,
            recipient_public_key: value.recipient_public_key,
        })
    }
}
