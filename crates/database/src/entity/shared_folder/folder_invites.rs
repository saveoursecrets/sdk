use crate::{Error, Result};
use async_sqlite::rusqlite::{Connection, Error as SqlError, Row};
use sos_core::UtcDateTime;
use sql_query_builder as sql;
use std::{ops::Deref, result::Result as StdResult};

fn folder_invites_select_columns(sql: sql::Select) -> sql::Select {
    sql.select(
        r#"
            folder_invite_id,
            created_at,
            modified_at,
            from_recipient_id,
            to_recipient_id,
            folder_id,
            invite_status
        "#,
    )
}

/// Represents an invite to a shared folder.
pub(super) struct FolderInviteRow {
    folder_invite_id: i64,
    created_at: String,
    modified_at: String,
    from_recipient_id: i64,
    to_recipient_id: i64,
    folder_id: i64,
    invite_status: i64,
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
        })
    }
}

#[derive(Debug)]
#[repr(u8)]
pub enum InviteStatus {
    /// Pending invite.
    Pending = 0,
    /// Accepted invite.
    Accepted = 1,
    /// Declined invite.
    Declined = 2,
}

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

#[derive(Debug)]
pub struct FolderInviteRecord {
    /// Row identifier.
    pub row_id: i64,
    /// Created date and time.
    pub created_at: UtcDateTime,
    /// Modified date and time.
    pub modified_at: UtcDateTime,
    /// From recipient id.
    pub(super) from_recipient_id: i64,
    /// To recipient id.
    pub(super) to_recipient_id: i64,
    /// Folder id.
    pub(super) folder_id: i64,
    /// Invite status.
    pub invite_status: InviteStatus,
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
        })
    }
}

/// Folder invite entity.
pub struct FolderInviteEntity<'conn, C>
where
    C: Deref<Target = Connection>,
{
    conn: &'conn C,
}

impl<'conn, C> FolderInviteEntity<'conn, C>
where
    C: Deref<Target = Connection>,
{
    /// Create a new folder invite.
    pub fn new(conn: &'conn C) -> Self {
        Self { conn }
    }

    /// Find all folder invites from a recipient.
    pub fn find_all_by_from_recipient_id(
        &self,
        from_recipient_id: i64,
        limit: Option<usize>,
    ) -> Result<Vec<FolderInviteRecord>> {
        let limit =
            limit.map(|l| l.to_string()).unwrap_or(String::from("10"));
        let query = folder_invites_select_columns(sql::Select::new())
            .from("folder_invites")
            .where_clause("from_recipient_id = ?1")
            .limit(&limit)
            .order_by("folder_invites.modified_at DESC");

        let mut stmt = self.conn.prepare_cached(&query.as_string())?;

        fn convert_row(row: &Row<'_>) -> Result<FolderInviteRow> {
            Ok(row.try_into()?)
        }

        let rows = stmt.query_and_then([from_recipient_id], convert_row)?;
        let mut invites = Vec::new();
        for row in rows {
            invites.push(row?.try_into()?);
        }
        Ok(invites)
    }

    /// Find all folder invites to a recipient.
    pub fn find_all_by_to_recipient_id(
        &self,
        to_recipient_id: i64,
        limit: Option<usize>,
    ) -> Result<Vec<FolderInviteRecord>> {
        let limit =
            limit.map(|l| l.to_string()).unwrap_or(String::from("10"));
        let query = folder_invites_select_columns(sql::Select::new())
            .from("folder_invites")
            .where_clause("to_recipient_id = ?1")
            .limit(&limit)
            .order_by("folder_invites.modified_at DESC");
        let mut stmt = self.conn.prepare_cached(&query.as_string())?;

        fn convert_row(row: &Row<'_>) -> Result<FolderInviteRow> {
            Ok(row.try_into()?)
        }
        let rows = stmt.query_and_then([to_recipient_id], convert_row)?;
        let mut invites = Vec::new();
        for row in rows {
            invites.push(row?.try_into()?);
        }
        Ok(invites)
    }
}
