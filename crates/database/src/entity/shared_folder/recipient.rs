use crate::{Error, Result};
use async_sqlite::rusqlite::{
    CachedStatement, Connection, Error as SqlError, OptionalExtension, Row,
};
use sos_core::UtcDateTime;
use sql_query_builder as sql;
use std::{ops::Deref, result::Result as StdResult};

fn select_columns(sql: sql::Select) -> sql::Select {
    sql.select(
        r#"
            recipients.recipient_id,
            recipients.account_id,
            recipients.created_at,
            recipients.modified_at,
            recipients.recipient_name,
            recipients.recipient_email,
            recipients.recipient_public_key,
            recipients.revoked
        "#,
    )
}

/// Represents a recipient.
#[doc(hidden)]
#[derive(Debug)]
pub struct RecipientRow {
    pub recipient_id: i64,
    pub account_id: i64,
    pub created_at: String,
    pub modified_at: String,
    pub recipient_name: String,
    pub recipient_email: Option<String>,
    pub recipient_public_key: String,
    pub revoked: i64,
}

impl<'a> TryFrom<&Row<'a>> for RecipientRow {
    type Error = SqlError;
    fn try_from(row: &Row<'a>) -> StdResult<Self, Self::Error> {
        Ok(RecipientRow {
            recipient_id: row.get(0)?,
            account_id: row.get(1)?,
            created_at: row.get(2)?,
            modified_at: row.get(3)?,
            recipient_name: row.get(4)?,
            recipient_email: row.get(5)?,
            recipient_public_key: row.get(6)?,
            revoked: row.get(7)?,
        })
    }
}

impl RecipientRow {
    /// Create a new recipient row to be inserted.
    pub fn new_insert(
        account_id: i64,
        recipient_name: String,
        recipient_email: Option<String>,
        recipient_public_key: String,
    ) -> Result<Self> {
        Ok(Self {
            recipient_id: 0,
            account_id,
            created_at: UtcDateTime::default().to_rfc3339()?,
            modified_at: UtcDateTime::default().to_rfc3339()?,
            recipient_name,
            recipient_email,
            recipient_public_key,
            revoked: 0,
        })
    }

    /// Create a new recipient row to update.
    pub fn new_update(
        &self,
        recipient_name: String,
        recipient_email: Option<String>,
        recipient_public_key: String,
    ) -> Result<Self> {
        Ok(RecipientRow {
            recipient_id: self.recipient_id,
            account_id: self.account_id,
            created_at: self.created_at.clone(),
            modified_at: UtcDateTime::default().to_rfc3339()?,
            recipient_name,
            recipient_email,
            recipient_public_key,
            revoked: self.revoked,
        })
    }
}

/// Record for a recipient.
#[derive(Debug)]
pub struct RecipientRecord {
    /// Row identifier.
    pub row_id: i64,
    /// Created date and time.
    pub created_at: UtcDateTime,
    /// Modified date and time.
    pub modified_at: UtcDateTime,
    /// Recipient public name.
    pub recipient_name: String,
    /// Recipient email address.
    pub recipient_email: Option<String>,
    /// Recipient public key.
    pub recipient_public_key: String,
    /// Whether the recipient public key has been revoked.
    pub revoked: bool,
}

impl TryFrom<RecipientRow> for RecipientRecord {
    type Error = Error;

    fn try_from(value: RecipientRow) -> Result<Self> {
        Ok(Self {
            row_id: value.recipient_id,
            created_at: UtcDateTime::parse_rfc3339(&value.created_at)?,
            modified_at: UtcDateTime::parse_rfc3339(&value.modified_at)?,
            recipient_name: value.recipient_name,
            recipient_email: value.recipient_email,
            recipient_public_key: value.recipient_public_key,
            revoked: value.revoked > 0,
        })
    }
}

/// Recipient entity.
pub struct RecipientEntity<'conn, C>
where
    C: Deref<Target = Connection>,
{
    conn: &'conn C,
}

impl<'conn, C> RecipientEntity<'conn, C>
where
    C: Deref<Target = Connection>,
{
    /// Create a new shared folder recipient.
    pub fn new(conn: &'conn C) -> Self {
        Self { conn }
    }

    fn select_recipient<'a>(
        &'a self,
    ) -> StdResult<CachedStatement<'a>, SqlError> {
        let query = select_columns(sql::Select::new())
            .from("recipients")
            .where_clause("account_id = ?1");
        self.conn.prepare_cached(&query.as_string())
    }

    /// Find a recipient in the database.
    pub fn find_one(
        &self,
        account_id: i64,
    ) -> StdResult<RecipientRow, SqlError> {
        let mut stmt = self.select_recipient()?;
        stmt.query_row([account_id], |row| row.try_into())
    }

    /// Find an optional recipient in the database.
    pub fn find_optional(
        &self,
        account_id: i64,
    ) -> StdResult<Option<RecipientRow>, SqlError> {
        let mut stmt = self.select_recipient()?;
        stmt.query_row([account_id], |row| {
            let row: RecipientRow = row.try_into()?;
            Ok(row)
        })
        .optional()
    }

    /// Find an optional recipient by public key.
    pub fn find_by_public_key(
        &self,
        public_key: &str,
    ) -> StdResult<Option<RecipientRow>, SqlError> {
        let query = select_columns(sql::Select::new())
            .from("recipients")
            .where_clause("recipient_public_key = ?1");
        let mut stmt = self.conn.prepare_cached(&query.as_string())?;
        stmt.query_row([public_key], |row| {
            let row: RecipientRow = row.try_into()?;
            Ok(row)
        })
        .optional()
    }

    /// Create the recipient entity in the database.
    pub fn insert_recipient(
        &self,
        recipient_row: &RecipientRow,
    ) -> StdResult<i64, SqlError> {
        let query = sql::Insert::new()
            .insert_into(
                r#"
                recipients
                (
                    account_id,
                    created_at,
                    modified_at,
                    recipient_name,
                    recipient_email,
                    recipient_public_key
                )
            "#,
            )
            .values("(?1, ?2, ?3, ?4, ?5, ?6)");

        let mut stmt = self.conn.prepare_cached(&query.as_string())?;
        stmt.execute((
            &recipient_row.account_id,
            &recipient_row.created_at,
            &recipient_row.modified_at,
            &recipient_row.recipient_name,
            &recipient_row.recipient_email,
            &recipient_row.recipient_public_key,
        ))?;
        Ok(self.conn.last_insert_rowid())
    }

    /// Update the recipient entity in the database.
    pub fn update_recipient(
        &self,
        recipient_row: &RecipientRow,
    ) -> StdResult<(), SqlError> {
        let query = sql::Update::new()
            .update("recipients")
            .set(
                r#"
                    modified_at = ?1,
                    recipient_name = ?2,
                    recipient_email = ?3,
                    recipient_public_key = ?4
                 "#,
            )
            .where_clause("recipient_id=?5");
        let mut stmt = self.conn.prepare_cached(&query.as_string())?;
        stmt.execute((
            &recipient_row.modified_at,
            &recipient_row.recipient_name,
            &recipient_row.recipient_email,
            &recipient_row.recipient_public_key,
            recipient_row.recipient_id,
        ))?;

        Ok(())
    }

    /// Search for recipients
    pub fn search_recipients(
        &mut self,
        search_query: &str,
    ) -> Result<Vec<RecipientRecord>> {
        let search_query = search_query
            .split_whitespace()
            .map(|word| format!("\"{}\"", word))
            .collect::<Vec<_>>()
            .join(" OR ");

        let query = sql::Select::new()
            .select(
                r#"
                r.recipient_id,
                r.account_id,
                r.created_at,
                r.modified_at,
                r.recipient_name,
                r.recipient_email,
                r.recipient_public_key,
                r.revoked,
                fts.rowid,
                fts.rank
            "#,
            )
            .from("recipients_fts AS fts")
            .inner_join("recipients AS r ON fts.rowid = r.recipient_id")
            .where_clause("recipients_fts MATCH ?1")
            .order_by("fts.rank DESC")
            .limit("25");

        let mut stmt = self.conn.prepare_cached(&query.as_string())?;
        fn convert_row(row: &Row<'_>) -> Result<RecipientRow> {
            Ok(row.try_into()?)
        }

        let rows = stmt.query_and_then([search_query], convert_row)?;
        let mut recipients = Vec::new();
        for row in rows {
            recipients.push(row?.try_into()?);
        }
        Ok(recipients)
    }
}
