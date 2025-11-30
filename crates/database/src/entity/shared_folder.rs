use crate::{Error, Result};
use async_sqlite::rusqlite::{
    CachedStatement, Connection, Error as SqlError, OptionalExtension, Row,
    Transaction,
};
use async_sqlite::Client;
use sos_core::UtcDateTime;
use sql_query_builder as sql;
use std::{ops::Deref, result::Result as StdResult};

fn recipient_select_columns(sql: sql::Select) -> sql::Select {
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
    recipient_id: i64,
    account_id: i64,
    created_at: String,
    modified_at: String,
    recipient_name: String,
    recipient_email: Option<String>,
    recipient_public_key: String,
    revoked: i64,
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

/// Join table for shared folders.
pub struct AccountSharedFolderRow {
    account_id: i64,
    folder_id: i64,
}

/// Represents an invite to a shared folder.
pub struct FolderInviteRow {
    folder_invite_id: i64,
    created_at: String,
    from_recipient: i64,
    to_recipient: i64,
    folder_id: i64,
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
    /// Create a new shared folder entity.
    pub fn new(conn: &'conn C) -> Self {
        Self { conn }
    }

    fn select_recipient<'a>(
        &'a self,
    ) -> StdResult<CachedStatement<'a>, SqlError> {
        let query = recipient_select_columns(sql::Select::new())
            .from("recipients")
            .where_clause("account_id = ?1");
        self.conn.prepare_cached(&query.as_string())
    }

    /// Find a folder in the database.
    pub fn find_one_recipient(
        &self,
        account_id: i64,
    ) -> StdResult<RecipientRow, SqlError> {
        let mut stmt = self.select_recipient()?;
        stmt.query_row([account_id], |row| row.try_into())
    }

    /// Find an optional folder in the database.
    pub fn find_optional_recipient(
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

    /// Create the recipient entity in the database.
    pub fn insert_recipient(
        &self,
        recipient_row: &RecipientRow,
    ) -> StdResult<i64, SqlError> {
        let query = sql::Insert::new()
            .insert_into(
                r#"
                recipients,
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
            .where_clause("identifier=?12");
        let mut stmt = self.conn.prepare_cached(&query.as_string())?;
        stmt.execute((
            &recipient_row.modified_at,
            &recipient_row.recipient_name,
            &recipient_row.recipient_email,
            &recipient_row.recipient_public_key,
        ))?;

        Ok(())
    }
}

/// Shared folder entity.
pub struct SharedFolderEntity<'conn, C>
where
    C: Deref<Target = Connection>,
{
    conn: &'conn C,
}

impl<'conn> SharedFolderEntity<'conn, Transaction<'conn>> {
    /// Create or update recipient information for an account.
    pub async fn upsert_recipient(
        client: &Client,
        account_id: i64,
        recipient_name: String,
        recipient_email: Option<String>,
        recipient_public_key: String,
    ) -> Result<i64> {
        client
            .conn_mut_and_then(move |conn| {
                let tx = conn.transaction()?;
                let recipient_entity = RecipientEntity::new(&tx);

                let recipient_id = if let Some(recipient_row) =
                    recipient_entity.find_optional_recipient(account_id)?
                {
                    let recipient_row = recipient_row.new_update(
                        recipient_name,
                        recipient_email,
                        recipient_public_key,
                    )?;
                    recipient_entity.update_recipient(&recipient_row)?;
                    recipient_row.recipient_id
                } else {
                    let recipient_row = RecipientRow::new_insert(
                        account_id,
                        recipient_name,
                        recipient_email,
                        recipient_public_key,
                    )?;

                    recipient_entity.insert_recipient(&recipient_row)?
                };

                tx.commit()?;
                Ok::<_, Error>(recipient_id)
            })
            .await
    }

    /// Invite a recipient to a folder.
    pub async fn invite_recipient(
        client: &Client,
        from_recipient: i64,
        to_recipient: i64,
        folder_id: i64,
    ) -> Result<i64> {
        todo!();
    }
}
