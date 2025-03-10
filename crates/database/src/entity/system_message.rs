use crate::Result;
use async_sqlite::rusqlite::{Connection, Error as SqlError, Row};
use sos_core::UtcDateTime;
use sos_system_messages::SysMessage;
use sql_query_builder as sql;
use std::ops::Deref;
use urn::Urn;

/// SystemMessage row from the database.
#[doc(hidden)]
#[derive(Debug, Default)]
pub struct SystemMessageRow {
    pub row_id: i64,
    created_at: String,
    modified_at: String,
    key: String,
    json_data: String,
}

impl<'a> TryFrom<&Row<'a>> for SystemMessageRow {
    type Error = SqlError;
    fn try_from(row: &Row<'a>) -> std::result::Result<Self, Self::Error> {
        Ok(SystemMessageRow {
            row_id: row.get(0)?,
            created_at: row.get(1)?,
            modified_at: row.get(2)?,
            key: row.get(3)?,
            json_data: row.get(4)?,
        })
    }
}

impl TryFrom<SystemMessageRow> for (Urn, SysMessage) {
    type Error = crate::Error;
    fn try_from(
        row: SystemMessageRow,
    ) -> std::result::Result<Self, Self::Error> {
        Ok((row.key.parse()?, serde_json::from_str(&row.json_data)?))
    }
}

impl TryFrom<(Urn, SysMessage)> for SystemMessageRow {
    type Error = crate::Error;
    fn try_from(
        value: (Urn, SysMessage),
    ) -> std::result::Result<Self, Self::Error> {
        Ok(Self {
            created_at: UtcDateTime::default().to_rfc3339()?,
            modified_at: UtcDateTime::default().to_rfc3339()?,
            key: value.0.to_string(),
            json_data: serde_json::to_string(&value.1)?,
            ..Default::default()
        })
    }
}

/// SystemMessage entity.
pub struct SystemMessageEntity<'conn, C>
where
    C: Deref<Target = Connection>,
{
    conn: &'conn C,
}

impl<'conn, C> SystemMessageEntity<'conn, C>
where
    C: Deref<Target = Connection>,
{
    /// Create a new server entity.
    pub fn new(conn: &'conn C) -> Self {
        Self { conn }
    }

    /// Load system messages for an account.
    pub fn load_system_messages(
        &self,
        account_id: i64,
    ) -> Result<Vec<SystemMessageRow>> {
        let query = sql::Select::new()
            .select(
                r#"
                    system_message_id,
                    created_at,
                    modified_at,
                    key,
                    json_data
                "#,
            )
            .from("system_messages")
            .where_clause("account_id = ?1");
        let mut stmt = self.conn.prepare_cached(&query.as_string())?;

        fn convert_row(row: &Row<'_>) -> Result<SystemMessageRow> {
            Ok(row.try_into()?)
        }

        let rows = stmt.query_and_then([account_id], |row| {
            Ok::<_, crate::Error>(convert_row(row)?)
        })?;
        let mut messages = Vec::new();
        for row in rows {
            messages.push(row?);
        }
        Ok(messages)
    }

    /// Update the is_read flag for a system message.
    pub fn mark_system_message(
        &self,
        account_id: i64,
        key: &str,
        is_read: bool,
    ) -> Result<()> {
        let modified_at = UtcDateTime::default().to_rfc3339()?;
        let query = sql::Update::new()
            .update("system_messages")
            .set(
                "
                modified_at = ?1,
                json_data = json_replace (json_data, '$.isRead', ?2)
            ",
            )
            .where_clause("account_id = ?3")
            .where_and("key = ?4");
        let mut stmt = self.conn.prepare_cached(&query.as_string())?;
        stmt.execute((modified_at, is_read, account_id, key))?;
        Ok(())
    }

    /// Delete a system message for an account.
    pub fn delete_system_message(
        &self,
        account_id: i64,
        key: &str,
    ) -> std::result::Result<(), SqlError> {
        let query = sql::Delete::new()
            .delete_from("system_messages")
            .where_clause("account_id = ?1")
            .where_and("key = ?2");
        let mut stmt = self.conn.prepare_cached(&query.as_string())?;
        stmt.execute((account_id, key))?;
        Ok(())
    }

    /// Delete system messages for an account.
    pub fn delete_system_messages(
        &self,
        account_id: i64,
    ) -> std::result::Result<(), SqlError> {
        let query = sql::Delete::new()
            .delete_from("system_messages")
            .where_clause("account_id = ?1");
        let mut stmt = self.conn.prepare_cached(&query.as_string())?;
        stmt.execute([account_id])?;
        Ok(())
    }

    /// Create system message in the database.
    pub fn insert_system_message(
        &self,
        account_id: i64,
        row: &SystemMessageRow,
    ) -> std::result::Result<(), SqlError> {
        let query = sql::Insert::new()
            .insert_into(
                r#"
                system_messages
                (
                    account_id,
                    created_at,
                    modified_at,
                    key,
                    json_data
                )
                "#,
            )
            .values("(?1, ?2, ?3, ?4, ?5)");
        let mut stmt = self.conn.prepare_cached(&query.as_string())?;
        stmt.execute((
            account_id,
            &row.created_at,
            &row.modified_at,
            &row.key,
            &row.json_data,
        ))?;
        Ok(())
    }

    /// Create system messages in the database.
    pub fn insert_system_messages(
        &self,
        account_id: i64,
        system_messages: &[SystemMessageRow],
    ) -> std::result::Result<(), SqlError> {
        for row in system_messages {
            self.insert_system_message(account_id, row)?;
        }
        Ok(())
    }
}
