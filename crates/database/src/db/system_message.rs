use crate::Result;
use async_sqlite::rusqlite::{Connection, Error as SqlError, Row};
use sos_system_messages::SysMessage;
use std::ops::Deref;
use urn::Urn;

/// SystemMessage row from the database.
#[doc(hidden)]
#[derive(Debug)]
pub struct SystemMessageRow {
    pub row_id: i64,
    pub created_at: String,
    pub modified_at: String,
    pub key: String,
    pub json_data: String,
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

    /*
    fn find_server_statement(
        &self,
    ) -> std::result::Result<CachedStatement, SqlError> {
        Ok(self.conn.prepare_cached(
            r#"
                SELECT
                    system_message_id,
                    created_at,
                    modified_at,
                    key,
                    json_data
                FROM system_messages
                WHERE account_id=?1
            "#,
        )?)
    }

    /// Find a system message in the database.
    pub fn find_one(
        &self,
        account_id: i64,
    ) -> std::result::Result<SystemMessageRow, SqlError> {
        let mut stmt = self.find_server_statement()?;
        Ok(stmt.query_row((account_id), |row| {
            Ok(row.try_into()?)
        })?)
    }

    /// Find an optional server in the database.
    pub fn find_optional(
        &self,
        account_id: i64,
        url: &Url,
    ) -> std::result::Result<Option<SystemMessageRow>, SqlError> {
        let mut stmt = self.find_server_statement()?;
        Ok(stmt
            .query_row((account_id, url.to_string()), |row| {
                Ok(row.try_into()?)
            })
            .optional()?)
    }
    */

    /// Load system messages for an account.
    pub fn load_system_messages(
        &self,
        account_id: i64,
    ) -> Result<Vec<SystemMessageRow>> {
        let mut stmt = self.conn.prepare_cached(
            r#"
                SELECT
                    system_message_id,
                    created_at,
                    modified_at,
                    key,
                    json_data
                FROM system_messages
                WHERE account_id=?1
            "#,
        )?;

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
    ) -> std::result::Result<(), SqlError> {
        let mut stmt = self.conn.prepare_cached(
            r#"
                UPDATE system_messages
                SET
                  json_data = json_replace (json_data, '$.isRead', ?1)
                WHERE account_id=?2 AND key=?3
            "#,
        )?;
        stmt.execute((is_read, account_id, key))?;

        Ok(())
    }

    /// Delete a system message for an account.
    pub fn delete_system_message(
        &self,
        account_id: i64,
        key: &str,
    ) -> std::result::Result<(), SqlError> {
        let mut stmt = self.conn.prepare_cached(
            r#"
                DELETE FROM system_messages WHERE account_id=?1 AND key=?2
            "#,
        )?;
        stmt.execute((account_id, key))?;
        Ok(())
    }

    /// Delete system messages for an account.
    pub fn delete_system_messages(
        &self,
        account_id: i64,
    ) -> std::result::Result<(), SqlError> {
        let mut stmt = self.conn.prepare_cached(
            r#"
                DELETE FROM system_messages WHERE account_id=?1
            "#,
        )?;
        stmt.execute([account_id])?;
        Ok(())
    }

    /// Create system message in the database.
    pub fn insert_system_message(
        &self,
        account_id: i64,
        key: &str,
        json_data: &str,
    ) -> std::result::Result<(), SqlError> {
        let mut stmt = self.conn.prepare_cached(
            r#"
              INSERT INTO system_messages
                (account_id, key, json_data)
                VALUES (?1, ?2, ?3)
            "#,
        )?;
        stmt.execute((account_id, key, json_data))?;
        Ok(())
    }

    /// Create system messages in the database.
    pub fn insert_system_messages(
        &self,
        account_id: i64,
        system_messages: Vec<(&str, &str)>,
    ) -> std::result::Result<(), SqlError> {
        for (key, json_data) in system_messages {
            self.insert_system_message(account_id, key, json_data)?;
        }
        Ok(())
    }
}
