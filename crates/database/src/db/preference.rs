use async_sqlite::rusqlite::{Connection, Error as SqlError};
use std::ops::Deref;

/// Preferences entity.
pub struct PreferenceEntity<'conn, C>
where
    C: Deref<Target = Connection>,
{
    conn: &'conn C,
}

impl<'conn, C> PreferenceEntity<'conn, C>
where
    C: Deref<Target = Connection>,
{
    /// Create a new preference entity.
    pub fn new(conn: &'conn C) -> Self {
        Self { conn }
    }

    /// Load preferences from the database.
    ///
    /// When no `account_id` is specified the preferences
    /// are global.
    pub fn load_preferences(
        &self,
        account_id: Option<i64>,
    ) -> std::result::Result<String, SqlError> {
        let mut stmt = self.conn.prepare_cached(
            r#"
                SELECT json_data FROM preferences WHERE account_id=?1
            "#,
        )?;
        Ok(stmt.query_row([account_id], |row| Ok(row.get(0)?))?)
    }

    /// Create preferences in the database.
    ///
    /// When no `account_id` is specified the preferences
    /// are global.
    pub fn insert_preferences(
        &self,
        account_id: Option<i64>,
        json_data: String,
    ) -> std::result::Result<(), SqlError> {
        let mut stmt = self.conn.prepare_cached(
            r#"
              INSERT INTO preferences
                (account_id, json_data)
                VALUES (?1, ?2)
            "#,
        )?;
        stmt.execute((account_id, json_data))?;
        Ok(())
    }
}
