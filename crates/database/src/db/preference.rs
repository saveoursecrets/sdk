use async_sqlite::rusqlite::{Connection, Error as SqlError};
use std::ops::Deref;

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
