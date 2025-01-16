use async_sqlite::rusqlite::{
    Connection, Error as SqlError, OptionalExtension, Row,
};
use std::ops::Deref;

/// Preference row from the database.
#[doc(hidden)]
#[derive(Debug)]
pub struct PreferenceRow {
    pub row_id: i64,
    pub created_at: String,
    pub modified_at: String,
    pub json_data: String,
}

impl<'a> TryFrom<&Row<'a>> for PreferenceRow {
    type Error = SqlError;
    fn try_from(row: &Row<'a>) -> Result<Self, Self::Error> {
        Ok(PreferenceRow {
            row_id: row.get(0)?,
            created_at: row.get(1)?,
            modified_at: row.get(2)?,
            json_data: row.get(3)?,
        })
    }
}

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

    /// Find a collection of preferences in the database.
    pub fn find_optional(
        &self,
        account_id: Option<i64>,
    ) -> Result<Option<PreferenceRow>, SqlError> {
        let mut stmt = self.conn.prepare_cached(
            r#"
                SELECT
                    preference_id,
                    created_at,
                    modified_at,
                    json_data
                FROM preferences
                WHERE account_id=?1
            "#,
        )?;
        Ok(stmt
            .query_row([account_id], |row| Ok(row.try_into()?))
            .optional()?)
    }

    /// Load preferences from the database.
    ///
    /// When no `account_id` is specified the preferences
    /// are global.
    pub fn load_preferences(
        &self,
        account_id: Option<i64>,
    ) -> std::result::Result<Option<String>, SqlError> {
        let mut stmt = self.conn.prepare_cached(
            r#"
                SELECT json_data FROM preferences WHERE account_id=?1
            "#,
        )?;
        Ok(stmt
            .query_row([account_id], |row| Ok(row.get(0)?))
            .optional()?)
    }

    /// Create preferences in the database.
    ///
    /// When no `account_id` is specified the preferences
    /// are global.
    pub fn insert_preferences(
        &self,
        account_id: Option<i64>,
        json_data: &str,
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

    /// Update preferences in the database.
    ///
    /// When no `account_id` is specified the preferences
    /// are global.
    pub fn update_preferences(
        &self,
        account_id: Option<i64>,
        json_data: &str,
    ) -> std::result::Result<(), SqlError> {
        let mut stmt = self.conn.prepare_cached(
            r#"
              UPDATE preferences
                SET json_data=?1
                WHERE account_id=?2
            "#,
        )?;
        stmt.execute((json_data, account_id))?;
        Ok(())
    }

    /// Create or update preferences in the database.
    ///
    /// When no `account_id` is specified the preferences
    /// are global.
    pub fn upsert_preferences(
        &self,
        account_id: Option<i64>,
        json_data: &str,
    ) -> std::result::Result<(), SqlError> {
        let pref_row = self.find_optional(account_id)?;
        match pref_row {
            Some(_) => {
                self.update_preferences(account_id, json_data)?;
            }
            None => self.insert_preferences(account_id, json_data)?,
        }
        Ok(())
    }
}
