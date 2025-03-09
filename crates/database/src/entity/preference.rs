use crate::{Error, Result};
use async_sqlite::rusqlite::{
    Connection, Error as SqlError, OptionalExtension, Row,
};
use sos_core::UtcDateTime;
use sos_preferences::Preference;
use sql_query_builder as sql;
use std::ops::Deref;

/// Preference row from the database.
#[doc(hidden)]
#[derive(Debug, Default)]
pub struct PreferenceRow {
    pub row_id: i64,
    created_at: String,
    modified_at: String,
    key: String,
    json_data: String,
}

impl PreferenceRow {
    /// Create a preference row to be inserted.
    pub fn new_insert(key: &str, value: &Preference) -> Result<Self> {
        Ok(Self {
            created_at: UtcDateTime::default().to_rfc3339()?,
            modified_at: UtcDateTime::default().to_rfc3339()?,
            key: key.to_owned(),
            json_data: serde_json::to_string(value)?,
            ..Default::default()
        })
    }

    /// Create a preference row to be updated.
    pub fn new_update(key: &str, value: &Preference) -> Result<Self> {
        Ok(Self {
            modified_at: UtcDateTime::default().to_rfc3339()?,
            key: key.to_owned(),
            json_data: serde_json::to_string(value)?,
            ..Default::default()
        })
    }
}

impl<'a> TryFrom<&Row<'a>> for PreferenceRow {
    type Error = SqlError;
    fn try_from(row: &Row<'a>) -> std::result::Result<Self, Self::Error> {
        Ok(PreferenceRow {
            row_id: row.get(0)?,
            created_at: row.get(1)?,
            modified_at: row.get(2)?,
            key: row.get(3)?,
            json_data: row.get(4)?,
        })
    }
}

impl TryFrom<PreferenceRow> for (String, Preference) {
    type Error = Error;

    fn try_from(value: PreferenceRow) -> Result<Self> {
        let pref: Preference = serde_json::from_str(&value.json_data)?;
        Ok((value.key, pref))
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

    fn find_preference_select(&self, select_one: bool) -> sql::Select {
        let mut query = sql::Select::new()
            .select(
                r#"
                    preference_id,
                    created_at,
                    modified_at,
                    key,
                    json_data
                "#,
            )
            .from("preferences")
            .where_clause("account_id=?1");
        if select_one {
            query = query.where_and("key=?2");
        }
        query
    }

    /// Find a preference in the database.
    pub fn find_optional(
        &self,
        account_id: Option<i64>,
        key: &str,
    ) -> std::result::Result<Option<PreferenceRow>, SqlError> {
        let query = self.find_preference_select(true);
        let mut stmt = self.conn.prepare_cached(&query.as_string())?;
        Ok(stmt
            .query_row((account_id, key), |row| Ok(row.try_into()?))
            .optional()?)
    }

    /// Load preferences from the database.
    ///
    /// When no `account_id` is specified the preferences
    /// are global.
    pub fn load_preferences(
        &self,
        account_id: Option<i64>,
    ) -> Result<Vec<PreferenceRow>> {
        let query = self.find_preference_select(false);
        let mut stmt = self.conn.prepare_cached(&query.as_string())?;

        fn convert_row(row: &Row<'_>) -> Result<PreferenceRow> {
            Ok(row.try_into()?)
        }

        let rows = stmt.query_and_then([account_id], |row| {
            Ok::<_, crate::Error>(convert_row(row)?)
        })?;
        let mut preferences = Vec::new();
        for row in rows {
            preferences.push(row?);
        }
        Ok(preferences)
    }

    /// Create preferences in the database.
    ///
    /// When no `account_id` is specified the preferences
    /// are global.
    pub fn insert_preference(
        &self,
        account_id: Option<i64>,
        row: &PreferenceRow,
    ) -> std::result::Result<(), SqlError> {
        let query = sql::Insert::new()
            .insert_into(
                r#"
                preferences
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

    /// Create preferences in the database.
    ///
    /// When no `account_id` is specified the preferences
    /// are global.
    pub fn insert_preferences(
        &self,
        account_id: Option<i64>,
        rows: &[PreferenceRow],
    ) -> std::result::Result<(), SqlError> {
        for row in rows {
            self.insert_preference(account_id, row)?;
        }
        Ok(())
    }

    /// Update preference in the database.
    ///
    /// When no `account_id` is specified the preferences
    /// are global.
    pub fn update_preference(
        &self,
        account_id: Option<i64>,
        row: &PreferenceRow,
    ) -> std::result::Result<(), SqlError> {
        let query = sql::Update::new()
            .update("preferences")
            .set("json_data = ?1, modified_at = ?2")
            .where_clause("account_id = ?3")
            .where_and("key = ?4");
        let mut stmt = self.conn.prepare_cached(&query.as_string())?;
        stmt.execute((
            &row.json_data,
            &row.modified_at,
            account_id,
            &row.key,
        ))?;
        Ok(())
    }

    /// Create or update preferences in the database.
    ///
    /// When no `account_id` is specified the preferences
    /// are global.
    pub fn upsert_preference(
        &self,
        account_id: Option<i64>,
        row: &PreferenceRow,
    ) -> std::result::Result<(), SqlError> {
        let pref_row = self.find_optional(account_id, &row.key)?;
        match pref_row {
            Some(_) => {
                self.update_preference(account_id, row)?;
            }
            None => self.insert_preference(account_id, row)?,
        }
        Ok(())
    }

    /// Delete a preference from the database.
    pub fn delete_preference(
        &self,
        account_id: Option<i64>,
        key: &str,
    ) -> std::result::Result<(), SqlError> {
        let query = sql::Delete::new()
            .delete_from("preferences")
            .where_clause("account_id = ?1")
            .where_and("key = ?2");
        let mut stmt = self.conn.prepare_cached(&query.as_string())?;
        stmt.execute((account_id, key))?;
        Ok(())
    }

    /// Delete all preferences from the database.
    pub fn delete_all_preferences(
        &self,
        account_id: Option<i64>,
    ) -> std::result::Result<(), SqlError> {
        let query = sql::Delete::new()
            .delete_from("preferences")
            .where_clause("account_id = ?1");
        let mut stmt = self.conn.prepare_cached(&query.as_string())?;
        stmt.execute([account_id])?;
        Ok(())
    }
}
