use async_sqlite::rusqlite::{Connection, Error as SqlError};
use std::ops::Deref;

pub struct AccountEntity<'conn, C>
where
    C: Deref<Target = Connection>,
{
    conn: &'conn C,
}

impl<'conn, C> AccountEntity<'conn, C>
where
    C: Deref<Target = Connection>,
{
    /// Create a new account entity.
    pub fn new(conn: &'conn C) -> Self {
        Self { conn }
    }

    /// Create the account entity in the database.
    pub fn insert(
        &self,
        account_identifier: &str,
        account_name: &str,
    ) -> Result<i64, SqlError> {
        self.conn.execute(
            r#"
            INSERT INTO accounts (identifier, name)
            VALUES (?1, ?2)
          "#,
            (account_identifier, account_name),
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    /// Create the join for the account login folder.
    pub fn insert_login_folder(
        &self,
        account_id: i64,
        folder_id: i64,
    ) -> Result<i64, SqlError> {
        self.conn.execute(
            r#"
              INSERT INTO account_login_folder (account_id, folder_id) 
              VALUES (?1, ?2)
            "#,
            (&account_id, &folder_id),
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    /// Create the join for the account device folder.
    pub fn insert_device_folder(
        &self,
        account_id: i64,
        folder_id: i64,
    ) -> Result<i64, SqlError> {
        self.conn.execute(
            r#"
              INSERT INTO account_device_folder (account_id, folder_id) 
              VALUES (?1, ?2)
            "#,
            (&account_id, &folder_id),
        )?;
        Ok(self.conn.last_insert_rowid())
    }
}
