use crate::Error;
use async_sqlite::rusqlite::{Connection, Error as SqlError, Row};
use sos_core::{AccountId, PublicIdentity, UtcDateTime};
use std::ops::Deref;

/// Account row from the database.
#[doc(hidden)]
#[derive(Debug)]
pub struct AccountRow {
    pub row_id: i64,
    pub created_at: String,
    pub modified_at: String,
    pub identifier: String,
    pub name: String,
}

impl<'a> TryFrom<&Row<'a>> for AccountRow {
    type Error = SqlError;
    fn try_from(row: &Row<'a>) -> Result<Self, Self::Error> {
        Ok(AccountRow {
            row_id: row.get(0)?,
            created_at: row.get(1)?,
            modified_at: row.get(2)?,
            identifier: row.get(3)?,
            name: row.get(4)?,
        })
    }
}

/// Account record from the database.
pub struct AccountRecord {
    /// Row identifier.
    pub row_id: i64,
    /// Created date and time.
    pub created_at: UtcDateTime,
    /// Modified date and time.
    pub modified_at: UtcDateTime,
    /// Account identity.
    pub identity: PublicIdentity,
}

impl TryFrom<AccountRow> for AccountRecord {
    type Error = Error;

    fn try_from(value: AccountRow) -> Result<Self, Self::Error> {
        let created_at = UtcDateTime::parse_utc_iso8601(&value.created_at)?;
        let modified_at = UtcDateTime::parse_utc_iso8601(&value.modified_at)?;
        let account_id: AccountId = value.identifier.parse()?;

        Ok(AccountRecord {
            row_id: value.row_id,
            created_at,
            modified_at,
            identity: PublicIdentity::new(account_id, value.name),
        })
    }
}

/// Account entity.
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

    /// Find an account in the database.
    pub fn find_one(
        &self,
        account_id: &AccountId,
    ) -> Result<AccountRow, SqlError> {
        let mut stmt = self.conn.prepare_cached(
            r#"
                SELECT
                    account_id,
                    created_at,
                    modified_at,
                    identifier,
                    name
                FROM accounts
                WHERE identifier=?1
            "#,
        )?;
        Ok(stmt
            .query_row([account_id.to_string()], |row| Ok(row.try_into()?))?)
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
