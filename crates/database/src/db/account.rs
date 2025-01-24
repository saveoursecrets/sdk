use crate::{
    db::{FolderEntity, FolderRow},
    Error,
};
use async_sqlite::rusqlite::{Connection, Error as SqlError, Row};
use sos_core::{AccountId, PublicIdentity, UtcDateTime};
use std::ops::Deref;

/// Account row from the database.
#[doc(hidden)]
#[derive(Debug, Default)]
pub struct AccountRow {
    /// Row identifier.
    pub row_id: i64,
    /// RFC3339 date and time.
    created_at: String,
    /// RFC3339 date and time.
    modified_at: String,
    /// Account identifier.
    identifier: String,
    /// Account name.
    name: String,
}

impl AccountRow {
    /// Create an account row for insertion.
    pub fn new_insert(
        account_id: &AccountId,
        name: String,
    ) -> Result<Self, Error> {
        Ok(AccountRow {
            identifier: account_id.to_string(),
            name,
            created_at: UtcDateTime::default().to_rfc3339()?,
            modified_at: UtcDateTime::default().to_rfc3339()?,
            ..Default::default()
        })
    }
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
        let created_at = UtcDateTime::parse_rfc3339(&value.created_at)?;
        let modified_at = UtcDateTime::parse_rfc3339(&value.modified_at)?;
        let account_id: AccountId = value.identifier.parse()?;
        Ok(AccountRecord {
            row_id: value.row_id,
            created_at,
            modified_at,
            identity: PublicIdentity::new(account_id, value.name),
        })
    }
}

/// Account folder join.
#[doc(hidden)]
#[derive(Debug, Default)]
pub struct AccountFolderJoin {
    /// Account identifier.
    pub account_id: i64,
    /// Folder identifier.
    pub folder_id: i64,
}

impl<'a> TryFrom<&Row<'a>> for AccountFolderJoin {
    type Error = SqlError;
    fn try_from(row: &Row<'a>) -> Result<Self, Self::Error> {
        Ok(AccountFolderJoin {
            account_id: row.get(0)?,
            folder_id: row.get(1)?,
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

    /// Try to find a login folder for an account.
    pub fn find_login_folder(
        &self,
        account_id: &AccountId,
    ) -> Result<(AccountRow, FolderRow), SqlError> {
        let account_row = self.find_one(account_id)?;

        // TODO: proper join query here!
        let mut stmt = self.conn.prepare_cached(
            r#"
                SELECT
                    account_id,
                    folder_id
                FROM account_login_folder
                WHERE account_id=?1
            "#,
        )?;
        let join_row: AccountFolderJoin =
            stmt.query_row([account_row.row_id], |row| Ok(row.try_into()?))?;

        let folder = FolderEntity::new(self.conn);
        let folder_row = folder.find_by_row_id(join_row.folder_id)?;
        Ok((account_row, folder_row))
    }

    /// Create the account entity in the database.
    pub fn insert(&self, row: &AccountRow) -> Result<i64, SqlError> {
        self.conn.execute(
            r#"
            INSERT INTO accounts (identifier, name, created_at, modified_at)
            VALUES (?1, ?2, ?3, ?4)
          "#,
            (
                &row.identifier,
                &row.name,
                &row.created_at,
                &row.modified_at,
            ),
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
            [account_id, folder_id],
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
            [account_id, folder_id],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    /// Delete the account from the database.
    pub fn delete_account(
        &self,
        account_id: &AccountId,
    ) -> Result<(), SqlError> {
        let account_row = self.find_one(account_id)?;
        self.conn.execute(
            r#"
              DELETE FROM accounts WHERE account_id=?1
            "#,
            [account_row.row_id],
        )?;
        Ok(())
    }
}
