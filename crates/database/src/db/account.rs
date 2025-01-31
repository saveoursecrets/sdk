use crate::{Error, Result};
use async_sqlite::rusqlite::{Connection, Error as SqlError, Row};
use sos_core::{AccountId, PublicIdentity, UtcDateTime};
use sql_query_builder as sql;
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
    pub fn new_insert(account_id: &AccountId, name: String) -> Result<Self> {
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
    fn try_from(row: &Row<'a>) -> std::result::Result<Self, Self::Error> {
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

    fn try_from(value: AccountRow) -> std::result::Result<Self, Self::Error> {
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

    fn account_select_columns(&self, sql: sql::Select) -> sql::Select {
        sql.select(
            r#"
                account_id,
                created_at,
                modified_at,
                identifier,
                name
            "#,
        )
    }

    /// Find an account in the database.
    pub fn find_one(
        &self,
        account_id: &AccountId,
    ) -> std::result::Result<AccountRow, SqlError> {
        let query = self
            .account_select_columns(sql::Select::new())
            .from("accounts")
            .where_clause("identifier = ?1");
        let mut stmt = self.conn.prepare_cached(&query.as_string())?;
        Ok(stmt
            .query_row([account_id.to_string()], |row| Ok(row.try_into()?))?)
    }

    /// List accounts.
    pub fn list_accounts(&self) -> Result<Vec<AccountRow>> {
        let query = self
            .account_select_columns(sql::Select::new())
            .from("accounts");

        let mut stmt = self.conn.prepare_cached(&query.as_string())?;

        fn convert_row(row: &Row<'_>) -> Result<AccountRow> {
            Ok(row.try_into()?)
        }

        let rows = stmt.query_and_then([], |row| {
            Ok::<_, crate::Error>(convert_row(row)?)
        })?;
        let mut accounts = Vec::new();
        for row in rows {
            accounts.push(row?);
        }
        Ok(accounts)
    }

    /// Create the account entity in the database.
    pub fn insert(
        &self,
        row: &AccountRow,
    ) -> std::result::Result<i64, SqlError> {
        let query = sql::Insert::new()
            .insert_into(
                "accounts (created_at, modified_at, identifier, name)",
            )
            .values("(?1, ?2, ?3, ?4)");
        self.conn.execute(
            &query.as_string(),
            (
                &row.created_at,
                &row.modified_at,
                &row.identifier,
                &row.name,
            ),
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    /// Create the join for the account login folder.
    pub fn insert_login_folder(
        &self,
        account_id: i64,
        folder_id: i64,
    ) -> std::result::Result<i64, SqlError> {
        let query = sql::Insert::new()
            .insert_into("account_login_folder (account_id, folder_id)")
            .values("(?1, ?2)");
        self.conn
            .execute(&query.as_string(), [account_id, folder_id])?;
        Ok(self.conn.last_insert_rowid())
    }

    /// Create the join for the account device folder.
    pub fn insert_device_folder(
        &self,
        account_id: i64,
        folder_id: i64,
    ) -> std::result::Result<i64, SqlError> {
        let query = sql::Insert::new()
            .insert_into("account_device_folder (account_id, folder_id)")
            .values("(?1, ?2)");
        self.conn
            .execute(&query.as_string(), [account_id, folder_id])?;
        Ok(self.conn.last_insert_rowid())
    }

    /// Rename the account.
    pub fn rename_account(&self, account_id: i64, name: &str) -> Result<()> {
        let modified_at = UtcDateTime::default().to_rfc3339()?;
        let query = sql::Update::new()
            .update("accounts")
            .set("name = ?1, modified_at = ?2")
            .where_clause("account_id = ?3");
        let mut stmt = self.conn.prepare_cached(&query.as_string())?;
        stmt.execute((name, modified_at, account_id))?;
        Ok(())
    }

    /// Delete the account from the database.
    pub fn delete_account(
        &self,
        account_id: &AccountId,
    ) -> std::result::Result<(), SqlError> {
        let account_row = self.find_one(account_id)?;
        let query = sql::Delete::new()
            .delete_from("accounts")
            .where_clause("account_id = ?1");
        self.conn
            .execute(&query.as_string(), [account_row.row_id])?;
        Ok(())
    }
}
