use crate::{
    entity::{FolderEntity, FolderRecord, SecretRow},
    Error, Result,
};
use async_sqlite::{
    rusqlite::{
        Connection, Error as SqlError, OptionalExtension, Row, Transaction,
    },
    Client,
};
use sos_core::{AccountId, PublicIdentity, UtcDateTime, VaultCommit};
use sos_vault::Vault;
use sql_query_builder as sql;
use std::ops::Deref;

use super::FolderRow;

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
#[derive(Debug)]
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

impl<'conn> AccountEntity<'conn, Box<Connection>> {
    /// Liat all accounts.
    pub async fn list_all_accounts(
        client: &Client,
    ) -> Result<Vec<AccountRecord>> {
        let account_rows = client
            .conn_and_then(move |conn| {
                let account = AccountEntity::new(&conn);
                account.list_accounts()
            })
            .await?;

        let mut accounts = Vec::new();
        for row in account_rows {
            accounts.push(row.try_into()?);
        }
        Ok(accounts)
    }

    /// Find an account and login folder.
    pub async fn find_account_with_login(
        client: &Client,
        account_id: &AccountId,
    ) -> Result<(AccountRecord, FolderRecord)> {
        let (account, folder_row) =
            Self::find_account_with_login_optional(client, account_id)
                .await?;

        let account_id = account.row_id;
        Ok((
            account,
            folder_row.ok_or_else(|| Error::NoLoginFolder(account_id))?,
        ))
    }

    /// Find an account and optional login folder.
    pub async fn find_account_with_login_optional(
        client: &Client,
        account_id: &AccountId,
    ) -> Result<(AccountRecord, Option<FolderRecord>)> {
        let account_id = *account_id;
        let (account_row, folder_row) = client
            .conn_and_then(move |conn| {
                let account = AccountEntity::new(&conn);
                let account_row = account.find_one(&account_id)?;
                let folders = FolderEntity::new(&conn);
                let folder_row =
                    folders.find_login_folder_optional(account_row.row_id)?;
                Ok::<_, Error>((account_row, folder_row))
            })
            .await?;

        let login_folder = if let Some(folder_row) = folder_row {
            Some(FolderRecord::from_row(folder_row).await?)
        } else {
            None
        };
        Ok((account_row.try_into()?, login_folder))
    }
}

impl<'conn> AccountEntity<'conn, Transaction<'conn>> {
    /// Upsert the login folder.
    pub async fn upsert_login_folder(
        client: &Client,
        account_id: &AccountId,
        vault: &Vault,
    ) -> Result<(AccountRecord, i64)> {
        // Check if we already have a login folder
        let (account, folder) =
            AccountEntity::find_account_with_login_optional(
                client, account_id,
            )
            .await?;

        // TODO: folder creation and join should be merged into a single
        // TODO: transaction

        // Create or update the folder and secrets
        let (folder_row_id, _) = FolderEntity::upsert_folder_and_secrets(
            client,
            account.row_id,
            vault,
        )
        .await?;

        let account_row_id = account.row_id;

        // Update or insert the join
        if folder.is_some() {
            client
                .conn(move |conn| {
                    let account_entity = AccountEntity::new(&conn);
                    account_entity
                        .update_login_folder(account_row_id, folder_row_id)
                })
                .await?;
        } else {
            client
                .conn(move |conn| {
                    let account_entity = AccountEntity::new(&conn);
                    account_entity
                        .insert_login_folder(account_row_id, folder_row_id)
                })
                .await?;
        }

        Ok((account, folder_row_id))
    }

    /// Replace the login folder.
    pub async fn replace_login_folder(
        client: &mut Client,
        account_id: &AccountId,
        vault: &Vault,
    ) -> Result<()> {
        // Check if we already have a login folder
        let (account, login_folder) =
            AccountEntity::find_account_with_login(client, account_id)
                .await?;

        let login_folder_id = *login_folder.summary.id();
        let new_login_folder = FolderRow::new_insert(vault).await?;

        let mut secret_rows = Vec::new();
        for (secret_id, commit) in vault.iter() {
            let VaultCommit(commit, entry) = commit;
            secret_rows.push(SecretRow::new(secret_id, commit, entry).await?);
        }

        client
            .conn_mut_and_then(move |conn| {
                let tx = conn.transaction()?;
                let account_entity = AccountEntity::new(&tx);
                let folder_entity = FolderEntity::new(&tx);

                // Delete the old folder
                folder_entity.delete_folder(&login_folder_id)?;

                // Create the new folder
                let folder_row_id = folder_entity
                    .insert_folder(account.row_id, &new_login_folder)?;

                // Insert the secrets
                folder_entity.insert_folder_secrets(
                    folder_row_id,
                    secret_rows.as_slice(),
                )?;

                // Update the join
                account_entity
                    .update_login_folder(account.row_id, folder_row_id)?;

                tx.commit()?;
                Ok::<_, Error>(())
            })
            .await?;

        Ok(())
    }
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
        stmt.query_row([account_id.to_string()], |row| row.try_into())
    }

    /// Find an optional account in the database.
    pub fn find_optional(
        &self,
        account_id: &AccountId,
    ) -> std::result::Result<Option<AccountRow>, SqlError> {
        let query = self
            .account_select_columns(sql::Select::new())
            .from("accounts")
            .where_clause("identifier = ?1");
        let mut stmt = self.conn.prepare_cached(&query.as_string())?;
        stmt.query_row([account_id.to_string()], |row| row.try_into())
            .optional()
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

        let rows = stmt.query_and_then([], convert_row)?;
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

    /// Update the join for an account login folder.
    pub fn update_login_folder(
        &self,
        account_id: i64,
        folder_id: i64,
    ) -> std::result::Result<(), SqlError> {
        let query = sql::Update::new()
            .update("account_login_folder")
            .set("folder_id = ?2")
            .where_clause("account_id = ?1");
        self.conn
            .execute(&query.as_string(), [account_id, folder_id])?;
        Ok(())
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
        let query = sql::Delete::new()
            .delete_from("accounts")
            .where_clause("identifier = ?1");
        self.conn
            .execute(&query.as_string(), [account_id.to_string()])?;
        Ok(())
    }
}
