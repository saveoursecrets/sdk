use crate::{Error, Result};
use async_sqlite::rusqlite::{
    CachedStatement, Connection, Error as SqlError, OptionalExtension, Row,
    Transaction,
};
use async_sqlite::Client;
use sos_core::crypto::Seed;
use sos_core::{
    commit::CommitHash, crypto::AeadPack, decode, encode, SecretId,
    UtcDateTime, VaultCommit, VaultEntry, VaultFlags, VaultId,
};
use sos_vault::{Summary, Vault};
use sql_query_builder as sql;
use std::collections::HashMap;
use std::ops::Deref;
use std::result::Result as StdResult;

fn folder_select_columns(sql: sql::Select) -> sql::Select {
    sql.select(
        r#"
            folders.folder_id,
            folders.created_at,
            folders.modified_at,
            folders.identifier,
            folders.name,
            folders.salt,
            folders.meta,
            folders.seed,
            folders.version,
            folders.cipher,
            folders.kdf,
            folders.flags
        "#,
    )
}

fn secret_select_columns(sql: sql::Select) -> sql::Select {
    sql.select(
        r#"
            secret_id,
            created_at,
            modified_at,
            identifier,
            commit_hash,
            meta,
            secret 
        "#,
    )
}

/// Folder row from the database.
#[doc(hidden)]
#[derive(Debug, Default)]
pub struct FolderRow {
    pub row_id: i64,
    created_at: String,
    modified_at: String,
    identifier: String,
    name: String,
    salt: Option<String>,
    meta: Option<Vec<u8>>,
    seed: Option<Vec<u8>>,
    version: i64,
    cipher: String,
    kdf: String,
    flags: Vec<u8>,
}

impl FolderRow {
    /// Create a new folder row to insert.
    pub async fn new_insert(vault: &Vault) -> Result<Self> {
        let meta = if let Some(meta) = vault.header().meta() {
            Some(encode(meta).await?)
        } else {
            None
        };
        let salt = vault.salt().cloned();
        let seed = vault.seed().map(|s| s.to_vec());
        Self::new_insert_parts(vault.summary(), salt, meta, seed)
    }

    /// Create a new folder row to be inserted from parts.
    pub fn new_insert_parts(
        summary: &Summary,
        salt: Option<String>,
        meta: Option<Vec<u8>>,
        seed: Option<Vec<u8>>,
    ) -> Result<Self> {
        Ok(Self {
            created_at: UtcDateTime::default().to_rfc3339()?,
            modified_at: UtcDateTime::default().to_rfc3339()?,
            identifier: summary.id().to_string(),
            name: summary.name().to_string(),
            salt,
            meta,
            seed,
            version: *summary.version() as i64,
            cipher: summary.cipher().to_string(),
            kdf: summary.kdf().to_string(),
            flags: summary.flags().bits().to_le_bytes().to_vec(),
            ..Default::default()
        })
    }

    /// Create a new folder row to update.
    pub async fn new_update(vault: &Vault) -> Result<Self> {
        let summary = vault.summary();
        let meta = if let Some(meta) = vault.header().meta() {
            Some(encode(meta).await?)
        } else {
            None
        };
        let salt = vault.salt().cloned();
        let seed = vault.seed().map(|s| s.to_vec());
        Ok(Self {
            modified_at: UtcDateTime::default().to_rfc3339()?,
            identifier: summary.id().to_string(),
            name: summary.name().to_string(),
            salt,
            meta,
            seed,
            version: *summary.version() as i64,
            cipher: summary.cipher().to_string(),
            kdf: summary.kdf().to_string(),
            flags: summary.flags().bits().to_le_bytes().to_vec(),
            ..Default::default()
        })
    }
}

impl<'a> TryFrom<&Row<'a>> for FolderRow {
    type Error = SqlError;
    fn try_from(row: &Row<'a>) -> StdResult<Self, Self::Error> {
        Ok(FolderRow {
            row_id: row.get(0)?,
            created_at: row.get(1)?,
            modified_at: row.get(2)?,
            identifier: row.get(3)?,
            name: row.get(4)?,
            salt: row.get(5)?,
            meta: row.get(6)?,
            seed: row.get(7)?,
            version: row.get(8)?,
            cipher: row.get(9)?,
            kdf: row.get(10)?,
            flags: row.get(11)?,
        })
    }
}

/// Folder record from the database.
#[derive(Debug, Clone)]
pub struct FolderRecord {
    /// Row identifier.
    pub row_id: i64,
    /// Created date and time.
    pub created_at: UtcDateTime,
    /// Modified date and time.
    pub modified_at: UtcDateTime,
    /// Key derivation salt.
    pub salt: Option<String>,
    /// Folder meta data.
    pub meta: Option<AeadPack>,
    /// Optional seed entropy.
    pub seed: Option<Seed>,
    /// Folder summary.
    pub summary: Summary,
}

impl FolderRecord {
    /// Convert from a folder row.
    pub async fn from_row(value: FolderRow) -> Result<Self> {
        let created_at = UtcDateTime::parse_rfc3339(&value.created_at)?;
        let modified_at = UtcDateTime::parse_rfc3339(&value.modified_at)?;
        let folder_id: VaultId = value.identifier.parse()?;
        let version: u16 = value.version.try_into()?;
        let cipher = value.cipher.parse()?;
        let kdf = value.kdf.parse()?;
        let bytes: [u8; 8] = value.flags.as_slice().try_into()?;
        let bits = u64::from_le_bytes(bytes);
        let flags = VaultFlags::from_bits(bits)
            .ok_or(sos_vault::Error::InvalidVaultFlags)?;

        let salt = if let Some(salt) = value.salt {
            Some(salt)
        } else {
            None
        };

        let meta = if let Some(meta) = &value.meta {
            Some(decode(meta).await?)
        } else {
            None
        };

        let seed = if let Some(seed) = value.seed {
            let seed: [u8; 32] = seed.as_slice().try_into()?;
            Some(seed)
        } else {
            None
        };

        let summary =
            Summary::new(version, folder_id, value.name, cipher, kdf, flags);

        Ok(FolderRecord {
            row_id: value.row_id,
            created_at,
            modified_at,
            salt,
            meta,
            seed,
            summary,
        })
    }

    /// Convert a folder record into a vault.
    pub fn into_vault(&self) -> Result<Vault> {
        let mut vault: Vault = self.summary.clone().into();
        vault.header_mut().set_meta(self.meta.clone());
        vault.header_mut().set_salt(self.salt.clone());
        vault.header_mut().set_seed(self.seed.clone());
        Ok(vault)
    }
}

/// Secret row from the database.
#[doc(hidden)]
#[derive(Debug, Default)]
pub struct SecretRow {
    pub row_id: i64,
    created_at: String,
    modified_at: String,
    identifier: String,
    commit: Vec<u8>,
    meta: Vec<u8>,
    secret: Vec<u8>,
}

impl SecretRow {
    /// Create a new secret row for insertion.
    pub async fn new(
        secret_id: &SecretId,
        commit: &CommitHash,
        entry: &VaultEntry,
    ) -> Result<Self> {
        let VaultEntry(meta, secret) = entry;
        let meta = encode(meta).await?;
        let secret = encode(secret).await?;
        Ok(Self {
            created_at: UtcDateTime::default().to_rfc3339()?,
            modified_at: UtcDateTime::default().to_rfc3339()?,
            identifier: secret_id.to_string(),
            commit: commit.as_ref().to_vec(),
            meta,
            secret,
            ..Default::default()
        })
    }

    /// Secret identifier.
    pub fn identifier(&self) -> &str {
        &self.identifier
    }

    /// Commit hash.
    pub fn commit(&self) -> &[u8] {
        &self.commit
    }

    /// Meta data bytes.
    pub fn meta_bytes(&self) -> &[u8] {
        &self.meta
    }

    /// Secret data bytes.
    pub fn secret_bytes(&self) -> &[u8] {
        &self.secret
    }
}

impl<'a> TryFrom<&Row<'a>> for SecretRow {
    type Error = SqlError;
    fn try_from(row: &Row<'a>) -> StdResult<Self, Self::Error> {
        Ok(SecretRow {
            row_id: row.get(0)?,
            created_at: row.get(1)?,
            modified_at: row.get(2)?,
            identifier: row.get(3)?,
            commit: row.get(4)?,
            meta: row.get(5)?,
            secret: row.get(6)?,
        })
    }
}

/// Secret record from the database.
#[doc(hidden)]
#[derive(Debug)]
pub struct SecretRecord {
    pub row_id: i64,
    pub created_at: UtcDateTime,
    pub modified_at: UtcDateTime,
    pub secret_id: VaultId,
    pub commit: VaultCommit,
}

impl SecretRecord {
    /// Convert from a secret row.
    pub async fn from_row(value: SecretRow) -> Result<Self> {
        let created_at = UtcDateTime::parse_rfc3339(&value.created_at)?;
        let modified_at = UtcDateTime::parse_rfc3339(&value.modified_at)?;
        let secret_id: SecretId = value.identifier.parse()?;
        let commit_hash = CommitHash(value.commit.as_slice().try_into()?);
        let meta: AeadPack = decode(&value.meta).await?;
        let secret: AeadPack = decode(&value.secret).await?;
        let commit = VaultCommit(commit_hash, VaultEntry(meta, secret));

        Ok(SecretRecord {
            row_id: value.row_id,
            created_at,
            modified_at,
            secret_id,
            commit,
        })
    }
}

/// Folder entity.
pub struct FolderEntity<'conn, C>
where
    C: Deref<Target = Connection>,
{
    conn: &'conn C,
}

impl<'conn> FolderEntity<'conn, Box<Connection>> {
    /// Query to find all secrets in a folder.
    pub fn find_all_secrets_query() -> sql::Select {
        secret_select_columns(sql::Select::new())
            .from("folder_secrets")
            .where_clause("folder_id=?1")
    }

    /// Compute the vault for a folder in the database.
    pub async fn compute_folder_vault(
        client: &Client,
        folder_id: &VaultId,
    ) -> Result<Vault> {
        let folder_id = *folder_id;

        let (folder_row, secret_rows) = client
            .conn_and_then(move |conn| {
                let folder_entity = FolderEntity::new(&conn);
                let folder_row = folder_entity.find_one(&folder_id)?;
                let secret_rows =
                    folder_entity.load_secrets(folder_row.row_id)?;
                Ok::<_, Error>((folder_row, secret_rows))
            })
            .await?;

        let folder_record = FolderRecord::from_row(folder_row).await?;
        let mut vault = folder_record.into_vault()?;
        for row in secret_rows {
            let record = SecretRecord::from_row(row).await?;
            vault.insert_entry(record.secret_id, record.commit);
        }
        Ok(vault)
    }
}

impl<'conn> FolderEntity<'conn, Transaction<'conn>> {
    /// Create a folder and the secrets in a vault.
    ///
    /// If a folder with the same identifier already exists
    /// it is updated and any existing secrets are deleted
    /// before inserting the new collection of secrets in the vault.
    pub async fn upsert_folder_and_secrets(
        client: &Client,
        account_id: i64,
        vault: &Vault,
    ) -> Result<(i64, HashMap<SecretId, i64>)> {
        let folder_id = *vault.id();

        let meta = if let Some(meta) = vault.header().meta() {
            Some(encode(meta).await?)
        } else {
            None
        };
        let salt = vault.salt().cloned();
        let seed = vault.seed().map(|s| s.to_vec());

        let folder_row =
            FolderRow::new_insert_parts(vault.summary(), salt, meta, seed)?;

        let mut secret_rows = Vec::new();
        for (secret_id, commit) in vault.iter() {
            let VaultCommit(commit, entry) = commit;
            secret_rows.push(SecretRow::new(secret_id, commit, entry).await?);
        }

        Ok(client
            .conn_mut_and_then(move |conn| {
                let tx = conn.transaction()?;
                let folder_entity = FolderEntity::new(&tx);

                let folder_id = if let Some(row) =
                    folder_entity.find_optional(&folder_id)?
                {
                    folder_entity.update_folder(&folder_id, &folder_row)?;
                    folder_entity.delete_all_secrets(row.row_id)?;
                    row.row_id
                } else {
                    folder_entity.insert_folder(account_id, &folder_row)?
                };

                let secret_ids = folder_entity.insert_folder_secrets(
                    folder_id,
                    secret_rows.as_slice(),
                )?;
                tx.commit()?;
                Ok::<_, Error>((folder_id, secret_ids))
            })
            .await?)
    }

    /// Replace all secrets for a folder using a transaction.
    pub async fn replace_all_secrets(
        client: Client,
        folder_id: &VaultId,
        vault: &Vault,
    ) -> Result<()> {
        let folder_id = folder_id.clone();
        let mut insert_secrets = Vec::new();
        for (secret_id, commit) in vault.iter() {
            let VaultCommit(commit, entry) = commit;
            insert_secrets
                .push(SecretRow::new(secret_id, commit, entry).await?);
        }

        let folder_update_row = FolderRow::new_update(vault).await?;
        client
            .conn_mut(move |conn| {
                let tx = conn.transaction()?;
                let folder = FolderEntity::new(&tx);
                let folder_row = folder.find_one(&folder_id)?;
                folder.delete_all_secrets(folder_row.row_id)?;
                for secret_row in insert_secrets {
                    folder.insert_secret_by_row_id(
                        folder_row.row_id,
                        &secret_row,
                    )?;
                }
                folder.update_folder(&folder_id, &folder_update_row)?;
                tx.commit()?;
                Ok(())
            })
            .await
            .map_err(Error::from)?;
        Ok(())
    }
}

impl<'conn, C> FolderEntity<'conn, C>
where
    C: Deref<Target = Connection>,
{
    /// Create a new folder entity.
    pub fn new(conn: &'conn C) -> Self {
        Self { conn }
    }

    fn select_folder(
        &self,
        use_identifier: bool,
    ) -> StdResult<CachedStatement, SqlError> {
        let query = folder_select_columns(sql::Select::new()).from("folders");

        let query = if use_identifier {
            query.where_clause("identifier = ?1")
        } else {
            query.where_clause("folder_id = ?1")
        };
        Ok(self.conn.prepare_cached(&query.as_string())?)
    }

    /// Find a folder in the database.
    pub fn find_one(
        &self,
        // FIXME: require account_id?
        folder_id: &VaultId,
    ) -> StdResult<FolderRow, SqlError> {
        let mut stmt = self.select_folder(true)?;
        Ok(stmt
            .query_row([folder_id.to_string()], |row| Ok(row.try_into()?))?)
    }

    /// Find an optional folder in the database.
    pub fn find_optional(
        &self,
        // FIXME: require account_id?
        folder_id: &VaultId,
    ) -> StdResult<Option<FolderRow>, SqlError> {
        let mut stmt = self.select_folder(true)?;
        Ok(stmt
            .query_row([folder_id.to_string()], |row| {
                let row: FolderRow = row.try_into()?;
                Ok(row)
            })
            .optional()?)
    }

    /// Find a folder in the database by primary key.
    pub fn find_by_row_id(
        &self,
        folder_id: i64,
    ) -> StdResult<FolderRow, SqlError> {
        let mut stmt = self.select_folder(false)?;
        Ok(stmt.query_row([folder_id], |row| Ok(row.try_into()?))?)
    }

    /// Try to find a login folder for an account.
    pub fn find_login_folder(&self, account_id: i64) -> Result<FolderRow> {
        Ok(self
            .find_login_folder_optional(account_id)?
            .ok_or_else(|| Error::NoLoginFolder(account_id))?)
    }

    /// Try to find an optional login folder for an account.
    pub fn find_login_folder_optional(
        &self,
        account_id: i64,
    ) -> StdResult<Option<FolderRow>, SqlError> {
        let query = folder_select_columns(sql::Select::new())
            .from("folders")
            .left_join(
                "account_login_folder login ON folders.folder_id = login.folder_id",
            )
            .where_clause("folders.account_id=?1")
            .where_and("login.account_id=?1");

        let mut stmt = self.conn.prepare_cached(&query.as_string())?;
        Ok(stmt
            .query_row([account_id], |row| Ok(row.try_into()?))
            .optional()?)
    }

    /// Try to find a device folder for an account.
    pub fn find_device_folder(
        &self,
        account_id: i64,
    ) -> StdResult<Option<FolderRow>, SqlError> {
        let query = folder_select_columns(sql::Select::new())
            .from("folders")
            .left_join(
                "account_device_folder device ON folders.folder_id = device.folder_id",
            )
            .where_clause("folders.account_id=?1")
            .where_and("device.account_id=?1");

        let mut stmt = self.conn.prepare_cached(&query.as_string())?;
        Ok(stmt
            .query_row([account_id], |row| Ok(row.try_into()?))
            .optional()?)
    }

    /// List user folders for an account.
    ///
    /// Does not include the identity and device folders.
    pub fn list_user_folders(
        &self,
        account_id: i64,
    ) -> Result<Vec<FolderRow>> {
        let query = folder_select_columns(sql::Select::new())
            .from("folders")
            .left_join(
                "account_login_folder login ON folders.folder_id = login.folder_id",
            )
            .left_join(
                "account_device_folder device ON folders.folder_id = device.folder_id",
            )
            .where_clause("folders.account_id=?1")
            .where_and("login.folder_id IS NULL")
            .where_and("device.folder_id IS NULL");

        let mut stmt = self.conn.prepare_cached(&query.as_string())?;

        fn convert_row(row: &Row<'_>) -> Result<FolderRow> {
            Ok(row.try_into()?)
        }

        let rows = stmt.query_and_then([account_id], |row| {
            Ok::<_, crate::Error>(convert_row(row)?)
        })?;
        let mut folders = Vec::new();
        for row in rows {
            folders.push(row?);
        }
        Ok(folders)
    }

    /// Update the name of a folder.
    pub fn update_name(&self, folder_id: &VaultId, name: &str) -> Result<()> {
        let modified_at = UtcDateTime::default().to_rfc3339()?;
        let query = sql::Update::new()
            .update("folders")
            .set("name = ?1, modified_at = ?2")
            .where_clause("identifier = ?3");
        let mut stmt = self.conn.prepare_cached(&query.as_string())?;
        stmt.execute((name, modified_at, folder_id.to_string()))?;
        Ok(())
    }

    /// Update the folder flags.
    pub fn update_flags(
        &self,
        folder_id: &VaultId,
        flags: &VaultFlags,
    ) -> Result<()> {
        let flags = flags.bits().to_le_bytes();
        let modified_at = UtcDateTime::default().to_rfc3339()?;
        let query = sql::Update::new()
            .update("folders")
            .set("flags = ?1, modified_at = ?2")
            .where_clause("identifier = ?3");
        let mut stmt = self.conn.prepare_cached(&query.as_string())?;
        stmt.execute((flags, modified_at, folder_id.to_string()))?;
        Ok(())
    }

    /// Update the folder meta data.
    pub fn update_meta(
        &self,
        folder_id: &VaultId,
        meta: &[u8],
    ) -> Result<()> {
        let modified_at = UtcDateTime::default().to_rfc3339()?;
        let query = sql::Update::new()
            .update("folders")
            .set("meta = ?1, modified_at = ?2")
            .where_clause("identifier = ?3");
        let mut stmt = self.conn.prepare_cached(&query.as_string())?;
        stmt.execute((meta, modified_at, folder_id.to_string()))?;
        Ok(())
    }

    /// Create the folder entity in the database.
    pub fn insert_folder(
        &self,
        account_id: i64,
        folder_row: &FolderRow,
    ) -> StdResult<i64, SqlError> {
        let query = sql::Insert::new()
            .insert_into(
                r#"
                folders
                (
                    account_id,
                    created_at,
                    modified_at,
                    identifier,
                    name,
                    salt,
                    meta,
                    seed,
                    version,
                    cipher,
                    kdf,
                    flags
                )
            "#,
            )
            .values("(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)");

        let mut stmt = self.conn.prepare_cached(&query.as_string())?;
        stmt.execute((
            &account_id,
            &folder_row.created_at,
            &folder_row.modified_at,
            &folder_row.identifier,
            &folder_row.name,
            &folder_row.salt,
            &folder_row.meta,
            &folder_row.seed,
            &folder_row.version,
            &folder_row.cipher,
            &folder_row.kdf,
            &folder_row.flags,
        ))?;

        Ok(self.conn.last_insert_rowid())
    }

    /// Update the folder entity in the database.
    pub fn update_folder(
        &self,
        folder_id: &VaultId,
        folder_row: &FolderRow,
    ) -> StdResult<(), SqlError> {
        let query = sql::Update::new()
            .update("folders")
            .set(
                r#"
                    modified_at = ?1,
                    identifier = ?2,
                    name = ?3,
                    salt = ?4,
                    meta = ?5,
                    seed = ?6,
                    version = ?7,
                    cipher = ?8,
                    kdf = ?9,
                    flags = ?10
                 "#,
            )
            .where_clause("identifier=?11");
        let mut stmt = self.conn.prepare_cached(&query.as_string())?;
        stmt.execute((
            &folder_row.modified_at,
            &folder_row.identifier,
            &folder_row.name,
            &folder_row.salt,
            &folder_row.meta,
            &folder_row.seed,
            &folder_row.version,
            &folder_row.cipher,
            &folder_row.kdf,
            &folder_row.flags,
            folder_id.to_string(),
        ))?;

        Ok(())
    }

    /// Create folder secret rows.
    pub fn insert_folder_secrets(
        &self,
        folder_id: i64,
        rows: &[SecretRow],
    ) -> Result<HashMap<SecretId, i64>> {
        let mut secret_ids = HashMap::new();
        for secret_row in rows {
            let identifier: SecretId = secret_row.identifier.parse()?;
            let secret_id =
                self.insert_secret_by_row_id(folder_id, &secret_row)?;
            secret_ids.insert(identifier, secret_id);
        }
        Ok(secret_ids)
    }

    /// Create folder secret.
    pub fn insert_secret(
        &self,
        folder_id: &VaultId,
        secret_row: &SecretRow,
    ) -> StdResult<i64, SqlError> {
        let row = self.find_one(folder_id)?;
        Ok(self.insert_secret_by_row_id(row.row_id, secret_row)?)
    }

    /// Insert a secret using the folder row id.
    pub fn insert_secret_by_row_id(
        &self,
        folder_id: i64,
        secret_row: &SecretRow,
    ) -> StdResult<i64, SqlError> {
        // NOTE: we have to use an upsert here as auto merge
        // NOTE: can try to create secrets that already exist
        // NOTE: so we handle the conflict situation
        let query = sql::Insert::new()
            .insert_into("folder_secrets (folder_id, identifier, commit_hash, meta, secret, created_at, modified_at)")
            .values("(?1, ?2, ?3, ?4, ?5, ?6, ?7)")
            .on_conflict(
            r#"
                (identifier)
                DO UPDATE SET
                    folder_id=excluded.folder_id,
                    commit_hash=excluded.commit_hash,
                    meta=excluded.meta,
                    secret=excluded.secret,
                    modified_at=excluded.modified_at
            "#);
        let mut stmt = self.conn.prepare_cached(&query.as_string())?;
        stmt.execute((
            &folder_id,
            &secret_row.identifier,
            &secret_row.commit,
            &secret_row.meta,
            &secret_row.secret,
            &secret_row.created_at,
            &secret_row.modified_at,
        ))?;
        Ok(self.conn.last_insert_rowid())
    }

    /// Find a folder secret.
    pub fn find_secret(
        &self,
        folder_id: &VaultId,
        secret_id: &SecretId,
    ) -> StdResult<Option<SecretRow>, SqlError> {
        let row = self.find_one(folder_id)?;
        let query = secret_select_columns(sql::Select::new())
            .from("folder_secrets")
            .where_clause("folder_id=?1")
            .where_and("identifier=?2");

        let mut stmt = self.conn.prepare_cached(&query.as_string())?;
        Ok(stmt
            .query_row((row.row_id, secret_id.to_string()), |row| {
                let row: SecretRow = row.try_into()?;
                Ok(row)
            })
            .optional()?)
    }

    /// Update a folder secret.
    pub fn update_secret(
        &self,
        folder_id: &VaultId,
        secret_row: &SecretRow,
    ) -> Result<bool> {
        let modified_at = UtcDateTime::default().to_rfc3339()?;
        let row = self.find_one(folder_id)?;
        let query = sql::Update::new()
            .update("folder_secrets")
            .set(
                r#"

                    modified_at=?1,
                    commit_hash=?2,
                    meta=?3, 
                    secret=?4
                 "#,
            )
            .where_clause("folder_id=?5")
            .where_and("identifier = ?6");

        let mut stmt = self.conn.prepare_cached(&query.as_string())?;
        let affected_rows = stmt.execute((
            modified_at,
            &secret_row.commit,
            &secret_row.meta,
            &secret_row.secret,
            row.row_id,
            &secret_row.identifier,
        ))?;
        Ok(affected_rows > 0)
    }

    /// Load secret rows.
    pub fn load_secrets(&self, folder_row_id: i64) -> Result<Vec<SecretRow>> {
        let query = secret_select_columns(sql::Select::new())
            .from("folder_secrets")
            .where_clause("folder_id=?1");
        let mut stmt = self.conn.prepare_cached(&query.as_string())?;

        fn convert_row(row: &Row<'_>) -> Result<SecretRow> {
            Ok(row.try_into()?)
        }

        let rows = stmt.query_and_then([folder_row_id], |row| {
            Ok::<_, crate::Error>(convert_row(row)?)
        })?;
        let mut secrets = Vec::new();
        for row in rows {
            secrets.push(row?);
        }
        Ok(secrets)
    }

    /// List secret ids.
    pub fn list_secret_ids(
        &self,
        folder_id: &VaultId,
    ) -> Result<Vec<SecretId>> {
        let folder = self.find_one(folder_id)?;
        let query = sql::Select::new()
            .select("identifier")
            .from("folder_secrets")
            .where_clause("folder_id=?1");
        let mut stmt = self.conn.prepare_cached(&query.as_string())?;

        fn convert_row(row: &Row<'_>) -> Result<SecretId> {
            let id: String = row.get(0)?;
            Ok(id.parse()?)
        }

        let rows = stmt.query_and_then([folder.row_id], |row| {
            Ok::<_, crate::Error>(convert_row(row)?)
        })?;
        let mut secrets = Vec::new();
        for row in rows {
            secrets.push(row?);
        }
        Ok(secrets)
    }

    /// Delete a folder.
    pub fn delete_folder(
        &self,
        folder_id: &VaultId,
    ) -> StdResult<bool, SqlError> {
        let row = self.find_one(folder_id)?;
        let query = sql::Delete::new()
            .delete_from("folders")
            .where_clause("folder_id = ?1");
        let mut stmt = self.conn.prepare_cached(&query.as_string())?;
        let affected_rows = stmt.execute([row.row_id])?;
        Ok(affected_rows > 0)
    }

    /// Delete folder secret.
    pub fn delete_secret(
        &self,
        folder_id: &VaultId,
        secret_id: &SecretId,
    ) -> StdResult<bool, SqlError> {
        let row = self.find_one(folder_id)?;
        let query = sql::Delete::new()
            .delete_from("folder_secrets")
            .where_clause("folder_id = ?1")
            .where_and("identifier = ?2");
        let mut stmt = self.conn.prepare_cached(&query.as_string())?;
        let affected_rows =
            stmt.execute((row.row_id, secret_id.to_string()))?;
        Ok(affected_rows > 0)
    }

    /// Delete all folder secrets.
    fn delete_all_secrets(
        &self,
        folder_id: i64,
    ) -> StdResult<usize, SqlError> {
        let query = sql::Delete::new()
            .delete_from("folder_secrets")
            .where_clause("folder_id = ?1");
        let mut stmt = self.conn.prepare_cached(&query.as_string())?;
        Ok(stmt.execute([folder_id])?)
    }
}
