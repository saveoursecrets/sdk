use crate::Result;
use async_sqlite::rusqlite::{
    CachedStatement, Connection, Error as SqlError, OptionalExtension, Row,
};
use sos_core::{
    commit::CommitHash, crypto::AeadPack, decode, encode, SecretId,
    UtcDateTime, VaultCommit, VaultEntry, VaultFlags, VaultId,
};
use sos_vault::{Summary, Vault};
use std::collections::HashMap;
use std::ops::Deref;
use std::result::Result as StdResult;

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
        Self::new_insert_parts(vault.summary(), salt, meta)
    }

    /// Create a new folder row to be inserted from parts.
    pub fn new_insert_parts(
        summary: &Summary,
        salt: Option<String>,
        meta: Option<Vec<u8>>,
    ) -> Result<Self> {
        Ok(Self {
            created_at: UtcDateTime::default().to_rfc3339()?,
            modified_at: UtcDateTime::default().to_rfc3339()?,
            identifier: summary.id().to_string(),
            name: summary.name().to_string(),
            salt,
            meta,
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
            version: row.get(7)?,
            cipher: row.get(8)?,
            kdf: row.get(9)?,
            flags: row.get(10)?,
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

        let summary =
            Summary::new(version, folder_id, value.name, cipher, kdf, flags);

        Ok(FolderRecord {
            row_id: value.row_id,
            created_at,
            modified_at,
            salt,
            meta,
            summary,
        })
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

impl<'conn, C> FolderEntity<'conn, C>
where
    C: Deref<Target = Connection>,
{
    /// Create a new folder entity.
    pub fn new(conn: &'conn C) -> Self {
        Self { conn }
    }

    fn find_folder_statement(
        &self,
        where_column: &str,
    ) -> StdResult<CachedStatement, SqlError> {
        Ok(self.conn.prepare_cached(&format!(
            r#"
                SELECT
                    folder_id,
                    created_at,
                    modified_at,
                    identifier,
                    name,
                    salt,
                    meta,
                    version,
                    cipher,
                    kdf,
                    flags
                FROM folders
                WHERE {}=?1
            "#,
            where_column
        ))?)
    }

    /// Find a folder in the database.
    pub fn find_one(
        &self,
        // FIXME: require account_id?
        folder_id: &VaultId,
    ) -> StdResult<FolderRow, SqlError> {
        let mut stmt = self.find_folder_statement("identifier")?;
        Ok(stmt
            .query_row([folder_id.to_string()], |row| Ok(row.try_into()?))?)
    }

    /// Find an optional folder in the database.
    pub fn find_optional(
        &self,
        // FIXME: require account_id?
        folder_id: &VaultId,
    ) -> StdResult<Option<FolderRow>, SqlError> {
        let mut stmt = self.find_folder_statement("identifier")?;
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
        let mut stmt = self.find_folder_statement("folder_id")?;
        Ok(stmt.query_row([folder_id], |row| Ok(row.try_into()?))?)
    }

    /// Try to find a login folder for an account.
    pub fn find_login_folder(
        &self,
        account_id: i64,
    ) -> StdResult<FolderRow, SqlError> {
        let mut stmt = self.conn.prepare_cached(
            r#"
                SELECT
                    folders.folder_id,
                    folders.created_at,
                    folders.modified_at,
                    folders.identifier,
                    folders.name,
                    folders.salt,
                    folders.meta,
                    folders.version,
                    folders.cipher,
                    folders.kdf,
                    folders.flags
                FROM folders
                LEFT JOIN account_login_folder
                    ON folders.folder_id = account_login_folder.folder_id
                WHERE folders.account_id=?1
                    AND account_login_folder.account_id=?1
            "#,
        )?;
        Ok(stmt.query_row([account_id], |row| Ok(row.try_into()?))?)
    }

    /// List user folders for an account.
    ///
    /// Does not include the identity and device folders.
    pub fn list_user_folders(
        &self,
        account_id: i64,
    ) -> Result<Vec<FolderRow>> {
        let mut stmt = self.conn.prepare_cached(
            r#"
                SELECT
                    folders.folder_id,
                    folders.created_at,
                    folders.modified_at,
                    folders.identifier,
                    folders.name,
                    folders.salt,
                    folders.meta,
                    folders.version,
                    folders.cipher,
                    folders.kdf,
                    folders.flags
                FROM folders
                LEFT JOIN account_login_folder
                    ON folders.folder_id = account_login_folder.folder_id
                LEFT JOIN account_device_folder
                    ON folders.folder_id = account_device_folder.folder_id
                WHERE folders.account_id=?1
                    AND account_login_folder.folder_id IS NULL
                    AND account_device_folder.folder_id IS NULL
            "#,
        )?;

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
    pub fn update_name(
        &self,
        folder_id: &VaultId,
        name: &str,
    ) -> StdResult<(), SqlError> {
        let mut stmt = self.conn.prepare_cached(
            r#"
              UPDATE
                folders
                SET name=?1
                WHERE identifier=?2
            "#,
        )?;
        stmt.execute((name, folder_id.to_string()))?;
        Ok(())
    }

    /// Update the folder flags.
    pub fn update_flags(
        &self,
        folder_id: &VaultId,
        flags: &[u8],
    ) -> StdResult<(), SqlError> {
        let mut stmt = self.conn.prepare_cached(
            r#"
              UPDATE
                folders
                SET flags=?1
                WHERE identifier=?2
            "#,
        )?;
        stmt.execute((flags, folder_id.to_string()))?;
        Ok(())
    }

    /// Update the folder meta data.
    pub fn update_meta(
        &self,
        folder_id: &VaultId,
        meta: &[u8],
    ) -> StdResult<(), SqlError> {
        let mut stmt = self.conn.prepare_cached(
            r#"
              UPDATE
                folders
                SET meta=?1
                WHERE identifier=?2
            "#,
        )?;
        stmt.execute((meta, folder_id.to_string()))?;
        Ok(())
    }

    /// Create the folder entity in the database.
    pub fn insert_folder(
        &self,
        account_id: i64,
        folder_row: &FolderRow,
    ) -> StdResult<i64, SqlError> {
        let mut stmt = self.conn.prepare_cached(
            r#"
              INSERT INTO folders
                (
                    account_id,
                    created_at,
                    modified_at,
                    identifier,
                    name,
                    salt,
                    meta,
                    version,
                    cipher,
                    kdf,
                    flags
                )
                VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
            "#,
        )?;
        stmt.execute((
            &account_id,
            &folder_row.created_at,
            &folder_row.modified_at,
            &folder_row.identifier,
            &folder_row.name,
            &folder_row.salt,
            &folder_row.meta,
            &folder_row.version,
            &folder_row.cipher,
            &folder_row.kdf,
            &folder_row.flags,
        ))?;

        Ok(self.conn.last_insert_rowid())
    }

    /// Create folder secret rows.
    pub fn insert_folder_secrets(
        &self,
        folder_id: i64,
        rows: Vec<(SecretId, SecretRow)>,
    ) -> StdResult<HashMap<SecretId, i64>, SqlError> {
        let mut secret_ids = HashMap::new();
        for (identifier, secret_row) in rows {
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
        let mut stmt = self.conn.prepare_cached(
            r#"
            INSERT INTO folder_secrets
              (folder_id, identifier, commit_hash, meta, secret, created_at, modified_at)
              VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
          "#,
        )?;
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

    fn find_secret_statement(&self) -> StdResult<CachedStatement, SqlError> {
        Ok(self.conn.prepare_cached(
            r#"
                SELECT
                    secret_id,
                    created_at,
                    modified_at,
                    identifier,
                    commit_hash,
                    meta,
                    secret 
                FROM folder_secrets
                WHERE folder_id=?1 AND identifier=?2
            "#,
        )?)
    }

    /// Find a folder secret.
    pub fn find_secret(
        &self,
        folder_id: &VaultId,
        secret_id: &SecretId,
    ) -> StdResult<Option<SecretRow>, SqlError> {
        let row = self.find_one(folder_id)?;
        let mut stmt = self.find_secret_statement()?;
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
    ) -> StdResult<bool, SqlError> {
        let row = self.find_one(folder_id)?;
        let mut stmt = self.conn.prepare_cached(
            r#"
            UPDATE folder_secrets
                SET
                    commit_hash=?1,
                    meta=?2, 
                    secret=?3
                WHERE folder_id=?4 AND identifier=?5
          "#,
        )?;
        let affected_rows = stmt.execute((
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
        let mut stmt = self.conn.prepare_cached(
            r#"
                SELECT
                    secret_id,
                    created_at,
                    modified_at,
                    identifier,
                    commit_hash,
                    meta,
                    secret
                FROM folder_secrets
                WHERE folder_id=?1
            "#,
        )?;

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

    /// Delete a folder.
    pub fn delete_folder(
        &self,
        folder_id: &VaultId,
    ) -> StdResult<bool, SqlError> {
        let row = self.find_one(folder_id)?;
        let mut stmt = self.conn.prepare_cached(
            r#"
                DELETE
                    FROM folders
                    WHERE folder_id=?1
            "#,
        )?;
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
        let mut stmt = self.conn.prepare_cached(
            r#"
                DELETE
                    FROM folder_secrets
                    WHERE folder_id=?1 AND identifier=?2
            "#,
        )?;
        let affected_rows =
            stmt.execute((row.row_id, secret_id.to_string()))?;
        Ok(affected_rows > 0)
    }

    /// Delete all folder secrets.
    pub fn delete_all_secrets(
        &self,
        folder_id: &VaultId,
    ) -> StdResult<usize, SqlError> {
        let row = self.find_one(folder_id)?;
        let mut stmt = self.conn.prepare_cached(
            r#"
                DELETE
                    FROM folder_secrets
                    WHERE folder_id=?1
            "#,
        )?;
        Ok(stmt.execute([row.row_id])?)
    }
}
