use crate::{Error, Result};
use async_sqlite::rusqlite::{
    Connection, Error as SqlError, OptionalExtension,
};
use sos_core::VaultFlags;
use sos_core::{commit::CommitHash, SecretId, VaultId};
use sos_sdk::UtcDateTime;
use sos_vault::Summary;
use std::collections::HashMap;
use std::ops::Deref;
use std::result::Result as StdResult;

/// Folder row from the database.
pub(crate) struct FolderRow {
    pub row_id: i64,
    pub created_at: String,
    pub modified_at: String,
    pub identifier: String,
    pub name: String,
    pub version: i64,
    pub cipher: String,
    pub kdf: String,
    pub flags: Vec<u8>,
}

impl TryFrom<FolderRow> for FolderRecord {
    type Error = Error;

    fn try_from(value: FolderRow) -> Result<Self> {
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
        let summary =
            Summary::new(version, folder_id, value.name, cipher, kdf, flags);

        Ok(FolderRecord {
            row_id: value.row_id,
            created_at,
            modified_at,
            summary,
        })
    }
}

/// Folder record from the database.
pub struct FolderRecord {
    /// Row identifier.
    pub row_id: i64,
    /// Created date and time.
    pub created_at: UtcDateTime,
    /// Modified date and time.
    pub modified_at: UtcDateTime,
    /// Folder summary.
    pub summary: Summary,
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

    /// Find a folder in the database.
    pub(crate) fn find_one(
        &self,
        folder_id: &VaultId,
    ) -> StdResult<Option<FolderRow>, SqlError> {
        let mut stmt = self.conn.prepare_cached(
            r#"
              SELECT
                folder_id,
                created_id,
                modified_at,
                identifier,
                name,
                version,
                cipher,
                kdf,
                flags
                FROM folders WHERE folder_id=?1
            "#,
        )?;

        let result = stmt
            .query_row([folder_id.to_string()], |row| {
                Ok(FolderRow {
                    row_id: row.get(0)?,
                    created_at: row.get(1)?,
                    modified_at: row.get(2)?,
                    identifier: row.get(3)?,
                    name: row.get(4)?,
                    version: row.get(5)?,
                    cipher: row.get(6)?,
                    kdf: row.get(7)?,
                    flags: row.get(8)?,
                })
            })
            .optional()?;

        Ok(result)

        /*
        if let Some(row) = result {
            Ok(Some(row.try_into()?))
        } else {
            Ok(None)
        }
        */
    }

    /// Create the folder entity in the database.
    pub fn insert_folder(
        &self,
        account_id: i64,
        summary: &Summary,
        meta: Option<Vec<u8>>,
    ) -> StdResult<i64, SqlError> {
        let identifier = summary.id().to_string();
        let name = summary.name().to_string();
        let version = summary.version();
        let cipher = summary.cipher().to_string();
        let kdf = summary.kdf().to_string();
        let flags = summary.flags().bits().to_le_bytes();

        let mut stmt = self.conn.prepare_cached(
            r#"
              INSERT INTO folders
                (account_id, identifier, name, meta, version, cipher, kdf, flags)
                VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
            "#,
        )?;
        stmt.execute((
            &account_id,
            &identifier,
            &name,
            &meta,
            &version,
            &cipher,
            &kdf,
            &flags,
        ))?;

        Ok(self.conn.last_insert_rowid())
    }

    /// Create folder secret rows.
    pub fn insert_folder_secrets(
        &self,
        folder_id: i64,
        rows: Vec<(SecretId, CommitHash, Vec<u8>, Vec<u8>)>,
    ) -> StdResult<HashMap<SecretId, i64>, SqlError> {
        let mut secret_ids = HashMap::new();
        let mut stmt = self.conn.prepare_cached(
            r#"
            INSERT INTO folder_secrets
              (folder_id, identifier, commit_hash, meta, secret)
              VALUES (?1, ?2, ?3, ?4, ?5)
          "#,
        )?;
        for (identifier, commit_hash, meta, secret) in rows {
            stmt.execute((
                &folder_id,
                &identifier.to_string(),
                commit_hash.as_ref(),
                &meta,
                &secret,
            ))?;
            secret_ids.insert(identifier, self.conn.last_insert_rowid());
        }
        Ok(secret_ids)
    }
}
