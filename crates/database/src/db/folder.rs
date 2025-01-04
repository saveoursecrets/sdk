use async_sqlite::rusqlite::{Connection, Error as SqlError};
use sos_core::{commit::CommitHash, SecretId};
use sos_sdk::vault::Summary;
use std::collections::HashMap;
use std::ops::Deref;

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

    /// Create the folder entity in the database.
    pub fn insert_folder(
        &self,
        account_id: i64,
        summary: &Summary,
    ) -> Result<i64, SqlError> {
        let identifier = summary.id().to_string();
        let name = summary.name().to_string();
        let version = summary.version();
        let cipher = summary.cipher().to_string();
        let kdf = summary.kdf().to_string();
        let flags = summary.flags().bits().to_le_bytes();

        let mut stmt = self.conn.prepare_cached(
            r#"
              INSERT INTO folders
                (account_id, identifier, name, version, cipher, kdf, flags)
                VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
            "#,
        )?;
        stmt.execute((
            &account_id,
            &identifier,
            &name,
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
    ) -> Result<HashMap<SecretId, i64>, SqlError> {
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
