use async_sqlite::rusqlite::{Connection, Error as SqlError};
use sos_core::{ExternalFile, SecretId, VaultId};
use std::collections::HashMap;
use std::ops::Deref;

/// File entity.
pub struct FileEntity<'conn, C>
where
    C: Deref<Target = Connection>,
{
    conn: &'conn C,
}

impl<'conn, C> FileEntity<'conn, C>
where
    C: Deref<Target = Connection>,
{
    /// Create a new file entity.
    pub fn new(conn: &'conn C) -> Self {
        Self { conn }
    }

    /// Create file blobs in the database.
    pub fn insert_files(
        &self,
        folder_ids: &HashMap<VaultId, (i64, HashMap<SecretId, i64>)>,
        user_files: Vec<(ExternalFile, Vec<u8>)>,
    ) -> std::result::Result<(), SqlError> {
        for (file, contents) in user_files {
            if let Some((folder_id, secret_ids)) =
                folder_ids.iter().find_map(|(k, v)| {
                    if k == file.vault_id() {
                        Some(v)
                    } else {
                        None
                    }
                })
            {
                if let Some(secret_id) = secret_ids.get(file.secret_id()) {
                    let mut stmt = self.conn.prepare_cached(
                        r#"
                        INSERT INTO folder_files
                          (folder_id, secret_id, checksum, contents)
                          VALUES (?1, ?2, ?3, ?4)
                      "#,
                    )?;
                    stmt.execute((
                        folder_id,
                        secret_id,
                        file.file_name().as_ref(),
                        contents,
                    ))?;
                } else {
                    tracing::warn!(
                        file = %file,
                        "db::import::no_secret_for_file",
                    );
                }
            } else {
                tracing::warn!(
                    file = %file,
                    "db::import::no_folder_for_file",
                );
            }
        }
        Ok(())
    }
}
