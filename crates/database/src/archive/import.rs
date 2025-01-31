use crate::db::{AccountEntity, AccountRecord};

use super::{types::ManifestVersion3, zip::Reader, Error, Result};
use async_sqlite::rusqlite::Connection;
use sos_core::{
    constants::{BLOBS_DIR, DATABASE_FILE},
    Paths,
};
use sos_vfs as vfs;
use std::{io::Write, path::Path};
use tempfile::NamedTempFile;
use tokio::io::BufReader;

/// Backup import.
pub struct BackupImport<'conn> {
    // Box the connection so it implements Deref<Target = Connection>
    // which database entities use so they can accept transactions
    source_db: Box<Connection>,
    target_db: &'conn mut Connection,
    paths: Paths,
    manifest: ManifestVersion3,
    // Ensure the temp file is not deleted
    // until this struct is dropped
    db_temp: NamedTempFile,
}

impl<'conn> BackupImport<'conn> {
    /// List accounts in the temporary source database.
    pub fn list_source_accounts(&self) -> Result<Vec<AccountRecord>> {
        let accounts = AccountEntity::new(&self.source_db);
        let rows = accounts.list_accounts()?;
        let mut records = Vec::new();
        for row in rows {
            records.push(row.try_into()?);
        }
        Ok(records)
    }

    /// List accounts in the target database.
    pub fn list_target_accounts(&self) -> Result<Vec<AccountRecord>> {
        let accounts = AccountEntity::new(&self.target_db);
        let rows = accounts.list_accounts()?;
        let mut records = Vec::new();
        for row in rows {
            records.push(row.try_into()?);
        }
        Ok(records)
    }

    /// Run migrations on the temporary source database.
    pub fn migrate(&mut self) -> Result<refinery::Report> {
        Ok(crate::migrations::migrate_connection(&mut self.source_db)?)
    }

    /// Try to import an account from the source to the target database.
    pub fn import_account(&self) -> Result<()> {
        todo!();
    }
}

/// Start importing a backup archive.
///
/// Reads the archive manifest and extracts the archive database file
/// to a temporary file and prepares the database connections.
///
/// The returned struct will hold the temporary file and connections
/// in memory until dropped and can be used to inspect the accounts in the
/// archive and perform imports.
pub(crate) async fn start<'conn>(
    target_db: &'conn mut Connection,
    paths: &Paths,
    input: impl AsRef<Path>,
    // progress: fn(backup::Progress),
) -> Result<BackupImport<'conn>> {
    if !vfs::try_exists(input.as_ref()).await? {
        return Err(Error::ArchiveFileNotExists(input.as_ref().to_owned()));
    }

    let zip_file = BufReader::new(vfs::File::open(input.as_ref()).await?);
    let mut zip_reader = Reader::new(zip_file).await?;
    let manifest = zip_reader.find_manifest().await?.ok_or_else(|| {
        Error::InvalidArchiveManifest(input.as_ref().to_owned())
    })?;

    // Extract the database and write to a temp file
    let db_buffer =
        zip_reader.by_name(DATABASE_FILE).await?.ok_or_else(|| {
            Error::NoDatabaseFile(
                input.as_ref().to_owned(),
                DATABASE_FILE.to_owned(),
            )
        })?;
    let mut db_temp = NamedTempFile::new()?;
    db_temp.as_file_mut().write_all(&db_buffer)?;

    let source_db = Connection::open(db_temp.path())?;

    let import = BackupImport {
        target_db,
        paths: paths.clone(),
        manifest,
        db_temp,
        source_db: Box::new(source_db),
    };

    Ok(import)
}
