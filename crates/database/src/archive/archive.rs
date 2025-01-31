use super::{zip::Writer, Error, Result};
use crate::db::{AccountEntity, AccountRecord};
use async_sqlite::rusqlite::{backup, Connection};
use sos_core::{
    constants::{BLOBS_DIR, DATABASE_FILE},
    Paths,
};
use sos_external_files::list_external_blobs;
use sos_vfs as vfs;
use std::{
    path::{Path, PathBuf},
    time::{Duration, SystemTime},
};
use tempfile::NamedTempFile;

/// Create a backup archive.
///
/// Performs an online backup of the database to a temporary file and
/// then reads the backup database into a buffer and adds it to the zip
/// archive.
///
/// External file blobs are read and added to the archive.
pub(crate) async fn create(
    source_db: &Connection,
    paths: &Paths,
    output: impl AsRef<Path>,
    // progress: fn(backup::Progress),
) -> Result<()> {
    if vfs::try_exists(output.as_ref()).await? {
        return Err(Error::ArchiveFileExists(output.as_ref().to_owned()));
    }

    let zip_file = vfs::File::create(output.as_ref()).await?;
    let mut zip_writer = Writer::new(zip_file);

    // Find blobs that we need to add to the archive
    let blobs = find_blobs(source_db, paths).await?;

    let db_temp = NamedTempFile::new()?;
    create_database_backup(source_db, db_temp.path(), |_| {})?;

    let db_buffer = vfs::read(db_temp.path()).await?;
    zip_writer.add_file(DATABASE_FILE, &db_buffer).await?;

    // Add external file blobs to the archive
    for (account, files) in blobs {
        tracing::debug!(
            account_id = %account.identity.account_id(),
            num_blobs = %files.len(),
            "create_archive::add_account_blobs"
        );
        for (name, path) in files {
            let metadata = vfs::metadata(&path).await?;
            tracing::debug!(
              bytes_len = %metadata.len(),
              "create_archive::read_blob");

            let buffer = vfs::read(path).await?;
            let entry_name = format!("{}/{}", BLOBS_DIR, name);
            zip_writer.add_file(&entry_name, &buffer).await?;
        }
    }

    zip_writer.finish().await?;
    Ok(())
}

async fn find_blobs(
    source_db: &Connection,
    paths: &Paths,
) -> Result<Vec<(AccountRecord, Vec<(String, PathBuf)>)>> {
    let accounts = AccountEntity::new(&source_db);
    let accounts = accounts.list_accounts()?;

    let mut output = Vec::new();

    for account in accounts {
        let record: AccountRecord = account.try_into()?;
        let account_paths = Paths::new(
            paths.documents_dir(),
            record.identity.account_id().to_string(),
        );
        let blobs = list_external_blobs(&account_paths).await?;
        let paths = blobs
            .into_iter()
            .map(|file| {
                let path = account_paths.blob_location(
                    file.vault_id(),
                    file.secret_id(),
                    file.file_name().to_string(),
                );
                let name =
                    format!("{}/{}", record.identity.account_id(), file);
                (name, path)
            })
            .collect::<Vec<_>>();

        output.push((record, paths));
    }
    Ok(output)
}

fn create_database_backup(
    src: &Connection,
    dst: impl AsRef<Path>,
    progress: fn(backup::Progress),
) -> Result<()> {
    let start = SystemTime::now();
    tracing::debug!(
        path = %dst.as_ref().display(),
        "create_archive::db_backup::start"
    );

    let mut dst = Connection::open(dst.as_ref())?;
    let backup = backup::Backup::new(src, &mut dst)?;
    backup.run_to_completion(
        32,
        Duration::from_millis(250),
        Some(progress),
    )?;

    tracing::debug!(
        duration = ?start.elapsed(),
        "create_archive::db_backup::complete"
    );

    Ok(())
}
