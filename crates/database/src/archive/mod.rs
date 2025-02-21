//! Create and import backup archives.
use async_sqlite::rusqlite::Connection;
use sos_core::Paths;
use std::path::Path;

mod archive;
mod error;
mod import;
mod types;
mod zip;

pub use error::Error;
pub use import::BackupImport;

pub(crate) type Result<T> = std::result::Result<T, Error>;

/// Create a backup archive.
pub async fn create_backup_archive(
    source_db: impl AsRef<Path>,
    paths: &Paths,
    output: impl AsRef<Path>,
) -> Result<()> {
    archive::create(source_db, paths, output).await
}

/// Import from a backup archive.
pub async fn import_backup_archive<'conn>(
    target_db: &'conn mut Connection,
    paths: &Paths,
    input: impl AsRef<Path>,
) -> Result<BackupImport<'conn>> {
    import::start(target_db, paths, input).await
}
