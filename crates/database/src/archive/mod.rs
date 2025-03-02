//! Create and import backup archives.
use sos_core::Paths;
use std::path::Path;

mod error;
mod export;
mod import;
mod types;

pub use error::Error;
pub use import::BackupImport;

pub(crate) type Result<T> = std::result::Result<T, Error>;

/// Export a backup archive.
pub async fn export_backup_archive(
    source_db: impl AsRef<Path>,
    paths: &Paths,
    output: impl AsRef<Path>,
) -> Result<()> {
    export::create(source_db, paths, output).await
}

/// Import from a backup archive.
pub async fn import_backup_archive(
    target_db: impl AsRef<Path>,
    paths: &Paths,
    input: impl AsRef<Path>,
) -> Result<BackupImport> {
    import::start(target_db, paths, input).await
}
