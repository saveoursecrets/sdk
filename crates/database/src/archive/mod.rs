//! Create and import backup archives.
use async_sqlite::rusqlite::Connection;
use sos_core::Paths;
use std::path::Path;

mod archive;
mod error;
mod types;
mod zip;

pub use error::Error;

pub(crate) type Result<T> = std::result::Result<T, Error>;

/// Create a backup archive.
pub async fn create_backup_archive(
    source_db: &Connection,
    paths: &Paths,
    output: impl AsRef<Path>,
) -> Result<()> {
    archive::create(source_db, paths, output).await
}
