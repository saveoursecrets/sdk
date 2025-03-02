//! Read and write backup zip archives.
mod error;
mod export;
mod import;
mod types;

pub use error::Error;
pub use export::export_backup_archive;
pub use import::import_backup_archive;
pub use types::*;

/// Result type for the library.
pub(crate) type Result<T> = std::result::Result<T, Error>;
