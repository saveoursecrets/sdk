//! Integrity checks for vaults, event logs and external files.
mod account_integrity;
mod error;
mod event_integrity;
#[cfg(feature = "files")]
mod file_integrity;
mod vault_integrity;

pub use account_integrity::{account_integrity, FolderIntegrityEvent};
pub use event_integrity::event_integrity;
pub use vault_integrity::vault_integrity;

#[cfg(feature = "files")]
pub use file_integrity::{file_integrity, FileIntegrityEvent};

pub use error::Error;

/// Result type for the library.
pub type Result<T> = std::result::Result<T, Error>;

use std::path::PathBuf;

/// Reasons why an integrity check can fail.
#[derive(Debug)]
pub enum IntegrityFailure {
    /// File is missing.
    Missing(PathBuf),
    /// Checksum mismatch, file is corrupted.
    Corrupted {
        /// File path.
        path: PathBuf,
        /// Expected file name checksum.
        expected: String,
        /// Actual file name checksum.
        actual: String,
    },
    /// Other error encountered.
    Error(Error),
}
