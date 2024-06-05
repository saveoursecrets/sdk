//! Integrity checks for vaults, event logs and external files.
use std::path::PathBuf;

mod event_integrity;
#[cfg(feature = "files")]
mod file_integrity;
mod vault_integrity;

pub use event_integrity::event_integrity;
pub use vault_integrity::vault_integrity;

#[cfg(feature = "files")]
pub use file_integrity::{file_integrity_report, FileIntegrityEvent};

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
}
