//! Read and write backup zip archives.
mod backup;
mod error;
mod types;
mod zip;

pub use backup::{
    AccountBackup, AccountManifest, ExtractFilesLocation, ManifestEntry,
    RestoreOptions,
};
pub use zip::*;

pub use error::Error;
pub use types::*;

/// Result type for the library.
pub(crate) type Result<T> = std::result::Result<T, Error>;
