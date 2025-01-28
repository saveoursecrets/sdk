#![deny(missing_docs)]
#![forbid(unsafe_code)]
#![cfg_attr(all(doc, CHANNEL_NIGHTLY), feature(doc_auto_cfg))]
//! Read and write backup zip archives.
mod error;
mod types;
mod v1;

pub use v1::backup::{
    AccountBackup, AccountManifest, ExtractFilesLocation, ManifestEntry,
    RestoreOptions,
};
pub use v1::zip::*;

pub use error::Error;
pub use types::*;

/// Result type for the library.
pub(crate) type Result<T> = std::result::Result<T, Error>;
