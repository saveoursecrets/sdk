#![deny(missing_docs)]
#![forbid(unsafe_code)]
#![cfg_attr(all(doc, CHANNEL_NIGHTLY), feature(doc_auto_cfg))]
//! Events logs backed by the file system.
mod encoding;
mod error;
pub mod events;
pub mod formats;
pub mod vault_writer;

pub use error::Error;
pub use vault_writer::VaultFileWriter;

/// AccessPoint that mirrors changes to a vault on disc.
pub type FileSystemAccessPoint<E> = sos_vault::AccessPoint<E>;

/// Result type for the library.
pub(crate) type Result<T> = std::result::Result<T, Error>;
