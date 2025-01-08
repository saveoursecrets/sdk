#![deny(missing_docs)]
#![forbid(unsafe_code)]
#![cfg_attr(all(doc, CHANNEL_NIGHTLY), feature(doc_auto_cfg))]
//! Events logs backed by the file system.
mod encoding;
mod error;
pub mod events;
pub mod folder;
pub mod formats;
pub mod vault_writer;

pub use error::Error;
pub use vault_writer::VaultFileWriter;

/// Gatekeeper that mirrors changes to a vault on disc.
pub type FileSystemGatekeeper = sos_vault::Gatekeeper<Error>;

/// Result type for the library.
pub(crate) type Result<T> = std::result::Result<T, Error>;

use async_trait::async_trait;
use binary_stream::futures::{Decodable, Encodable};
use sos_core::{
    commit::{CommitHash, CommitTree},
    encode,
    events::EventRecord,
};

/// Encode an event into a record.
#[async_trait]
pub trait IntoRecord {
    /// Encode an event into a record using a zero last commit
    /// and a date time from now.
    async fn default_record(&self) -> Result<EventRecord>;
}

#[async_trait]
impl<'a, T> IntoRecord for &'a T
where
    T: Default + Encodable + Decodable + Send + Sync,
{
    async fn default_record(&self) -> Result<EventRecord> {
        let bytes = encode(*self).await?;
        let commit = CommitHash(CommitTree::hash(&bytes));
        Ok(EventRecord::new(
            Default::default(),
            Default::default(),
            commit,
            bytes,
        ))
    }
}
