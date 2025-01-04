#![deny(missing_docs)]
#![forbid(unsafe_code)]
#![cfg_attr(all(doc, CHANNEL_NIGHTLY), feature(doc_auto_cfg))]
//! Events logs backed by the file system.
mod encoding;
mod error;
pub mod events;
pub mod folder;
pub mod formats;

pub use error::Error;

/// Result type for the library.
pub(crate) type Result<T> = std::result::Result<T, Error>;

use binary_stream::{Endian, Options};

/// Maximum buffer size allowed when encoding and decoding.
const MAX_BUFFER_SIZE: usize = 1024 * 1024 * 16;

/// Standard encoding options.
pub fn encoding_options() -> Options {
    Options {
        endian: Endian::Little,
        max_buffer_size: Some(MAX_BUFFER_SIZE),
    }
}

use async_trait::async_trait;
use binary_stream::futures::{Decodable, Encodable};
use events::EventRecord;
use sos_core::{
    commit::{CommitHash, CommitTree},
    encode,
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
        Ok(EventRecord(
            Default::default(),
            Default::default(),
            commit,
            bytes,
        ))
    }
}
