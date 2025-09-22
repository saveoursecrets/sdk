//! Local socket change notification producer and consumer.
#![deny(missing_docs)]
#![forbid(unsafe_code)]
#![cfg_attr(all(doc, CHANNEL_NIGHTLY), feature(doc_auto_cfg))]

mod error;
pub use error::Error;

#[cfg(feature = "changes-consumer")]
pub mod consumer;
#[cfg(feature = "changes-producer")]
pub mod producer;

pub(crate) type Result<T> = std::result::Result<T, Error>;

use std::path::PathBuf;

pub(crate) const SOCKS: &str = "socks";
pub(crate) const SOCK_EXT: &str = "sock";

/// Socket file.
pub(crate) struct SocketFile(PathBuf);

impl From<PathBuf> for SocketFile {
    fn from(value: PathBuf) -> Self {
        Self(value)
    }
}

impl AsRef<PathBuf> for SocketFile {
    fn as_ref(&self) -> &PathBuf {
        &self.0
    }
}

impl Drop for SocketFile {
    fn drop(&mut self) {
        tracing::debug!(
            file = %self.0.display(),
            "changes::socket_file::drop",
        );
        let _ = std::fs::remove_file(&self.0);
    }
}
