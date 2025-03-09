#![deny(missing_docs)]
#![forbid(unsafe_code)]
#![cfg_attr(all(doc, CHANNEL_NIGHTLY), feature(doc_auto_cfg))]
//! Log tracing output to disc.
mod error;
mod logger;

pub use error::Error;
pub use logger::{LogFileStatus, Logger};

pub(crate) type Result<T> = std::result::Result<T, Error>;
