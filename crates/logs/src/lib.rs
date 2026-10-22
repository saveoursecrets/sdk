//! Log tracing output to disc.
#![deny(missing_docs)]
#![forbid(unsafe_code)]
#![cfg_attr(docsrs, feature(doc_cfg))]

mod error;
mod logger;

pub use error::Error;
pub use logger::{LOG_FILE_NAME, LogFileStatus, Logger};

pub(crate) type Result<T> = std::result::Result<T, Error>;
