//! Support for external encypted file blobs.
#![deny(missing_docs)]
#![forbid(unsafe_code)]
#![cfg_attr(docsrs, feature(doc_cfg))]

#[cfg(feature = "files")]
mod file_helpers;
#[cfg(feature = "files")]
mod types;

#[cfg(feature = "files")]
pub use file_helpers::*;
#[cfg(feature = "files")]
pub use types::*;
