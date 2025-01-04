#![deny(missing_docs)]
#![forbid(unsafe_code)]
#![cfg_attr(all(doc, CHANNEL_NIGHTLY), feature(doc_auto_cfg))]
//! Read and write backup zip archives.

mod types;
#[cfg(feature = "zip")]
pub mod zip;

pub use types::*;
