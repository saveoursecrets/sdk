//! Sync protocol implementation types and traits.
#![deny(missing_docs)]
#![forbid(unsafe_code)]
#![cfg_attr(docsrs, feature(doc_cfg))]

mod auto_merge;
mod error;
mod remote;

pub use error::Error;

pub use auto_merge::*;
pub use remote::*;
