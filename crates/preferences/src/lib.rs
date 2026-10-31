//! Preferences management for the [Save Our Secrets](https://saveoursecrets.com) SDK.
#![deny(missing_docs)]
#![forbid(unsafe_code)]
#![cfg_attr(docsrs, feature(doc_cfg))]
mod error;
mod preferences;

pub use error::Error;
pub use preferences::*;
