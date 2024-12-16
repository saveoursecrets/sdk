#![deny(missing_docs)]
#![forbid(unsafe_code)]
#![cfg_attr(all(doc, CHANNEL_NIGHTLY), feature(doc_auto_cfg))]
//! Inter-process communcation library
//! for [Save Our Secrets](https://saveoursecrets.com/) that listens and
//! sends HTTP requests over a named pipe.
//!
//! This crate also includes the source for the `sos-native-bridge`
//! helper executable which forwards length-delimited JSON requests
//! into HTTP requests sent to the named pipe.

mod error;

mod integration;
pub use integration::*;

pub use error::Error;

/// Result type for the library.
pub type Result<T> = std::result::Result<T, Error>;
