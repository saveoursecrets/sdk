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

/// Forbid usage of println! macro.
///
/// The native bridge code writes to stdout and
/// using println! in the wrong place will cause
/// strange errors with the tokio FramedRead typically
/// something like "frame size too big" because we have
/// inadvertently written a bad length prefix to stdout.
#[macro_export]
#[allow(missing_fragment_specifier)]
macro_rules! println {
    ($($any:tt)*) => {
        compile_error!("println! macro is forbidden, use eprintln! instead");
    };
}

#[cfg(feature = "integration")]
pub mod integration;

#[cfg(feature = "memory-http-server")]
pub mod memory_server;

#[cfg(any(
    feature = "native-bridge-server",
    feature = "native-bridge-client"
))]
pub mod native_bridge;
#[cfg(feature = "native-bridge-server")]
mod web_service;
#[cfg(feature = "native-bridge-server")]
pub(crate) use web_service::LocalWebService;
#[cfg(feature = "local-transport")]
pub mod local_transport;

pub use error::Error;

/// Result type for the library.
pub type Result<T> = std::result::Result<T, Error>;

use serde::{Deserialize, Serialize};

/// Information about the service.
#[typeshare::typeshare]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ServiceAppInfo {
    /// App name.
    pub name: String,
    /// App version.
    pub version: String,
}

impl Default for ServiceAppInfo {
    fn default() -> Self {
        Self {
            name: env!("CARGO_PKG_NAME").to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
        }
    }
}
