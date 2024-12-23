#![deny(missing_docs)]
#![forbid(unsafe_code)]
#![cfg_attr(all(doc, CHANNEL_NIGHTLY), feature(doc_auto_cfg))]
//! Inter-process communication library supporting the
//! native messaging API for browser extensions.

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

#[cfg(feature = "memory-http-server")]
pub mod memory_server;

#[cfg(any(
    feature = "extension-helper-server",
    feature = "extension-helper-client"
))]
pub mod extension_helper;
#[cfg(feature = "extension-helper-server")]
mod web_service;
#[cfg(feature = "extension-helper-server")]
pub(crate) use web_service::LocalWebService;
#[cfg(feature = "extension-helper-server")]
pub use web_service::WebAccounts;
#[cfg(feature = "local-transport")]
pub mod local_transport;

pub use error::Error;

#[cfg(feature = "extension-helper-server")]
pub use error::FileEventError;

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
