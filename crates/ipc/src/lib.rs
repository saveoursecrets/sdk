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

#[cfg(feature = "compression-zlib")]
pub(crate) mod compression;

#[cfg(feature = "integration")]
pub mod integration;

#[cfg(feature = "client")]
pub mod client;
#[cfg(any(
    feature = "native-bridge-server",
    feature = "native-bridge-client"
))]
pub mod native_bridge;
#[cfg(feature = "server")]
pub mod server;
#[cfg(feature = "server")]
mod web_service;
#[cfg(feature = "server")]
pub(crate) use web_service::LocalWebService;
#[cfg(feature = "local-transport")]
pub mod local_transport;

pub use error::Error;

/// Result type for the library.
pub type Result<T> = std::result::Result<T, Error>;

/// Information about the service.
#[typeshare::typeshare]
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ServiceAppInfo {
    /// App name.
    pub name: String,
    /// App version.
    pub version: String,
    /// App build number.
    pub build_number: u32,
}

impl Default for ServiceAppInfo {
    fn default() -> Self {
        Self {
            name: env!("CARGO_PKG_NAME").to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            build_number: 0,
        }
    }
}

#[doc(hidden)]
pub fn remove_socket_file(socket_name: &str) {
    if cfg!(target_os = "macos") {
        let socket_path =
            std::path::PathBuf::from(format!("/tmp/{}", socket_name));
        if socket_path.exists() {
            let _ = std::fs::remove_file(&socket_path);
        }
    }
}
