#![deny(missing_docs)]
#![forbid(unsafe_code)]
#![cfg_attr(all(doc, CHANNEL_NIGHTLY), feature(doc_auto_cfg))]
//! Inter-process communcation library
//! for [Save Our Secrets](https://saveoursecrets.com/).
//!
//! Communication uses [protocol buffers](https://protobuf.dev/)
//! however to facilitate browser extensions that need to use
//! [native messaging](https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/Native_messaging) all request and response types must
//! also implement the [serde](https://docs.rs/serde/latest/serde/) traits.
//!
//! This crate also includes the source for the `sos-native-bridge`
//! helpers executable which translates length-delimited JSON requests
//! into the underlying protobuf messages and relay them over the IPC
//! channel.

mod error;

mod bindings;
#[cfg(feature = "client")]
mod client;
#[cfg(feature = "server")]
mod local_server;
#[cfg(feature = "native-bridge")]
pub mod native_bridge;
#[cfg(feature = "server")]
mod server;
#[cfg(feature = "client")]
pub use client::SocketClient;
#[cfg(feature = "server")]
pub(crate) use local_server::LocalServer;
#[cfg(feature = "server")]
pub use server::SocketServer;

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

/// Encode to protobuf.
pub(crate) fn encode_proto<T: prost::Message>(value: &T) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    buf.reserve(value.encoded_len());
    value.encode(&mut buf)?;
    Ok(buf)
}

/// Decode from protobuf.
pub(crate) fn decode_proto<T: prost::Message + Default>(
    buffer: &[u8],
) -> Result<T> {
    Ok(T::decode(buffer)?)
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
