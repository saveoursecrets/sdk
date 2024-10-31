#![deny(missing_docs)]
#![forbid(unsafe_code)]
#![cfg_attr(all(doc, CHANNEL_NIGHTLY), feature(doc_auto_cfg))]
//! Inter-process communcation library for [Save Our Secrets](https://saveoursecrets.com/).
//!
//! Supports a local socket transport using [interprocess](https://docs.rs/interprocess/latest/interprocess/) which is enabled by default and an alternative TCP transport which can be enabled using the `tcp` feature if required.
//!
//! Communication uses [protocol buffers](https://protobuf.dev/)
//! however to facilitate browser extensions that need to use
//! [native messaging](https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/Native_messaging) all request and response types must
//! also implement the [serde](https://docs.rs/serde/latest/serde/) traits.
//!
//! This crate also includes the source for the `sos-native-bridge`
//! executable which translates JSON requests into the underlying protobuf
//! messages and relay them over the IPC channel.

mod error;

mod bindings;
mod client;
mod server;
mod service;

pub use error::Error;

/// Result type for the library.
pub type Result<T> = std::result::Result<T, Error>;

pub use bindings::*;
pub use service::{
    AuthenticateCommand, IpcService, IpcServiceHandler,
    LocalAccountAuthenticateCommand, LocalAccountIpcService,
    NetworkAccountAuthenticateCommand, NetworkAccountIpcService,
    ServiceDelegate,
};

#[cfg(feature = "tcp")]
pub use server::{LocalAccountTcpServer, NetworkAccountTcpServer};

#[cfg(feature = "tcp")]
pub use client::TcpClient;

#[cfg(feature = "local-socket")]
pub use server::{LocalAccountSocketServer, NetworkAccountSocketServer};

#[cfg(feature = "local-socket")]
pub use client::SocketClient;

pub use client::app_integration::*;

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
