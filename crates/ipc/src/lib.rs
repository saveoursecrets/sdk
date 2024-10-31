#![deny(missing_docs)]
#![forbid(unsafe_code)]
#![cfg_attr(all(doc, CHANNEL_NIGHTLY), feature(doc_auto_cfg))]
//! Inter-process communcation library for [Save Our Secrets](https://saveoursecrets.com/).
//!
//! Supports a local socket transport using [interprocess](https://docs.rs/interprocess/latest/interprocess/) which is enabled by default and an alternative TCP transport which can be enabled using the `tcp` feature if required.

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
    IpcService, LocalAccountIpcService, NetworkAccountIpcService,
};

#[cfg(feature = "tcp")]
pub use server::{LocalAccountTcpServer, NetworkAccountTcpServer};

#[cfg(feature = "tcp")]
pub use client::TcpClient;

#[cfg(feature = "local-socket")]
pub use server::{LocalAccountSocketServer, NetworkAccountSocketServer};

#[cfg(feature = "local-socket")]
pub use client::SocketClient;

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
