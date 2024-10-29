mod error;

mod bindings;
mod client;
mod server;
mod service;

pub use error::Error;

pub type Result<T> = std::result::Result<T, Error>;

pub use bindings::*;
pub use client::IpcClient;
pub use server::{LocalAccountIpcServer, NetworkAccountIpcServer};
pub use service::{
    IpcService, LocalAccountIpcService, NetworkAccountIpcService,
};

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
