use super::client_impl;
use crate::{
    codec, decode_proto, encode_proto, Error, IpcRequest, IpcResponse, Result,
};
use futures_util::sink::SinkExt;
use interprocess::local_socket::{tokio::prelude::*, GenericNamespaced};
use std::sync::atomic::AtomicU32;
use tokio_stream::StreamExt;
use tokio_util::codec::{Framed, LengthDelimitedCodec};

/// Socket client for inter-process communication.
pub struct SocketClient {
    socket: Framed<LocalSocketStream, LengthDelimitedCodec>,
    pub(super) id: AtomicU32,
}

impl SocketClient {
    /// Create a client and connect the server.
    pub async fn connect(socket_name: &str) -> Result<Self> {
        let name = socket_name.to_ns_name::<GenericNamespaced>()?;
        let io = LocalSocketStream::connect(name).await?;
        Ok(Self {
            socket: codec::framed(io),
            id: AtomicU32::new(1),
        })
    }

    client_impl!();
}
