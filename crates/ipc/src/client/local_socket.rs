use super::client_impl;
use crate::{
    codec, decode_proto, encode_proto, Error, IpcRequest, IpcResponse, Result,
};
use futures_util::sink::SinkExt;
use interprocess::local_socket::{
    tokio::{prelude::*, RecvHalf, SendHalf},
    GenericNamespaced,
};
use std::sync::atomic::AtomicU64;
use tokio_stream::StreamExt;
use tokio_util::{
    bytes::Bytes,
    codec::{FramedRead, FramedWrite, LengthDelimitedCodec},
};

/// Socket client for inter-process communication.
pub struct SocketClient {
    reader: RecvHalf,
    writer: FramedWrite<SendHalf, LengthDelimitedCodec>,
    pub(super) id: AtomicU64,
}

impl SocketClient {
    /// Create a client and connect the server.
    pub async fn connect(socket_name: &str) -> Result<Self> {
        let name = socket_name.to_ns_name::<GenericNamespaced>()?;
        let stream = LocalSocketStream::connect(name).await?;
        let (reader, writer) = stream.split();
        Ok(Self {
            reader,
            writer: FramedWrite::new(writer, codec()),
            id: AtomicU64::new(1),
        })
    }

    client_impl!();
}
