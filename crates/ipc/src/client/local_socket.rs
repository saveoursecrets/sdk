use super::client_impl;
use crate::{
    decode_proto, encode_proto, Error, IpcRequest, IpcResponse, Result,
};
use interprocess::local_socket::{
    tokio::{prelude::*, RecvHalf, SendHalf},
    GenericNamespaced,
};
use std::sync::atomic::AtomicU64;
use tokio::io::AsyncWriteExt;
use tokio_stream::StreamExt;
use tokio_util::codec::{BytesCodec, FramedRead};

/// Socket client for inter-process communication.
pub struct SocketClient {
    reader: RecvHalf,
    writer: SendHalf,
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
            writer,
            id: AtomicU64::new(1),
        })
    }

    client_impl!();
}
