use super::client_impl;
use crate::{
    codec, decode_proto, encode_proto, Error, IpcRequest, IpcResponse, Result,
};

use futures_util::sink::SinkExt;
use std::sync::atomic::AtomicU64;
use tokio::net::{
    tcp::{OwnedReadHalf, OwnedWriteHalf},
    TcpStream, ToSocketAddrs,
};
use tokio_stream::StreamExt;
use tokio_util::{
    bytes::Bytes,
    codec::{FramedRead, FramedWrite, LengthDelimitedCodec},
};

/// TCP client for inter-process communication.
pub struct TcpClient {
    reader: OwnedReadHalf,
    writer: FramedWrite<OwnedWriteHalf, LengthDelimitedCodec>,
    pub(super) id: AtomicU64,
}

impl TcpClient {
    /// Create a client and connect the server.
    pub async fn connect<A: ToSocketAddrs>(addr: A) -> Result<Self> {
        let stream = TcpStream::connect(&addr).await?;
        let (reader, writer) = stream.into_split();
        Ok(Self {
            reader,
            writer: FramedWrite::new(writer, codec()),
            id: AtomicU64::new(1),
        })
    }

    client_impl!();
}
