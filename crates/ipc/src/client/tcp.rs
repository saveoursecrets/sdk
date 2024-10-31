use super::client_impl;
use crate::{decode_proto, encode_proto, Error, Result, WireIpcResponse};
use std::sync::atomic::AtomicU64;
use tokio::io::AsyncWriteExt;
use tokio::net::{
    tcp::{OwnedReadHalf, OwnedWriteHalf},
    TcpStream, ToSocketAddrs,
};
use tokio_stream::StreamExt;
use tokio_util::codec::{BytesCodec, FramedRead};

/// TCP client for inter-process communication.
pub struct TcpClient {
    reader: OwnedReadHalf,
    writer: OwnedWriteHalf,
    pub(super) id: AtomicU64,
}

impl TcpClient {
    /// Create a client and connect the server.
    pub async fn connect<A: ToSocketAddrs>(addr: A) -> Result<Self> {
        let stream = TcpStream::connect(&addr).await?;
        let (reader, writer) = stream.into_split();
        Ok(Self {
            reader,
            writer,
            id: AtomicU64::new(1),
        })
    }

    client_impl!();
}
