use super::client_impl;
use crate::{
    codec, decode_proto, encode_proto, Error, IpcRequest, IpcResponse, Result,
};

use futures_util::sink::SinkExt;
use std::sync::atomic::AtomicU32;
use tokio::net::{TcpStream, ToSocketAddrs};
use tokio_stream::StreamExt;
use tokio_util::codec::{Framed, LengthDelimitedCodec};

/// TCP client for inter-process communication.
pub struct TcpClient {
    socket: Framed<TcpStream, LengthDelimitedCodec>,
    pub(super) id: AtomicU32,
}

impl TcpClient {
    /// Create a client and connect the server.
    pub async fn connect<A: ToSocketAddrs>(addr: A) -> Result<Self> {
        let io = TcpStream::connect(&addr).await?;
        Ok(Self {
            socket: codec::framed(io),
            id: AtomicU32::new(1),
        })
    }

    client_impl!();
}
