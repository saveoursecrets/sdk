use std::{
    collections::HashMap,
    sync::atomic::{AtomicU64, Ordering},
};

use crate::{
    decode_proto, encode_proto, ipc_request_body, Error, IpcRequest,
    IpcRequestBody, IpcResponse, Result, VoidBody,
};
use sos_net::sdk::prelude::Address;
use tokio::io::AsyncWriteExt;
use tokio::net::{
    tcp::{OwnedReadHalf, OwnedWriteHalf},
    TcpStream, ToSocketAddrs,
};
use tokio_stream::StreamExt;
use tokio_util::codec::{BytesCodec, FramedRead};

/// Client for inter-process communication.
pub struct IpcClient {
    reader: OwnedReadHalf,
    writer: OwnedWriteHalf,
    id: AtomicU64,
}

impl IpcClient {
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

    /// Account authenticated state.
    pub async fn authenticated(&mut self) -> Result<HashMap<Address, bool>> {
        let request = IpcRequest {
            message_id: self.id.fetch_add(1, Ordering::SeqCst),
            body: Some(IpcRequestBody {
                inner: Some(ipc_request_body::Inner::Authenticated(
                    VoidBody {},
                )),
            }),
        };

        let response = self.send(request).await?;
        Ok(response.as_authenticated()?)
    }

    /// Send a request.
    async fn send(&mut self, request: IpcRequest) -> Result<IpcResponse> {
        let buf = encode_proto(&request)?;
        self.write_all(&buf).await?;
        self.read_response().await
    }

    /// Read response from the server.
    async fn read_response(&mut self) -> Result<IpcResponse> {
        let mut stream = FramedRead::new(&mut self.reader, BytesCodec::new());

        let mut reply: Option<IpcResponse> = None;
        while let Some(message) = stream.next().await {
            match message {
                Ok(bytes) => {
                    let response: IpcResponse = decode_proto(&bytes)?;
                    reply = Some(response);
                    break;
                }
                Err(err) => {
                    return Err(err.into());
                }
            }
        }
        reply.ok_or(Error::NoResponse)
    }

    /// Write a buffer.
    async fn write_all(&mut self, buf: &[u8]) -> Result<()> {
        Ok(self.writer.write_all(buf).await?)
    }
}
