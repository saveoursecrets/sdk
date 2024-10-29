use crate::{
    decode_proto, encode_proto,
    protocol::{WireIpcRequest, WireIpcResponse},
    Error, IpcRequest, IpcResponse, Result,
};
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
}

impl IpcClient {
    /// Create a client and connect the server.
    pub async fn connect<A: ToSocketAddrs>(addr: A) -> Result<Self> {
        let stream = TcpStream::connect(&addr).await?;
        let (reader, writer) = stream.into_split();
        Ok(Self { reader, writer })
    }

    /// Send a request.
    async fn send(&mut self, request: IpcRequest) -> Result<IpcResponse> {
        let request: WireIpcRequest = request.into();
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
                    let response: WireIpcResponse = decode_proto(&bytes)?;
                    reply = Some(response.try_into()?);
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
