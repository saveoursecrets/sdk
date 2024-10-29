use crate::{encode_proto, IpcRequest, Result};
use tokio::io::AsyncWriteExt;
use tokio::net::{tcp::OwnedWriteHalf, TcpStream, ToSocketAddrs};
use tokio_stream::StreamExt;
use tokio_util::codec::{BytesCodec, FramedRead};

/// Client for inter-process communication.
pub struct IpcClient {
    writer: OwnedWriteHalf,
}

impl IpcClient {
    /// Create a new client and connect the stream.
    pub async fn connect<A: ToSocketAddrs>(addr: A) -> Result<Self> {
        let stream = TcpStream::connect(&addr).await?;
        let (reader, writer) = stream.into_split();
        tokio::task::spawn(async move {
            let mut stream = FramedRead::new(reader, BytesCodec::new());
            while let Some(message) = stream.next().await {
                match message {
                    Ok(bytes) => println!("client got bytes: {:?}", bytes),
                    Err(err) => {
                        println!("Socket closed with error: {:?}", err)
                    }
                }
            }
        });
        Ok(Self { writer })
    }

    /// Send a request.
    pub async fn send(&mut self, request: IpcRequest) -> Result<()> {
        let buf = encode_proto(&request)?;
        self.write_all(&buf).await
    }

    /// Write a buffer.
    async fn write_all(&mut self, buf: &[u8]) -> Result<()> {
        Ok(self.writer.write_all(buf).await?)
    }
}
