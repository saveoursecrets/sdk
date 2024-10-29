use futures_util::sink::SinkExt;
use tokio::net::{TcpListener, ToSocketAddrs};
use tokio_stream::StreamExt;
use tokio_util::codec::{BytesCodec, Decoder};

use crate::{decode_proto, Error, IpcRequest, Result};

/// Server for inter-process communication.
pub struct IpcServer;

impl IpcServer {
    /// Listen on a bind address.
    pub async fn listen<A: ToSocketAddrs>(addr: A) -> Result<()> {
        let listener = TcpListener::bind(&addr).await?;

        loop {
            let (socket, _) = listener.accept().await?;

            tokio::spawn(async move {
                let mut framed = BytesCodec::new().framed(socket);
                while let Some(message) = framed.next().await {
                    match message {
                        Ok(bytes) => {
                            let request: IpcRequest = decode_proto(&bytes)?;
                            println!("Server got {:#?}", request);
                            framed.send(bytes).await?;
                        }
                        Err(err) => {
                            println!("Socket closed with error: {:?}", err)
                        }
                    }
                }
                println!("Socket received FIN packet and closed connection");

                Ok::<(), Error>(())
            });
        }
    }
}
