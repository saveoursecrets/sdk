use futures_util::sink::SinkExt;
use std::sync::Arc;
use tokio::net::{TcpListener, ToSocketAddrs};
use tokio::sync::Mutex;
use tokio_stream::StreamExt;
use tokio_util::{
    bytes::BytesMut,
    codec::{BytesCodec, Decoder},
};

use crate::{
    decode_proto, encode_proto, Error, IpcRequest, IpcService, Result,
};

/// Server for inter-process communication.
pub struct IpcServer;

impl IpcServer {
    /// Listen on a bind address.
    pub async fn listen<A: ToSocketAddrs>(
        addr: A,
        service: Arc<Mutex<IpcService>>,
    ) -> Result<()> {
        let listener = TcpListener::bind(&addr).await?;
        loop {
            let (socket, _) = listener.accept().await?;
            let service = service.clone();
            tokio::spawn(async move {
                let mut framed = BytesCodec::new().framed(socket);
                while let Some(message) = framed.next().await {
                    match message {
                        Ok(bytes) => {
                            let request: IpcRequest = decode_proto(&bytes)?;
                            // println!("Server got {:#?}", request);
                            let mut handler = service.lock().await;
                            let response = handler.handle(request).await?;
                            let buffer = encode_proto(&response)?;
                            let bytes: BytesMut = buffer.as_slice().into();
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
