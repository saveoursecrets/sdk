use futures_util::sink::SinkExt;
use interprocess::local_socket::{
    tokio::prelude::*, GenericNamespaced, ListenerOptions,
};
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio_stream::StreamExt;
use tokio_util::{
    bytes::BytesMut,
    codec::{BytesCodec, Decoder},
};

use crate::{
    decode_proto, encode_proto, Error, IpcRequest, IpcService,
    LocalAccountIpcService, NetworkAccountIpcService, Result,
};

/// TCP server for network-enabled accounts.
pub type NetworkAccountSocketServer = SocketServer<NetworkAccountIpcService>;

/// TCP server for local accounts.
pub type LocalAccountSocketServer = SocketServer<LocalAccountIpcService>;

/// Socket server for inter-process communication.
pub struct SocketServer<S>
where
    S: IpcService + Send + Sync + 'static,
{
    phantom: std::marker::PhantomData<S>,
}

impl<S> SocketServer<S>
where
    S: IpcService + Send + Sync + 'static,
{
    /// Listen on a bind address.
    pub async fn listen(
        socket_name: &str,
        service: Arc<RwLock<S>>,
    ) -> Result<()> {
        let name = socket_name.to_ns_name::<GenericNamespaced>()?;
        let opts = ListenerOptions::new().name(name);
        let listener = match opts.create_tokio() {
            Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => {
                tracing::error!(
                    "Error: could not start server because the socket file is occupied. Please check if {socket_name} is in use by another process and try again."
                );
                return Err(e.into());
            }
            x => x?,
        };

        println!("Listener created...");

        loop {
            let socket = listener.accept().await?;
            let service = service.clone();

            tokio::spawn(async move {
                let mut framed = BytesCodec::new().framed(socket);
                while let Some(message) = framed.next().await {
                    match message {
                        Ok(bytes) => {
                            tracing::debug!(
                                len = bytes.len(),
                                "socket_server::socket_recv"
                            );
                            let request: IpcRequest = decode_proto(&bytes)?;
                            tracing::debug!(
                                request = ?request,
                                "socket_server::socket_request"
                            );
                            let mut handler = service.write().await;
                            let response = handler.handle(request).await?;
                            tracing::debug!(
                                response = ?response,
                                "socket_server::socket_response"
                            );
                            let buffer = encode_proto(&response)?;
                            let bytes: BytesMut = buffer.as_slice().into();
                            framed.send(bytes).await?;
                        }
                        Err(err) => {
                            tracing::error!(
                              error = ?err,
                              "socket_server::socket_error",
                            );
                        }
                    }
                }
                tracing::debug!("socket_server::socket_closed");

                Ok::<(), Error>(())
            });
        }
    }
}
