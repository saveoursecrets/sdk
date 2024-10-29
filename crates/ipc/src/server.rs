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
    decode_proto, encode_proto,
    protocol::{WireIpcRequest, WireIpcResponse},
    Error, IpcRequest, IpcService, LocalAccountIpcService,
    NetworkAccountIpcService, Result,
};

pub type NetworkAccountIpcServer = IpcServer<NetworkAccountIpcService>;
pub type LocalAccountIpcServer = IpcServer<LocalAccountIpcService>;

/// Server for inter-process communication.
pub struct IpcServer<S>
where
    S: IpcService + Send + 'static,
{
    phantom: std::marker::PhantomData<S>,
}

impl<S> IpcServer<S>
where
    S: IpcService + Send + 'static,
{
    /// Listen on a bind address.
    pub async fn listen<A: ToSocketAddrs>(
        addr: A,
        service: Arc<Mutex<S>>,
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
                            tracing::debug!(
                                len = bytes.len(),
                                "ipc_server::socket_recv"
                            );
                            let request: WireIpcRequest =
                                decode_proto(&bytes)?;
                            tracing::debug!(
                                request = ?request,
                                "ipc_server::socket_request"
                            );
                            let request: IpcRequest = request.try_into()?;
                            let mut handler = service.lock().await;
                            let response = handler.handle(request).await?;
                            tracing::debug!(
                                response = ?response,
                                "ipc_server::socket_response"
                            );
                            let response: WireIpcResponse = response.into();
                            let buffer = encode_proto(&response)?;
                            let bytes: BytesMut = buffer.as_slice().into();
                            framed.send(bytes).await?;
                        }
                        Err(err) => {
                            tracing::error!(
                              error = ?err,
                              "ipc_server::socket_error",
                            );
                        }
                    }
                }
                tracing::debug!("ipc_server::socket_closed");

                Ok::<(), Error>(())
            });
        }
    }
}
