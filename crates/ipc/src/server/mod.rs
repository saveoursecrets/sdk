use futures_util::sink::SinkExt;
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio_stream::StreamExt;
use tokio_util::{
    bytes::BytesMut,
    codec::{BytesCodec, Decoder},
};

use crate::{
    decode_proto, encode_proto, IpcRequest, IpcService, Result,
    WireIpcRequest, WireIpcResponse,
};

#[cfg(feature = "tcp")]
mod tcp;

#[cfg(feature = "tcp")]
pub use tcp::*;

#[cfg(feature = "local-socket")]
mod local_socket;

#[cfg(feature = "local-socket")]
pub use local_socket::*;

async fn handle_conn<E, S, T>(
    service: Arc<RwLock<S>>,
    socket: T,
) -> Result<()>
where
    S: IpcService<E> + Send + Sync + 'static,
    E: Send,
    T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Sized,
{
    let mut framed = BytesCodec::new().framed(Box::pin(socket));
    while let Some(message) = framed.next().await {
        match message {
            Ok(bytes) => {
                tracing::debug!(
                    len = bytes.len(),
                    "socket_server::socket_recv"
                );
                let request: WireIpcRequest = decode_proto(&bytes)?;
                let request: (u64, IpcRequest) = request.try_into()?;
                tracing::debug!(
                    request = ?request,
                    "socket_server::socket_request"
                );
                let (message_id, request) = request;
                let handler = service.read().await;
                match handler.handle(request).await {
                    Ok(response) => {
                        tracing::debug!(
                            response = ?response,
                            "socket_server::socket_response"
                        );
                        let response: WireIpcResponse =
                            (message_id, response).into();
                        let buffer = encode_proto(&response)?;
                        let bytes: BytesMut = buffer.as_slice().into();
                        framed.send(bytes).await?;
                    }
                    Err(err) => todo!("handle service error"),
                }
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

    Ok(())
}
