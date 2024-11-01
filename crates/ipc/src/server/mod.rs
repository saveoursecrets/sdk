use futures_util::sink::SinkExt;
use std::{pin::Pin, sync::Arc};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::RwLock;
use tokio_stream::StreamExt;
use tokio_util::{
    bytes::BytesMut,
    codec::{BytesCodec, Decoder, Framed},
};

use crate::{
    decode_proto, encode_proto, io_err, IpcRequest, IpcService,
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

async fn handle_conn<E, S, T>(service: Arc<RwLock<S>>, socket: T)
where
    S: IpcService<E> + Send + Sync + 'static,
    E: Send + From<std::io::Error> + std::fmt::Debug,
    T: AsyncRead + AsyncWrite + Sized,
{
    let mut framed = BytesCodec::new().framed(Box::pin(socket));
    while let Some(message) = framed.next().await {
        match message {
            Ok(bytes) => {
                tracing::debug!(
                    len = bytes.len(),
                    "socket_server::socket_recv"
                );

                if let Err(err) =
                    handle_request(service.clone(), &mut framed, bytes).await
                {
                    // err.foo();
                    todo!("send error response {:#?}", err);
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
}

async fn handle_request<E, S, T>(
    service: Arc<RwLock<S>>,
    channel: &mut Framed<Pin<Box<T>>, BytesCodec>,
    bytes: BytesMut,
) -> std::result::Result<(), E>
where
    S: IpcService<E> + Send + Sync + 'static,
    E: Send + From<std::io::Error> + std::fmt::Debug,
    T: AsyncRead + AsyncWrite + Sized,
{
    let request: WireIpcRequest = decode_proto(&bytes).map_err(io_err)?;
    let request: (u64, IpcRequest) = request.try_into().map_err(io_err)?;
    tracing::debug!(
        request = ?request,
        "socket_server::socket_request"
    );
    let (message_id, request) = request;
    let handler = service.read().await;
    let response = handler.handle(request).await?;
    tracing::debug!(
        response = ?response,
        "socket_server::socket_response"
    );
    let response: WireIpcResponse = (message_id, response).into();
    let buffer = encode_proto(&response).map_err(io_err)?;
    let bytes: BytesMut = buffer.as_slice().into();
    channel.send(bytes).await?;

    Ok(())
}
