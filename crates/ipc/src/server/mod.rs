use futures_util::sink::SinkExt;
use std::{pin::Pin, sync::Arc};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    sync::RwLock,
    time::timeout,
};
use tokio_stream::StreamExt;
use tokio_util::{
    bytes::BytesMut,
    codec::{Framed, LengthDelimitedCodec},
};

use crate::{
    codec, decode_proto, encode_proto, io_err, Error, IpcRequest,
    IpcResponse, IpcResponseError, IpcService, WireIpcRequest,
    WireIpcResponse,
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
    E: Send + From<std::io::Error> + std::fmt::Debug + std::fmt::Display,
    T: AsyncRead + AsyncWrite + Sized,
{
    let io = Box::pin(socket);
    let mut framed = codec::framed(io);

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
                    // Internal error, try to send a response and close
                    // the connection if we error here
                    let response = IpcResponse::Error(
                        0,
                        IpcResponseError {
                            code: -1,
                            message: err.to_string(),
                        },
                    );
                    let response: WireIpcResponse = response.into();
                    match encode_proto(&response) {
                        Ok(buffer) => {
                            match framed.send(buffer.into()).await {
                                Err(err) => {
                                    tracing::error!(
                                        error = ?err,
                                        "socket_server::internal_error::close_connection"
                                    );
                                    break;
                                }
                                _ => {}
                            }
                        }
                        Err(err) => {
                            tracing::error!(
                                error = ?err,
                                "socket_server::internal_error::close_connection"
                            );
                            break;
                        }
                    }
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
    channel: &mut Framed<Pin<Box<T>>, LengthDelimitedCodec>,
    bytes: BytesMut,
) -> std::result::Result<(), E>
where
    S: IpcService<E> + Send + Sync + 'static,
    E: Send + From<std::io::Error> + std::fmt::Debug,
    T: AsyncRead + AsyncWrite + Sized,
{
    let request: WireIpcRequest = decode_proto(&bytes).map_err(io_err)?;
    let request: IpcRequest = request.try_into().map_err(io_err)?;
    tracing::debug!(
        request = ?request,
        "socket_server::socket_request"
    );
    let message_id = request.message_id;
    let handler = service.read().await;
    let duration = request.timeout_duration();
    let response = match timeout(duration, handler.handle(request)).await {
        Ok(res) => res?,
        Err(_) => {
            tracing::debug!(
                duration = ?duration,
                "socket_server::request_timeout");
            IpcResponse::Error(
                message_id,
                Error::ServiceTimeout(duration).into(),
            )
        }
    };

    let response: WireIpcResponse = response.into();
    let buffer = encode_proto(&response).map_err(io_err)?;
    channel.send(buffer.into()).await?;
    Ok(())
}
