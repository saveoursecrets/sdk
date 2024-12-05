use futures_util::sink::SinkExt;
use http::StatusCode;
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
    codec, decode_proto, encode_proto, io_err, Error, IpcService,
    WireLocalRequest, WireLocalResponse,
};

use sos_protocol::local_transport::{LocalRequest, LocalResponse};

mod local_socket;
pub use local_socket::*;

async fn handle_conn<E, S, T>(service: Arc<RwLock<S>>, socket: T)
where
    S: IpcService<E> + Send + Sync + 'static,
    E: std::error::Error
        + Send
        + From<std::io::Error>
        + std::fmt::Debug
        + std::fmt::Display,
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
                    let response = LocalResponse::new_internal_error(err);
                    let response: WireLocalResponse = response.into();
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
    E: std::error::Error
        + Send
        + From<std::io::Error>
        + std::fmt::Debug
        + std::fmt::Display,
    T: AsyncRead + AsyncWrite + Sized,
{
    let request: WireLocalRequest = decode_proto(&bytes).map_err(io_err)?;
    let request: LocalRequest = request.try_into().map_err(io_err)?;
    tracing::debug!(
        request = ?request,
        "socket_server::socket_request"
    );
    let message_id = request.request_id();
    let handler = service.read().await;
    let duration = request.timeout_duration();
    let response = match timeout(duration, handler.handle(request)).await {
        Ok(res) => res,
        Err(_) => {
            tracing::debug!(
                duration = ?duration,
                "socket_server::request_timeout");
            LocalResponse::with_id(StatusCode::REQUEST_TIMEOUT, message_id)
        }
    };

    let response: WireLocalResponse = response.into();
    let buffer = encode_proto(&response).map_err(io_err)?;
    channel.send(buffer.into()).await?;
    Ok(())
}
