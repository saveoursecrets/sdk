use http::StatusCode;
use interprocess::local_socket::{
    tokio::prelude::*, GenericNamespaced, ListenerOptions,
};
use sos_net::{
    sdk::prelude::{Account, LocalAccount},
    NetworkAccount,
};
use sos_protocol::local_transport::{LocalRequest, LocalResponse};
use std::{pin::Pin, sync::Arc};

use futures_util::sink::SinkExt;
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
    codec, decode_proto, encode_proto, io_err, IpcService, WireLocalRequest,
    WireLocalResponse,
};

use crate::{LocalAccountIpcService, NetworkAccountIpcService, Result};

/// Socket server for network-enabled accounts.
pub type NetworkAccountSocketServer = SocketServer<
    NetworkAccountIpcService,
    <NetworkAccount as Account>::Error,
>;

/// Socket server for local accounts.
pub type LocalAccountSocketServer =
    SocketServer<LocalAccountIpcService, <LocalAccount as Account>::Error>;

/// Socket server for inter-process communication.
pub struct SocketServer<S, E>
where
    S: IpcService<E> + Send + Sync + 'static,
    E: Send,
{
    phantom: std::marker::PhantomData<(S, E)>,
}

impl<S, E> SocketServer<S, E>
where
    S: IpcService<E> + Send + Sync + 'static,
    E: std::error::Error
        + Send
        + From<std::io::Error>
        + std::fmt::Debug
        + std::fmt::Display,
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

        loop {
            let socket = listener.accept().await?;
            let service = service.clone();

            tokio::spawn(async move {
                handle_conn(service, socket).await;
            });
        }
    }
}

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
