//! Listen for change notifications on a websocket connection.
use crate::{
    Error, NetworkChangeEvent, Result, WireEncodeDecode,
    network_client::{NetworkConfig, NetworkRetry, WebSocketRequest},
    transfer::CancelReason,
};
use futures::{
    Future, FutureExt, StreamExt,
    stream::{Map, SplitStream},
};
use prost::bytes::Bytes;
use rustls::{ClientConfig, RootCertStore};
use sos_core::{AccountId, Origin};
use sos_signer::ed25519::BoxedEd25519Signer;
use std::pin::Pin;
use std::sync::Arc;
use tokio::{net::TcpStream, sync::watch, time::Duration};
use tokio_tungstenite::{
    Connector, MaybeTlsStream, WebSocketStream, client_async_tls_with_config,
    connect_async,
    tungstenite::{
        self,
        client::IntoClientRequest,
        protocol::{
            CloseFrame, Message,
            frame::{Utf8Bytes, coding::CloseCode},
        },
    },
};

use super::{bearer_prefix, encode_device_signature};

type ChangeEventFuture =
    Pin<Box<dyn Future<Output = Result<NetworkChangeEvent>> + Send>>;

/// Options used when listening for change notifications.
#[derive(Clone)]
pub struct ListenOptions {
    /// Identifier for this connection.
    ///
    /// Should match the identifier used by the RPC
    /// client so the server can ignore sending change notifications
    /// to the caller.
    pub(crate) connection_id: String,

    /// Network retry state.
    pub(crate) retry: NetworkRetry,

    network_config: NetworkConfig,
}

impl ListenOptions {
    /// Create new listen options using the default retry
    /// configuration.
    pub fn new(
        connection_id: String,
        network_config: NetworkConfig,
        retry: Option<NetworkRetry>,
    ) -> Result<Self> {
        Ok(Self {
            connection_id,
            network_config,
            retry: retry.unwrap_or_else(|| NetworkRetry::new(16, 1000)),
        })
    }
}

/// Get the URI for a websocket changes connection.
async fn request_bearer(
    request: &mut WebSocketRequest,
    device: &BoxedEd25519Signer,
    connection_id: &str,
) -> Result<String> {
    //let endpoint = changes_endpoint_url(remote)?;
    let sign_url = request.uri.path();

    let device_signature =
        encode_device_signature(device.sign(sign_url.as_bytes()).await?)
            .await?;
    let auth = bearer_prefix(&device_signature);
    request
        .uri
        .query_pairs_mut()
        .append_pair("connection_id", connection_id);

    Ok(auth)
}

/// Type of stream created for websocket connections.
pub type WsStream = WebSocketStream<MaybeTlsStream<TcpStream>>;

/// Create the websocket connection and listen for events.
pub async fn connect(
    account_id: AccountId,
    origin: Origin,
    device: BoxedEd25519Signer,
    connection_id: String,
    network_config: NetworkConfig,
) -> Result<WsStream> {
    let mut request = WebSocketRequest::new(
        account_id,
        origin.url(),
        "api/v1/sync/changes",
    )?;

    let bearer =
        request_bearer(&mut request, &device, &connection_id).await?;
    request.set_bearer(bearer);

    tracing::debug!(uri = %request.uri, "ws_client::connect");

    let (ws_stream, _) = match request.uri.scheme() {
        "wss" => {
            if network_config.certificates.is_empty() {
                connect_async(request).await?
            } else {
                let mut root_store = RootCertStore::empty();
                root_store
                    .extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

                // Add user-defined root certificates
                for (_, pem) in network_config.certificates.into_iter() {
                    let mut reader = std::io::Cursor::new(pem);
                    if let Some(cert) =
                        rustls_pemfile::certs(&mut reader).next()
                    {
                        let cert = cert.map_err(|_| Error::RustlsPemfile)?;
                        root_store.add(cert)?;
                    };
                }

                let config = ClientConfig::builder()
                    .with_root_certificates(root_store)
                    .with_no_client_auth();

                let req = request.clone().into_client_request()?;
                let domain = domain(&req)?;
                let port = req
                    .uri()
                    .port_u16()
                    .or_else(|| match req.uri().scheme_str() {
                        Some("wss") => Some(443),
                        Some("ws") => Some(80),
                        _ => None,
                    })
                    .ok_or(Error::UnsupportedUrlScheme)?;

                let addr = if let Some(ip) =
                    network_config.resolve_addrs.get(&domain)
                {
                    format!("{ip}:{port}")
                } else {
                    format!("{domain}:{port}")
                };

                let stream = TcpStream::connect(addr).await?;
                let connector = Connector::Rustls(Arc::new(config));
                client_async_tls_with_config(
                    request,
                    stream,
                    None,
                    Some(connector),
                )
                .await?
            }
        }
        _ => connect_async(request).await?,
    };
    Ok(ws_stream)
}

// Borrowed from tokio-tungstenite so we can handle domains correctly.
fn domain(
    request: &tokio_tungstenite::tungstenite::handshake::client::Request,
) -> Result<String> {
    match request.uri().host() {
        // rustls expects IPv6 addresses without the surrounding [] brackets
        Some(d) if d.starts_with('[') && d.ends_with(']') => {
            Ok(d[1..d.len() - 1].to_string())
        }
        Some(d) => Ok(d.to_string()),
        None => Err(tungstenite::error::UrlError::NoHostName.into()),
    }
}

/// Read change messages from a websocket stream,
/// and decode to change notifications that can
/// be processed.
pub fn changes(
    stream: WsStream,
) -> Map<
    SplitStream<WsStream>,
    impl FnMut(
        std::result::Result<Message, tungstenite::Error>,
    ) -> Result<ChangeEventFuture>,
> {
    let (_, read) = stream.split();
    read.map(
        move |message| -> Result<
            Pin<Box<dyn Future<Output = Result<NetworkChangeEvent>> + Send>>,
        > {
            match message {
                Ok(message) => {
                    Ok(Box::pin(
                        async move { decode_notification(message).await },
                    ))
                }
                Err(e) => Ok(Box::pin(async move { Err(e.into()) })),
            }
        },
    )
}

async fn decode_notification(message: Message) -> Result<NetworkChangeEvent> {
    match message {
        Message::Binary(buffer) => {
            let buf: Bytes = buffer;
            let notification = NetworkChangeEvent::decode(buf).await?;
            Ok(notification)
        }
        _ => Err(Error::NotBinaryWebsocketMessageType),
    }
}

/// Handle to a websocket listener.
#[derive(Clone)]
pub struct WebSocketHandle {
    notify: watch::Sender<()>,
    cancel_retry: watch::Sender<CancelReason>,
}

impl WebSocketHandle {
    /// Close the websocket.
    pub async fn close(&self) {
        tracing::debug!(
            receivers = %self.notify.receiver_count(),
            "ws_client::close");
        if let Err(error) = self.notify.send(()) {
            tracing::error!(error = ?error);
        }

        if let Err(error) = self.cancel_retry.send(CancelReason::Closed) {
            tracing::error!(error = ?error);
        }
    }
}

/// Creates a websocket that listens for changes emitted by a remote
/// server and invokes a handler with the change notifications.
pub struct WebSocketChangeListener {
    account_id: AccountId,
    origin: Origin,
    device: BoxedEd25519Signer,
    options: ListenOptions,
    shutdown: watch::Sender<()>,
    cancel_retry: watch::Sender<CancelReason>,
}

impl WebSocketChangeListener {
    /// Create a new websocket changes listener.
    pub fn new(
        account_id: AccountId,
        origin: Origin,
        device: BoxedEd25519Signer,
        options: ListenOptions,
    ) -> Self {
        let (shutdown, _) = watch::channel(());
        let (cancel_retry, _) = watch::channel(Default::default());
        Self {
            account_id,
            origin,
            device,
            options,
            shutdown,
            cancel_retry,
        }
    }

    /// Spawn a task to listen for changes notifications and invoke
    /// the handler with the notifications.
    pub fn spawn<F>(
        self,
        handler: impl Fn(NetworkChangeEvent) -> F + Send + Sync + 'static,
    ) -> WebSocketHandle
    where
        F: Future<Output = ()> + Send + 'static,
    {
        let notify = self.shutdown.clone();
        let cancel_retry = self.cancel_retry.clone();
        tokio::task::spawn(async move {
            let _ = self.connect_loop(&handler).await;
        });
        WebSocketHandle {
            notify,
            cancel_retry,
        }
    }

    async fn listen<F>(
        &self,
        mut stream: WsStream,
        handler: &(impl Fn(NetworkChangeEvent) -> F + Send + Sync + 'static),
    ) -> Result<()>
    where
        F: Future<Output = ()> + Send + 'static,
    {
        tracing::debug!("ws_client::connected");

        let mut shutdown_rx = self.shutdown.subscribe();
        loop {
            futures::select! {
                _ = shutdown_rx.changed().fuse() => {
                    tracing::debug!("ws_client::shutting_down");
                    // Perform close handshake
                    if let Err(error) = stream.close(Some(CloseFrame {
                        code: CloseCode::Normal,
                        reason: Utf8Bytes::from_static("closed"),
                    })).await {
                        tracing::warn!(
                            error = ?error,
                            "ws_client::websocket::close_error",
                        );
                    }
                    tracing::debug!("ws_client::shutdown");
                    return Ok(());
                }
                message = stream.next().fuse() => {
                    if let Some(message) = message {
                        match message {
                            Ok(message) => {
                                let notification = decode_notification(
                                    message).await?;
                                // Call the handler
                                let future = handler(notification);
                                future.await;
                            }
                            Err(e) => {
                                tracing::error!(error = ?e);
                                break;
                            }
                        }
                    } else {
                        break;
                    }
                }
            }
        }

        tracing::debug!("ws_client::disconnected");
        Ok(())
    }

    async fn stream(&self) -> Result<WsStream> {
        connect(
            self.account_id,
            self.origin.clone(),
            self.device.clone(),
            self.options.connection_id.clone(),
            self.options.network_config.clone(),
        )
        .await
    }

    async fn connect_loop<F>(
        &self,
        handler: &(impl Fn(NetworkChangeEvent) -> F + Send + Sync + 'static),
    ) -> Result<()>
    where
        F: Future<Output = ()> + Send + 'static,
    {
        let mut cancel_retry_rx = self.cancel_retry.subscribe();

        loop {
            tokio::select! {
                _ = cancel_retry_rx.changed() => {
                    tracing::debug!("ws_client::retry_canceled");
                    return Ok(());
                }
                result = self.stream() => {
                    match result {
                        Ok(stream) => {
                            self.options.retry.reset();
                            if let Err(e) = self.listen(stream, handler).await {
                                tracing::error!(
                                    error = ?e,
                                    "ws_client::listen_error");
                            }
                        }
                        Err(e) => {
                            tracing::error!(
                                error = ?e,
                                "ws_client::connect_error");
                            let retries = self.options.retry.retries();
                            if self.options.retry.is_exhausted(retries) {
                                tracing::debug!(
                                    maximum_retries = %self.options.retry.maximum_retries,
                                    "wsclient::retry_attempts_exhausted");
                                return Ok(());
                            }
                        }
                    }
                }
            }

            let retries = self.options.retry.retries();
            let delay = self.options.retry.delay(retries)?;
            let maximum = self.options.retry.maximum();
            tracing::debug!(
              retries = %retries,
              delay = %delay,
              maximum_retries = %maximum,
              "ws_client::retry");

            tokio::select! {
                _ = tokio::time::sleep(Duration::from_millis(delay)) => {
                  self.options.retry.increment();
                }
                _ = cancel_retry_rx.changed() => {
                    tracing::debug!("ws_client::retry_canceled");
                    return Ok(());
                }
            }
        }
    }
}
