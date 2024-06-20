//! Listen for change notifications on a websocket connection.
use futures::{
    stream::{Map, SplitStream},
    Future, FutureExt, StreamExt,
};
use prost::bytes::Bytes;
use std::{borrow::Cow, pin::Pin};
use tokio_tungstenite::{
    connect_async,
    tungstenite::{
        self,
        protocol::{frame::coding::CloseCode, CloseFrame, Message},
    },
    MaybeTlsStream, WebSocketStream,
};

use async_recursion::async_recursion;
use tokio::{net::TcpStream, sync::watch};

use sos_sdk::signer::{ecdsa::BoxedEcdsaSigner, ed25519::BoxedEd25519Signer};

use crate::{
    net::NetworkRetry,
    protocol::{ChangeNotification, Origin, WireEncodeDecode},
    CancelReason, Error, Result, WebSocketRequest,
};

use super::{
    bearer_prefix, encode_account_signature, encode_device_signature,
};

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
}

impl ListenOptions {
    /// Create new listen options using the default retry
    /// configuration.
    pub fn new(connection_id: String) -> Result<Self> {
        Ok(Self {
            connection_id,
            retry: NetworkRetry::new(16, 1000),
        })
    }

    /// Create new listen options using a custom retry
    /// configuration.
    ///
    pub fn new_retry(
        connection_id: String,
        retry: NetworkRetry,
    ) -> Result<Self> {
        Ok(Self {
            connection_id,
            retry,
        })
    }
}

/// Get the URI for a websocket changes connection.
async fn request_bearer(
    request: &mut WebSocketRequest,
    signer: &BoxedEcdsaSigner,
    device: &BoxedEd25519Signer,
    connection_id: &str,
) -> Result<String> {
    //let endpoint = changes_endpoint_url(remote)?;
    let sign_url = request.uri.path();

    let account_signature =
        encode_account_signature(signer.sign(sign_url.as_bytes()).await?)
            .await?;
    let device_signature =
        encode_device_signature(device.sign(sign_url.as_bytes()).await?)
            .await?;
    let auth = bearer_prefix(&account_signature, Some(&device_signature));

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
    origin: Origin,
    signer: BoxedEcdsaSigner,
    device: BoxedEd25519Signer,
    connection_id: String,
) -> Result<WsStream> {
    let mut request =
        WebSocketRequest::new(origin.url(), "api/v1/sync/changes")?;

    let bearer =
        request_bearer(&mut request, &signer, &device, &connection_id)
            .await?;
    request.set_bearer(bearer);

    tracing::debug!(uri = %request.uri, "ws_client::connect");

    let (ws_stream, _) = connect_async(request).await?;
    Ok(ws_stream)
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
    ) -> Result<
        Pin<Box<dyn Future<Output = Result<ChangeNotification>> + Send>>,
    >,
> {
    let (_, read) = stream.split();
    read.map(
        move |message| -> Result<
            Pin<Box<dyn Future<Output = Result<ChangeNotification>> + Send>>,
        > {
            match message {
                Ok(message) => Ok(Box::pin(async move {
                    Ok(decode_notification(message).await?)
                })),
                Err(e) => Ok(Box::pin(async move { Err(e.into()) })),
            }
        },
    )
}

async fn decode_notification(message: Message) -> Result<ChangeNotification> {
    match message {
        Message::Binary(buffer) => {
            let buf: Bytes = buffer.into();
            let notification = ChangeNotification::decode(buf).await?;
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
    origin: Origin,
    signer: BoxedEcdsaSigner,
    device: BoxedEd25519Signer,
    options: ListenOptions,
    shutdown: watch::Sender<()>,
    cancel_retry: watch::Sender<CancelReason>,
}

impl WebSocketChangeListener {
    /// Create a new websocket changes listener.
    pub fn new(
        origin: Origin,
        signer: BoxedEcdsaSigner,
        device: BoxedEd25519Signer,
        options: ListenOptions,
    ) -> Self {
        let (shutdown, _) = watch::channel(());
        let (cancel_retry, _) = watch::channel(Default::default());
        Self {
            origin,
            signer,
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
        handler: impl Fn(ChangeNotification) -> F + Send + Sync + 'static,
    ) -> WebSocketHandle
    where
        F: Future<Output = ()> + Send + 'static,
    {
        let notify = self.shutdown.clone();
        let cancel_retry = self.cancel_retry.clone();
        tokio::task::spawn(async move {
            let _ = self.connect(&handler).await;
        });
        WebSocketHandle {
            notify,
            cancel_retry,
        }
    }

    #[async_recursion]
    async fn listen<F>(
        &self,
        mut stream: WsStream,
        handler: &(impl Fn(ChangeNotification) -> F + Send + Sync + 'static),
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
                        reason: Cow::Borrowed("closed"),
                    })).await {
                        tracing::warn!(error = ?error);
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
                    }
                }
            }
        }

        // reconnection is recursive so explicitly drop the receiver
        drop(shutdown_rx);

        tracing::debug!("ws_client::disconnected");

        self.delay_connect(handler).await
    }

    async fn stream(&self) -> Result<WsStream> {
        connect(
            self.origin.clone(),
            self.signer.clone(),
            self.device.clone(),
            self.options.connection_id.clone(),
        )
        .await
    }

    async fn connect<F>(
        &self,
        handler: &(impl Fn(ChangeNotification) -> F + Send + Sync + 'static),
    ) -> Result<()>
    where
        F: Future<Output = ()> + Send + 'static,
    {
        match self.stream().await {
            Ok(stream) => self.listen(stream, handler).await,
            Err(_) => self.delay_connect(handler).await,
        }
    }

    #[async_recursion]
    async fn delay_connect<F>(
        &self,
        handler: &(impl Fn(ChangeNotification) -> F + Send + Sync + 'static),
    ) -> Result<()>
    where
        F: Future<Output = ()> + Send + 'static,
    {
        let retries = self.options.retry.increment();
        if self.options.retry.is_exhausted(retries) {
            tracing::debug!(
                maximum_retries = %self.options.retry.maximum_retries,
                "wsclient::retry_attempts_exhausted");
            return Ok(());
        }

        tracing::debug!(retries = %retries, "ws_client::retry");

        match self
            .options
            .retry
            .wait_and_retry(
                "ws_client",
                retries,
                async move { self.connect(handler).await },
                self.cancel_retry.subscribe(),
            )
            .await
        {
            Ok(_) => Ok(()),
            Err(e) => match e {
                Error::RetryCanceled(_) => Ok(()),
                _ => Err(e),
            },
        }
    }
}
