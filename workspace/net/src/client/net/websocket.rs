//! Listen for change notifications on a websocket connection.
use futures::{
    select,
    stream::{Map, SplitStream},
    Future, FutureExt, StreamExt,
};
use std::{
    borrow::Cow,
    pin::Pin,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio_tungstenite::{
    connect_async,
    tungstenite::{
        self,
        client::IntoClientRequest,
        handshake::client::generate_key,
        protocol::{frame::coding::CloseCode, CloseFrame, Message},
    },
    MaybeTlsStream, WebSocketStream,
};

use async_recursion::async_recursion;
use tokio::{
    net::TcpStream,
    sync::{Mutex, Notify},
    time::sleep,
};
use url::Url;

use sos_sdk::{
    signer::{ecdsa::BoxedEcdsaSigner, ed25519::BoxedEd25519Signer},
    sync::Origin,
};

use crate::{
    client::{Error, Result},
    ChangeNotification,
};

use super::encode_account_signature;

/// Options used when listening for change notifications.
#[derive(Clone)]
pub struct ListenOptions {
    /// Identifier for this connection.
    ///
    /// Should match the identifier used by the RPC
    /// client so the server can ignore sending change notifications
    /// to the caller.
    pub(crate) connection_id: String,

    /// Base reconnection interval for exponential backoff reconnect
    /// attempts.
    pub(crate) reconnect_interval: u64,

    /// Maximum number of retry attempts.
    pub(crate) maximum_retries: u64,
}

impl ListenOptions {
    /// Create new listen options using the default reconnect
    /// configuration.
    pub fn new(connection_id: String) -> Result<Self> {
        Ok(Self {
            connection_id,
            reconnect_interval: 1000,
            maximum_retries: 16,
        })
    }

    /// Create new listen options using a custom reconnect
    /// configuration.
    ///
    /// The reconnect interval is a *base interval* in milliseconds
    /// for the exponential backoff so use a small value such as
    /// `1000` or `2000`.
    pub fn new_config(
        connection_id: String,
        reconnect_interval: u64,
        maximum_retries: u64,
    ) -> Result<Self> {
        Ok(Self {
            connection_id,
            reconnect_interval,
            maximum_retries,
        })
    }
}

/// Get the URI for a websocket connection.
fn websocket_uri(
    endpoint: Url,
    bearer: String,
    sign_bytes: &[u8],
    connection_id: &str,
) -> String {
    format!(
        "{}?bearer={}&sign_bytes={}&connection_id={}",
        endpoint,
        urlencoding::encode(&bearer),
        urlencoding::encode(&hex::encode(sign_bytes)),
        urlencoding::encode(connection_id),
    )
}

/// Gets the endpoint URL for a websocket connection.
///
/// The `remote` must be an HTTP/S URL; it's scheme will
/// be switched to `ws` or `wss` as appropiate and the path
/// for the changes endpoint will be added.
///
/// Panics if the remote scheme is invalid or it failed to
/// set the scheme on the endpoint.
fn changes_endpoint_url(remote: &Url) -> Result<Url> {
    let mut endpoint = remote.join("api/v1/sync/changes")?;
    let scheme = if endpoint.scheme() == "http" {
        "ws"
    } else if endpoint.scheme() == "https" {
        "wss"
    } else {
        panic!("bad url scheme for websocket connection, requires http(s)");
    };
    endpoint
        .set_scheme(scheme)
        .expect("failed to set websocket scheme");
    Ok(endpoint)
}

/// Get the URI for a websocket changes connection.
async fn changes_uri(
    remote: &Url,
    signer: &BoxedEcdsaSigner,
    sign_bytes: &[u8],
    connection_id: &str,
) -> Result<String> {
    let endpoint = changes_endpoint_url(remote)?;
    let bearer =
        encode_account_signature(signer.sign(&sign_bytes).await?).await?;
    let uri = websocket_uri(endpoint, bearer, sign_bytes, connection_id);
    Ok(uri)
}

/// Type of stream created for websocket connections.
pub type WsStream = WebSocketStream<MaybeTlsStream<TcpStream>>;

struct WebSocketRequest {
    uri: String,
    host: String,
    origin: url::Origin,
}

impl IntoClientRequest for WebSocketRequest {
    fn into_client_request(
        self,
    ) -> std::result::Result<http::Request<()>, tungstenite::Error> {
        let origin = self.origin.unicode_serialization();
        let request = http::Request::builder()
            .uri(self.uri)
            .header("sec-websocket-key", generate_key())
            .header("sec-websocket-version", "13")
            .header("host", self.host)
            .header("origin", origin)
            .header("connection", "keep-alive, Upgrade")
            .header("upgrade", "websocket")
            .body(())?;
        Ok(request)
    }
}

/// Create the websocket connection and listen for events.
pub async fn connect(
    origin: Origin,
    signer: BoxedEcdsaSigner,
    device: BoxedEd25519Signer,
    connection_id: String,
) -> Result<WsStream> {
    let url_origin = origin.url().origin();
    let endpoint = origin.url().clone();

    let sign_bytes = device.verifying_key().to_bytes();
    let host = endpoint.host_str().unwrap().to_string();
    let uri =
        changes_uri(&endpoint, &signer, &sign_bytes, &connection_id).await?;

    tracing::debug!(uri = %uri);

    let request = WebSocketRequest {
        host,
        uri,
        origin: url_origin,
    };
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
            let notification: ChangeNotification =
                serde_json::from_slice(&buffer)?;
            Ok(notification)
        }
        _ => Err(Error::NotBinaryWebsocketMessageType),
    }
}

/// Handle to a websocket listener.
#[derive(Clone)]
pub struct WebSocketHandle {
    notify: Arc<Notify>,
}

impl WebSocketHandle {
    /// Close the websocket.
    pub fn close(&self) {
        self.notify.notify_one();
    }
}

/// Creates a websocket that listens for changes emitted by a remote
/// server and invokes a handler with the change notifications.
pub struct WebSocketChangeListener {
    origin: Origin,
    signer: BoxedEcdsaSigner,
    device: BoxedEd25519Signer,
    options: ListenOptions,
    retries: Arc<Mutex<AtomicU64>>,
    notify: Arc<Notify>,
}

impl WebSocketChangeListener {
    /// Create a new websocket changes listener.
    pub fn new(
        origin: Origin,
        signer: BoxedEcdsaSigner,
        device: BoxedEd25519Signer,
        options: ListenOptions,
    ) -> Self {
        let notify = Arc::new(Notify::new());
        Self {
            origin,
            signer,
            device,
            options,
            retries: Arc::new(Mutex::new(AtomicU64::from(1))),
            notify,
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
        let notify = Arc::clone(&self.notify);
        tokio::task::spawn(async move {
            let _ = self.connect(&handler).await;
        });
        WebSocketHandle { notify }
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
        tracing::debug!("connected");

        let shutdown = Arc::clone(&self.notify);
        loop {
            select! {
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
                _ = shutdown.notified().fuse() => {
                    // Perform close handshake
                    let _ = stream.close(Some(CloseFrame {
                        code: CloseCode::Normal,
                        reason: Cow::Borrowed("closed"),
                    })).await;
                    return Ok(());
                }
            }
        }

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
        let retries = {
            let retries = self.retries.lock().await;
            retries.fetch_add(1, Ordering::SeqCst)
        };

        if retries > self.options.maximum_retries {
            tracing::debug!(
                maximum_retries = %self.options.maximum_retries,
                "retry attempts exhausted");
            return Ok(());
        }

        tracing::debug!(attempt = %retries, "retry");

        if let Some(factor) = 2u64.checked_pow(retries as u32) {
            let delay = self.options.reconnect_interval * factor;
            tracing::debug!(delay = %delay);
            sleep(Duration::from_millis(delay)).await;
            self.connect(handler).await?;
            Ok(())
        } else {
            panic!("websocket connect retry attempts overflowed");
        }
    }
}
