//! Listen for change notifications on a websocket connection.
use futures::{
    select,
    stream::{Map, SplitStream},
    Future, FutureExt, StreamExt,
};
use std::{
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
        self, client::IntoClientRequest, handshake::client::generate_key,
        protocol::Message,
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
    events::ChangeNotification,
    mpc::{generate_keypair, Keypair},
    signer::ecdsa::BoxedEcdsaSigner,
};

use crate::client::{Origin, Result, RpcClient};

use super::encode_signature;

/// Options used when listening for change notifications.
#[derive(Clone)]
pub struct ListenOptions {
    /// Identifier for this connection.
    ///
    /// Should match the identifier used by the RPC
    /// client so the server can ignore sending change notifications
    /// to the caller.
    pub(crate) connection_id: String,
    /// Noise protocol keypair.
    ///
    /// Must NOT be the same as the RPC client keypair.
    pub(crate) keypair: Keypair,

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
            keypair: generate_keypair()?,
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
            keypair: generate_keypair()?,
        })
    }
}

/// Get the URI for a websocket connection.
fn websocket_uri(endpoint: Url, bearer: String, public_key: &[u8]) -> String {
    format!(
        "{}?bearer={}&public_key={}",
        endpoint,
        //bs58::encode(&request).into_string(),
        bearer,
        hex::encode(public_key),
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
    let mut endpoint = remote.join("api/changes")?;
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
    public_key: &[u8],
) -> Result<String> {
    let endpoint = changes_endpoint_url(remote)?;
    let bearer = encode_signature(signer.sign(&public_key).await?).await?;
    let uri = websocket_uri(endpoint, bearer, public_key);
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
    keypair: Keypair,
) -> Result<(WsStream, Arc<RpcClient>)> {
    let url_origin = origin.url.origin();
    let endpoint = origin.url.clone();
    let public_key = keypair.public_key().to_vec();

    let client = RpcClient::new(origin, signer, keypair)?;
    client.handshake().await?;

    let host = endpoint.host_str().unwrap().to_string();
    let uri = changes_uri(&endpoint, client.signer(), &public_key).await?;

    tracing::debug!(uri = %uri);

    let request = WebSocketRequest {
        host,
        uri,
        origin: url_origin,
    };
    let (ws_stream, _) = connect_async(request).await?;
    Ok((ws_stream, Arc::new(client)))
}

/// Read change messages from a websocket stream,
/// decrypt them from the noise protocol and decode
/// to change notifications that can be processed.
pub fn changes(
    stream: WsStream,
    client: Arc<RpcClient>,
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
                Ok(message) => {
                    let rpc = Arc::clone(&client);
                    Ok(Box::pin(async move {
                        match message {
                            Message::Binary(buffer) => {
                                let buffer =
                                    rpc.decrypt_server_envelope(&buffer).await?;
                                let notification: ChangeNotification =
                                    serde_json::from_slice(&buffer)?;
                                Ok(notification)
                            }
                            _ => panic!(
                                "bad websocket message type, expected binary data"
                            ),
                        }
                    }))
                }
                Err(e) => {
                    Ok(Box::pin(async move { Err(e.into()) }))
                }
            }
        },
    )
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
    options: ListenOptions,
    retries: Arc<Mutex<AtomicU64>>,
    notify: Arc<Notify>,
    closed: Arc<Mutex<bool>>,
}

impl WebSocketChangeListener {
    /// Create a new websocket changes listener.
    pub fn new(
        origin: Origin,
        signer: BoxedEcdsaSigner,
        options: ListenOptions,
    ) -> Self {
        let notify = Arc::new(Notify::new());
        Self {
            origin,
            signer,
            options,
            retries: Arc::new(Mutex::new(AtomicU64::from(1))),
            notify,
            closed: Arc::new(Mutex::new(false)),
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
        stream: WsStream,
        client: Arc<RpcClient>,
        handler: &(impl Fn(ChangeNotification) -> F + Send + Sync + 'static),
    ) -> Result<()>
    where
        F: Future<Output = ()> + Send + 'static,
    {
        let mut stream = changes(stream, client);

        tracing::debug!("connected");

        let shutdown = Arc::clone(&self.notify);
        loop {
            select! {
                event = stream.next().fuse() => {
                    if let Some(notification) = event {
                        match notification?.await {
                            Ok(notification) => {
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
                    tracing::debug!("closing websocket");
                    let mut closed = self.closed.lock().await;
                    *closed = true;
                    break;
                }
            }
        }

        // Try to re-connect if not explicitly closed
        let closed = self.closed.lock().await;
        if !*closed {
            self.delay_connect(handler).await
        } else {
            Ok(())
        }
    }

    async fn stream(&self) -> Result<(WsStream, Arc<RpcClient>)> {
        connect(
            self.origin.clone(),
            self.signer.clone(),
            self.options.keypair.clone(),
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
            Ok((stream, client)) => {
                self.listen(stream, client, handler).await
            }
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
