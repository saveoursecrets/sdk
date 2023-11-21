//! Listen for change notifications on a websocket connection.
use futures::{
    stream::{Map, SplitStream},
    Future, StreamExt,
};
use std::{pin::Pin, sync::Arc, time::Duration};
use tokio_tungstenite::{
    connect_async,
    tungstenite::{
        self, client::IntoClientRequest, handshake::client::generate_key,
        protocol::Message,
    },
    MaybeTlsStream, WebSocketStream,
};

use async_recursion::async_recursion;
use tokio::{net::TcpStream, time::sleep};
use url::Url;

use sos_sdk::{
    events::ChangeNotification,
    mpc::{generate_keypair, Keypair},
    signer::ecdsa::BoxedEcdsaSigner,
};

use crate::client::{Origin, Result, RpcClient};

use super::encode_signature;

/// Options used when listening for change notifications.
pub struct ListenOptions {
    pub(crate) connection_id: String,
    pub(crate) keypair: Keypair,
    pub(crate) reconnect_interval: u64,
}

impl ListenOptions {
    /// Create new listen options.
    pub fn new(connection_id: String) -> Result<Self> {
        Ok(Self {
            connection_id,
            reconnect_interval: 15000,
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
    tracing::debug!(origin = ?url_origin);

    let request = WebSocketRequest {
        host,
        uri,
        origin: url_origin,
    };
    let (ws_stream, _) = connect_async(request).await?;
    Ok((ws_stream, Arc::new(client)))
}

/// Read change notifications from a websocket stream.
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
            let message = message?;
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
        },
    )
}

/// Creates a websocket that listens for changes emitted by a remote
/// server and invokes a handler with the change notifications.
#[derive(Clone)]
pub struct WebSocketChangeListener {
    origin: Origin,
    signer: BoxedEcdsaSigner,
    keypair: Keypair,
    reconnect_interval: u64,
}

impl WebSocketChangeListener {
    /// Create a new changes listener.
    pub fn new(
        origin: Origin,
        signer: BoxedEcdsaSigner,
        keypair: Keypair,
        reconnect_interval: u64,
    ) -> Self {
        assert!(
            reconnect_interval >= 15000,
            "reconnect interval must not be less than 15 seconds"
        );

        Self {
            origin,
            signer,
            keypair,
            reconnect_interval,
        }
    }

    /// Spawn a thread to listen for changes and apply incoming
    /// changes to the local cache.
    pub fn spawn<F>(
        self,
        handler: impl Fn(ChangeNotification) -> F + Send + Sync + 'static,
    ) -> tokio::task::JoinHandle<()>
    where
        F: Future<Output = ()> + Send + 'static,
    {
        tokio::task::spawn(async move {
            let _ = self.connect(&handler).await;
        })
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
        while let Some(notification) = stream.next().await {
            let notification = notification?.await?;
            let future = handler(notification);
            future.await;
        }
        Ok(())
    }

    async fn stream(&self) -> Result<(WsStream, Arc<RpcClient>)> {
        connect(
            self.origin.clone(),
            self.signer.clone(),
            self.keypair.clone(),
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
        loop {
            sleep(Duration::from_millis(self.reconnect_interval)).await;
            self.connect(handler).await?;
        }
    }
}
