//! Listen for change notifications on a websocket connection.
use futures::{
    stream::{Map, SplitStream},
    Future, StreamExt,
};
use std::{pin::Pin, sync::Arc, thread, time::Duration};
use tokio_tungstenite::{
    connect_async,
    tungstenite::{
        self, client::IntoClientRequest, handshake::client::generate_key,
        protocol::Message,
    },
    MaybeTlsStream, WebSocketStream,
};

use async_recursion::async_recursion;
use tokio::{net::TcpStream, sync::RwLock, time::sleep};

use url::Url;

use sos_sdk::{
    events::ChangeNotification, mpc::Keypair, signer::ecdsa::BoxedEcdsaSigner,
};

use crate::client::{net::RpcClient, Error, Origin, Result};

use super::changes_uri;

/// Interval for websocket re-connect attempts.
const INTERVAL_MS: u64 = 15000;

/*
/// Spawn a change notification listener that
/// updates the local node cache.
#[cfg(not(target_arch = "wasm32"))]
pub fn spawn_changes_listener(
    origin: Origin,
    signer: BoxedEcdsaSigner,
    keypair: Keypair,
    cache: Arc<RwLock<LocalProvider>>,
) {
    let listener =
        ChangesListener::new(origin, signer, keypair);
    listener.spawn(move |notification| {
        let cache = Arc::clone(&cache);
        async move {
            println!("{:#?}", notification);
            let mut writer = cache.write().await;
            todo!("restore handling change event notifications");
            //let _ = writer.handle_change(notification).await;
        }
    });
}
*/

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

                        //let message: ServerEnvelope = decode(buffer).await?;

                        /*
                        let (encoding, buffer) =
                            decrypt_server_channel(
                                protocol, message.envelope).await?;
                        */

                        /*
                        let aead: AeadPack = decode(&buffer).await?;
                        session.set_nonce(&aead.nonce);
                        let message = session.decrypt(&aead).await?;
                        let notification: ChangeNotification =
                            serde_json::from_slice(&message)?;
                        Ok(notification)
                        */
                    }
                    _ => unreachable!("bad websocket message type"),
                }
            }))
        },
    )
}

/// Listen for changes and call a handler with the change notification.
#[derive(Clone)]
pub struct ChangesListener {
    origin: Origin,
    signer: BoxedEcdsaSigner,
    keypair: Keypair,
}

impl ChangesListener {
    /// Create a new changes listener.
    pub fn new(
        origin: Origin,
        signer: BoxedEcdsaSigner,
        keypair: Keypair,
    ) -> Self {
        Self {
            origin,
            signer,
            keypair,
        }
    }

    /// Spawn a thread to listen for changes and apply incoming
    /// changes to the local cache.
    pub fn spawn<F>(
        self,
        handler: impl Fn(ChangeNotification) -> F + Send + Sync + 'static,
    ) -> thread::JoinHandle<()>
    where
        F: Future<Output = ()> + 'static,
    {
        thread::spawn(move || {
            let runtime = tokio::runtime::Runtime::new().unwrap();
            let _ = runtime.block_on(async move {
                let _ = self.connect(&handler).await;
                Ok::<(), Error>(())
            });
        })
    }

    #[async_recursion(?Send)]
    async fn listen<F>(
        &self,
        stream: WsStream,
        client: Arc<RpcClient>,
        handler: &(impl Fn(ChangeNotification) -> F + Send + Sync + 'static),
    ) -> Result<()>
    where
        F: Future<Output = ()> + 'static,
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
        F: Future<Output = ()> + 'static,
    {
        match self.stream().await {
            Ok((stream, client)) => {
                self.listen(stream, client, handler).await
            }
            Err(_) => self.delay_connect(handler).await,
        }
    }

    #[async_recursion(?Send)]
    async fn delay_connect<F>(
        &self,
        handler: &(impl Fn(ChangeNotification) -> F + Send + Sync + 'static),
    ) -> Result<()>
    where
        F: Future<Output = ()> + 'static,
    {
        loop {
            sleep(Duration::from_millis(INTERVAL_MS)).await;
            self.connect(handler).await?;
        }
    }
}
