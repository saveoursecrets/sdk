//! Listen for change notifications on a websocket connection.
use futures::{
    stream::{Map, SplitStream},
    Future, StreamExt,
};
use std::{pin::Pin, sync::Arc};
use tokio_tungstenite::{
    connect_async,
    tungstenite::{
        self, client::IntoClientRequest, handshake::client::generate_key,
        protocol::Message,
    },
    MaybeTlsStream, WebSocketStream,
};

use tokio::{net::TcpStream, sync::Mutex};

use url::{Origin, Url};

use sos_sdk::{
    crypto::{
        channel::{ClientSession, EncryptedChannel},
        AeadPack,
    },
    decode,
    events::ChangeNotification,
    signer::ecdsa::BoxedEcdsaSigner,
};

use crate::client::{net::RpcClient, Result};

use super::changes_uri;

/// Type of stream created for websocket connections.
pub type WsStream = WebSocketStream<MaybeTlsStream<TcpStream>>;

struct WebSocketRequest {
    uri: String,
    host: String,
    origin: Origin,
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
    remote: Url,
    signer: BoxedEcdsaSigner,
) -> Result<(WsStream, ClientSession)> {
    let origin = remote.origin();

    let endpoint = remote.clone();

    //let endpoint = changes_endpoint_url(&remote)?;

    let client = RpcClient::new(remote, signer);
    let mut session = client.new_session().await?;

    /*
    // Need to encode a message into the query string
    // so the server can validate the session request
    let aead = session.encrypt(&[])?;

    let sign_bytes = session.sign_bytes::<sha3::Keccak256>(&aead.nonce)?;
    let bearer = encode_signature(client.signer().sign(&sign_bytes).await?).await?;

    let message = encode(&aead)?;

    let host = endpoint.host_str().unwrap().to_string();
    let uri = websocket_uri(endpoint, message, bearer, *session.id());
    */

    let host = endpoint.host_str().unwrap().to_string();
    let uri = changes_uri(&endpoint, client.signer(), &mut session).await?;

    tracing::debug!(uri = %uri);
    tracing::debug!(origin = ?origin);

    let request = WebSocketRequest { host, uri, origin };

    let (ws_stream, _) = connect_async(request).await?;
    Ok((ws_stream, session))
}

/// Read change notifications from a websocket stream.
pub fn changes(
    stream: WsStream,
    session: Arc<Mutex<ClientSession>>,
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
            let message_session = Arc::clone(&session);
            Ok(Box::pin(async move {
                let mut session = message_session.lock().await;
                match message {
                    Message::Binary(buffer) => {
                        let aead: AeadPack = decode(&buffer).await?;
                        session.set_nonce(&aead.nonce);
                        let message = session.decrypt(&aead)?;
                        let notification: ChangeNotification =
                            serde_json::from_slice(&message)?;
                        Ok(notification)
                    }
                    _ => unreachable!("bad websocket message type"),
                }
            }))
        },
    )
}
