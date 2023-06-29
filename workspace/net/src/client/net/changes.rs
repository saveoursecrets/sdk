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
    decode, events::ChangeNotification, mpc::Keypair,
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
    remote_public_key: Vec<u8>,
    signer: BoxedEcdsaSigner,
    keypair: Keypair,
) -> Result<WsStream> {
    let origin = remote.origin();
    let endpoint = remote.clone();
    let public_key = keypair.public_key().to_vec();
    let mut client =
        RpcClient::new(remote, remote_public_key, signer, keypair)?;
    client.handshake().await?;

    let host = endpoint.host_str().unwrap().to_string();
    let uri = changes_uri(&endpoint, client.signer(), &public_key).await?;

    tracing::debug!(uri = %uri);
    tracing::debug!(origin = ?origin);

    let request = WebSocketRequest { host, uri, origin };
    let (ws_stream, _) = connect_async(request).await?;
    Ok(ws_stream)
}

/// Read change notifications from a websocket stream.
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
            let message = message?;
            Ok(Box::pin(async move {
                match message {
                    Message::Binary(buffer) => {
                        todo!("decrypt change notification packet");

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
