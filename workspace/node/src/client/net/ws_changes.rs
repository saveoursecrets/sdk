//! Listen for change notifications from a websocket connection.

//use tokio::io::{AsyncReadExt, AsyncWriteExt};
use futures::StreamExt;
use tokio_tungstenite::{
    connect_async,
    tungstenite::{
        self, client::IntoClientRequest, handshake::client::generate_key,
        protocol::Message,
    },
};

use url::{Origin, Url};
use uuid::Uuid;

use sos_core::{constants::X_SESSION, encode, signer::BoxedSigner};

use crate::{
    client::{net::RpcClient, Result},
    session::EncryptedChannel,
};

use super::{bearer_prefix, encode_signature, AUTHORIZATION};

struct WebSocketRequest {
    origin: Origin,
    endpoint: Url,
    session_id: Uuid,
    message: Vec<u8>,
    bearer: String,
}

impl IntoClientRequest for WebSocketRequest {
    fn into_client_request(
        self,
    ) -> std::result::Result<http::Request<()>, tungstenite::Error> {
        let host = self.endpoint.host_str().unwrap();
        let uri = format!(
            "{}?request={}",
            self.endpoint,
            bs58::encode(&self.message).into_string()
        );
        let origin = self.origin.unicode_serialization();
        let request = http::Request::builder()
            .uri(uri)
            .header(X_SESSION, self.session_id.to_string())
            .header(AUTHORIZATION, self.bearer)
            .header("sec-websocket-key", generate_key())
            .header("sec-websocket-version", "13")
            .header("host", host)
            .header("origin", origin)
            .header("connection", "keep-alive, Upgrade")
            .header("upgrade", "websocket")
            .body(())?;
        Ok(request)
    }
}

/// Create the websocket connection and listen for events.
pub async fn connect(remote: Url, signer: BoxedSigner) -> Result<()> {
    let origin = remote.origin();

    let mut endpoint = remote.join("api/changes2")?;
    let scheme = if endpoint.scheme() == "http" {
        "ws"
    } else if endpoint.scheme() == "https" {
        "wss"
    } else {
        panic!("bad url scheme for websocket connection");
    };
    endpoint
        .set_scheme(scheme)
        .expect("failed to set websocket scheme");

    let client = RpcClient::new(remote, signer);
    let mut session = client.new_session().await?;

    // Need to encode a message into the query string
    // so the server can validate the session request
    let aead = session.encrypt(&[])?;

    let sign_bytes = session.sign_bytes::<sha3::Keccak256>(&aead.nonce)?;
    let signature =
        encode_signature(client.signer().sign(&sign_bytes).await?)?;
    let bearer = bearer_prefix(&signature);

    let message = encode(&aead)?;

    let request = WebSocketRequest {
        endpoint,
        session_id: *session.id(),
        message,
        bearer,
        origin,
    };

    let (ws_stream, _) =
        connect_async(request).await.expect("Failed to connect");

    let (_, mut read) = ws_stream.split();

    while let Some(message) = read.next().await {
        let message = message?;
        match message {
            Message::Text(value) => {
                println!("Got message {:#?}", value);
            }
            _ => {}
        }
    }

    Ok(())
}
