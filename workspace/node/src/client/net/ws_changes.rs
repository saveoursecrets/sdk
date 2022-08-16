//! Listen for change notifications on a websocket connection.
use futures::{
    stream::{Map, SplitStream},
    StreamExt,
};
use tokio_tungstenite::{
    connect_async,
    tungstenite::{
        self, client::IntoClientRequest, handshake::client::generate_key,
        protocol::Message,
    },
    MaybeTlsStream, WebSocketStream,
};

use tokio::net::TcpStream;

use url::{Origin, Url};
use uuid::Uuid;

use sos_core::{encode, events::ChangeNotification, signer::BoxedSigner};

use crate::{
    client::{net::RpcClient, Result},
    session::{ClientSession, EncryptedChannel},
};

use super::encode_signature;

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

/// Get the URI for a websocket connection.
pub fn websocket_uri(
    endpoint: Url,
    request: Vec<u8>,
    bearer: String,
    session: Uuid,
) -> String {
    format!(
        "{}?request={}&bearer={}&session={}",
        endpoint,
        bs58::encode(&request).into_string(),
        bearer,
        session,
    )
}

/// Create the websocket connection and listen for events.
pub async fn connect(
    remote: Url,
    signer: BoxedSigner,
) -> Result<(WsStream, ClientSession)> {
    let origin = remote.origin();

    let mut endpoint = remote.join("api/changes")?;
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
    let bearer = encode_signature(client.signer().sign(&sign_bytes).await?)?;

    let message = encode(&aead)?;

    let host = endpoint.host_str().unwrap().to_string();
    let uri = websocket_uri(endpoint, message, bearer, *session.id());

    println!("uri {}", uri);
    println!("origin {:#?}", origin);

    let request = WebSocketRequest { host, uri, origin };

    let (ws_stream, _) = connect_async(request).await?;
    Ok((ws_stream, session))
}

/// Read change notifications from a websocket stream.
pub fn changes(
    stream: WsStream,
    _session: ClientSession,
) -> Map<
    SplitStream<WsStream>,
    impl FnMut(
        std::result::Result<Message, tungstenite::Error>,
    ) -> Result<ChangeNotification>,
> {
    let (_, read) = stream.split();
    read.map(|message| -> Result<ChangeNotification> {
        let message = message?;
        match message {
            Message::Text(value) => {
                let notification: ChangeNotification =
                    serde_json::from_str(&value)?;
                Ok(notification)
            }
            _ => unreachable!("bad websocket message type"),
        }
    })
}
