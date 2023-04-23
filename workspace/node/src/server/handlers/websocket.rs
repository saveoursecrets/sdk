use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        Extension, Query,
    },
    http::StatusCode,
    response::Response,
};
use futures::{
    stream::{SplitSink, SplitStream},
    SinkExt, StreamExt,
};

use std::sync::Arc;
use tokio::sync::{
    broadcast::{self, Receiver, Sender},
    RwLock,
};

use sos_core::{
    crypto::{channel::EncryptedChannel, AeadPack},
    decode, encode,
};
use uuid::Uuid;
use web3_address::ethereum::Address;

use crate::server::{
    authenticate::{self, QueryMessage},
    Result, State,
};

const MAX_SOCKET_CONNECTIONS_PER_CLIENT: u8 = 6;

/// State for the websocket  connection for a single
/// authenticated client.
pub struct WebSocketConnection {
    /// Broadcast sender for websocket message.
    ///
    /// Handlers can send messages via this sender to broadcast
    /// to all the connected sockets for the client.
    pub(crate) tx: Sender<Vec<u8>>,

    /// Number of connected clients, used to know when
    /// the connection state can be disposed of.
    pub(crate) clients: u8,
}

/// Upgrade to a websocket connection.
pub async fn upgrade(
    Extension(state): Extension<Arc<RwLock<State>>>,
    Query(query): Query<QueryMessage>,
    ws: WebSocketUpgrade,
) -> std::result::Result<Response, StatusCode> {
    tracing::debug!("websocket upgrade request");

    let mut writer = state.write().await;

    let session_id = query.session;

    let session = writer
        .sessions
        .get_mut(&session_id)
        .ok_or(StatusCode::UNAUTHORIZED)?;
    session
        .valid()
        .then_some(())
        .ok_or(StatusCode::UNAUTHORIZED)?;

    let buffer = bs58::decode(&query.request)
        .into_vec()
        .map_err(|_| StatusCode::BAD_REQUEST)?;

    let aead: AeadPack =
        decode(&buffer).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // Verify the nonce is ahead of this nonce
    // otherwise we may have a possible replay attack
    session
        .verify_nonce(&aead.nonce)
        .map_err(|_| StatusCode::BAD_REQUEST)?;

    // Verify the signature for the message
    let sign_bytes = session
        .sign_bytes::<sha3::Keccak256>(&aead.nonce)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // Parse the bearer token
    let token = authenticate::BearerToken::new(&query.bearer, &sign_bytes)
        .map_err(|_| StatusCode::BAD_REQUEST)?;

    // Attempt to impersonate the session identity
    if &token.address != session.identity() {
        return Err(StatusCode::BAD_REQUEST);
    }

    let address = token.address;

    // Update the server nonce
    session.set_nonce(&aead.nonce);

    // Prevent this session from expiring because
    // we need it to last as long as the socket connection
    session.set_keep_alive(true);

    // Refresh the session on activity
    session.refresh();

    let conn = if let Some(conn) = writer.sockets.get_mut(&token.address) {
        conn
    } else {
        let (tx, _) = broadcast::channel::<Vec<u8>>(32);
        writer
            .sockets
            .entry(token.address)
            .or_insert(WebSocketConnection { tx, clients: 0 })
    };

    // Update the connected client count
    if let Some(result) = conn.clients.checked_add(1) {
        if result > MAX_SOCKET_CONNECTIONS_PER_CLIENT {
            return Err(StatusCode::TOO_MANY_REQUESTS);
        }
        conn.clients = result;
    } else {
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    }

    let rx = conn.tx.subscribe();

    drop(writer);

    Ok(ws.on_upgrade(move |socket| {
        handle_socket(socket, state, address, session_id, rx)
    }))
}

async fn disconnect(
    state: Arc<RwLock<State>>,
    address: Address,
    session_id: Uuid,
) {
    let mut writer = state.write().await;

    // Sessions for websocket connections have the keep alive
    // flag so we must remove them on disconnect
    writer.sessions.remove_session(&session_id);

    let clients = if let Some(conn) = writer.sockets.get_mut(&address) {
        conn.clients -= 1;
        Some(conn.clients)
    } else {
        None
    };

    if let Some(clients) = clients {
        if clients == 0 {
            writer.sockets.remove(&address);
        }
    }
}

async fn handle_socket(
    socket: WebSocket,
    state: Arc<RwLock<State>>,
    address: Address,
    session_id: Uuid,
    outgoing: Receiver<Vec<u8>>,
) {
    let (writer, reader) = socket.split();
    tokio::spawn(write(
        writer,
        Arc::clone(&state),
        address,
        outgoing,
        session_id,
    ));
    tokio::spawn(read(reader, Arc::clone(&state), address, session_id));
}

async fn read(
    mut receiver: SplitStream<WebSocket>,
    state: Arc<RwLock<State>>,
    address: Address,
    session_id: Uuid,
) -> Result<()> {
    while let Some(msg) = receiver.next().await {
        match msg {
            Ok(msg) => match msg {
                Message::Text(_) => {}
                Message::Binary(_) => {}
                Message::Ping(_) => {}
                Message::Pong(_) => {}
                Message::Close(_) => {
                    disconnect(state, address, session_id).await;
                    return Ok(());
                }
            },
            Err(e) => {
                disconnect(state, address, session_id).await;
                return Err(e.into());
            }
        }
    }
    Ok(())
}

async fn write(
    mut sender: SplitSink<WebSocket, Message>,
    state: Arc<RwLock<State>>,
    address: Address,
    mut outgoing: Receiver<Vec<u8>>,
    session_id: Uuid,
) -> Result<()> {
    // Receive change notifications and send them over the websocket
    while let Ok(msg) = outgoing.recv().await {
        let mut writer = state.write().await;
        let session = writer
            .sessions
            .get_mut(&session_id)
            .expect("failed to locate websocket session");

        let aead = match session.encrypt(&msg) {
            Ok(aead) => aead,
            Err(e) => {
                drop(writer);
                disconnect(state, address, session_id).await;
                return Err(e.into());
            }
        };

        drop(writer);

        match encode(&aead) {
            Ok(buffer) => {
                if sender.send(Message::Binary(buffer)).await.is_err() {
                    disconnect(state, address, session_id).await;
                    return Ok(());
                }
            }
            Err(e) => {
                tracing::error!("{}", e);
                disconnect(state, address, session_id).await;
                return Err(e.into());
            }
        }
    }
    Ok(())
}
