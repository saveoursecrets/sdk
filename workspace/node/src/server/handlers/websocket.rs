use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        Extension, Query, TypedHeader,
    },
    headers::{authorization::Bearer, Authorization},
    http::StatusCode,
    response::Response,
};
use futures::{SinkExt, StreamExt};

use std::sync::Arc;
use tokio::sync::{
    broadcast::{self, Sender},
    RwLock,
};

use sos_core::{
    address::AddressStr, crypto::AeadPack, decode, events::ChangeNotification,
};

use crate::{
    server::{
        authenticate::{self, QueryMessage},
        headers::Session,
        State,
    },
    session::EncryptedChannel,
};

const MAX_SOCKET_CONNECTIONS_PER_CLIENT: u8 = 6;

/// State for the websocket  connection for a single
/// authenticated client.
pub struct WebSocketConnection {
    /// Broadcast sender for change notifications.
    ///
    /// Handlers can send messages via this sender to broadcast
    /// to all the connected sockets for the client.
    pub(crate) tx: Sender<ChangeNotification>,

    /// Number of connected clients, used to know when
    /// the connection state can be disposed of.
    pub(crate) clients: u8,
}

/// Upgrade to a websocket connection.
pub async fn upgrade(
    Extension(state): Extension<Arc<RwLock<State>>>,
    TypedHeader(bearer): TypedHeader<Authorization<Bearer>>,
    TypedHeader(session_id): TypedHeader<Session>,
    Query(query): Query<QueryMessage>,
    ws: WebSocketUpgrade,
) -> std::result::Result<Response, StatusCode> {
    let mut writer = state.write().await;

    let session = writer
        .sessions
        .get_mut(session_id.id())
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
    let token = authenticate::bearer(bearer, &sign_bytes)
        .map_err(|_| StatusCode::BAD_REQUEST)?;

    // Attempt to impersonate the session identity
    if &token.address != session.identity() {
        return Err(StatusCode::BAD_REQUEST);
    }

    let address = token.address;

    // Update the server nonce
    session.set_nonce(&aead.nonce);

    // Refresh the session on activity
    session.refresh();

    let conn = if let Some(conn) = writer.sockets.get_mut(&token.address) {
        conn
    } else {
        let (tx, _) = broadcast::channel::<ChangeNotification>(32);
        writer
            .sockets
            .entry(token.address)
            .or_insert(WebSocketConnection { tx, clients: 0 })
    };

    // Update the connected client count
    if let Some(result) = conn.clients.checked_add(1) {
        if result > MAX_SOCKET_CONNECTIONS_PER_CLIENT {
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
        conn.clients = result;
    } else {
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    }

    let mut rx = conn.tx.subscribe();

    drop(writer);

    Ok(ws.on_upgrade(move |mut socket: WebSocket| async move {
        let disconnect = move |state: Arc<RwLock<State>>| async move {
            let mut writer = state.write().await;
            let clients = if let Some(conn) = writer.sockets.get_mut(&address)
            {
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
        };

        let (mut write, mut read) = socket.split();

        let read_state = Arc::clone(&state);
        tokio::task::spawn(async move {
            while let Some(msg) = read.next().await {
                if let Ok(msg) = msg {
                    match msg {
                        Message::Text(_) => {}
                        Message::Binary(_) => {}
                        Message::Ping(_) => {}
                        Message::Pong(_) => {}
                        Message::Close(_) => {
                            disconnect(read_state).await;
                            return;
                        }
                    }
                } else {
                    disconnect(read_state).await;
                    return;
                }
            }
        });

        // Read change notifications and send them over the socket
        while let Ok(event) = rx.recv().await {
            tracing::trace!("{:#?}", event);
            if let Ok(msg) = serde_json::to_string(&event) {
                if write.send(Message::Text(msg)).await.is_err() {
                    disconnect(state).await;
                    return;
                }
            } else {
                disconnect(state).await;
                return;
            }
        }
    }))
}
