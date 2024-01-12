use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        Extension, Query,
    },
    http::StatusCode,
    response::Response,
};
use futures::{
    select,
    stream::{SplitSink, SplitStream},
    FutureExt, SinkExt, StreamExt,
};

use std::sync::Arc;
use tokio::sync::{
    broadcast::{self, Receiver, Sender},
    mpsc,
};

use serde::Deserialize;
use tracing::{span, Level};
use web3_address::ethereum::Address;

use crate::server::{authenticate, Result, ServerState};

const MAX_SOCKET_CONNECTIONS_PER_CLIENT: u8 = 6;

/// Query string for websocket connections.
#[derive(Debug, Deserialize)]
pub struct WebsocketQuery {
    pub bearer: String,
    pub sign_bytes: String,
    pub connection_id: String,
}

/// Message broadcast to connected sockets.
#[derive(Clone)]
pub struct BroadcastMessage {
    /// Buffer of the message to broadcast.
    pub buffer: Vec<u8>,
    /// Connection identifier of the caller.
    pub connection_id: String,
}

/// State for the websocket  connection for a single
/// authenticated client.
pub struct WebSocketConnection {
    /// Broadcast sender for websocket message.
    ///
    /// Handlers can send messages via this sender to broadcast
    /// to all the connected sockets for the client.
    pub(crate) tx: Sender<BroadcastMessage>,

    /// Number of connected clients, used to know when
    /// the connection state can be disposed of.
    pub(crate) clients: u8,
}

/// Upgrade to a websocket connection.
pub async fn upgrade(
    Extension(state): Extension<ServerState>,
    Query(query): Query<WebsocketQuery>,
    ws: WebSocketUpgrade,
) -> std::result::Result<Response, StatusCode> {
    let span = span!(Level::DEBUG, "ws_server");
    let _enter = span.enter();

    tracing::debug!("upgrade request");

    let mut writer = state.write().await;

    // Bytes that are signed is the device public key
    let sign_bytes = hex::decode(&query.sign_bytes)
        .map_err(|_| StatusCode::BAD_REQUEST)?;

    // Parse the bearer token
    let token = authenticate::BearerToken::new(&query.bearer, &sign_bytes)
        .await
        .map_err(|_| StatusCode::BAD_REQUEST)?;

    let address = token.address;
    let connection_id = query.connection_id;

    let (close_tx, close_rx) = mpsc::channel::<Message>(32);

    let conn = if let Some(conn) = writer.sockets.get_mut(&token.address) {
        conn
    } else {
        let (tx, _) = broadcast::channel::<BroadcastMessage>(32);
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
        handle_socket(
            socket,
            state,
            rx,
            address,
            connection_id,
            close_tx,
            close_rx,
        )
    }))
}

async fn disconnect(state: ServerState, address: Address) {
    let span = span!(Level::DEBUG, "ws_server");
    let _enter = span.enter();

    let mut writer = state.write().await;

    tracing::debug!("server websocket disconnect");

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
    state: ServerState,
    outgoing: Receiver<BroadcastMessage>,
    address: Address,
    connection_id: String,
    close_tx: mpsc::Sender<Message>,
    close_rx: mpsc::Receiver<Message>,
) {
    let (writer, reader) = socket.split();
    tokio::spawn(write(
        Arc::clone(&state),
        address,
        connection_id,
        writer,
        outgoing,
        close_rx,
    ));
    tokio::spawn(read(Arc::clone(&state), address, reader, close_tx));
}

async fn read(
    state: ServerState,
    address: Address,
    mut receiver: SplitStream<WebSocket>,
    close_tx: mpsc::Sender<Message>,
) -> Result<()> {
    while let Some(msg) = receiver.next().await {
        match msg {
            Ok(msg) => match msg {
                Message::Text(_) => {}
                Message::Binary(_) => {}
                Message::Ping(_) => {}
                Message::Pong(_) => {}
                Message::Close(frame) => {
                    let _ = close_tx.send(Message::Close(frame)).await;
                    disconnect(state, address).await;
                    return Ok(());
                }
            },
            Err(e) => {
                disconnect(state, address).await;
                return Err(e.into());
            }
        }
    }
    Ok(())
}

async fn write(
    state: ServerState,
    address: Address,
    connection_id: String,
    mut sender: SplitSink<WebSocket, Message>,
    mut outgoing: Receiver<BroadcastMessage>,
    mut close_rx: mpsc::Receiver<Message>,
) -> Result<()> {
    loop {
        select! {
            event = close_rx.recv().fuse() => {
                match event {
                    Some(msg) => {
                        let _ = sender.send(msg).await;
                        return Ok(())
                    }
                    _ => {}
                }
            }
            event = outgoing.recv().fuse() => {
                match event {
                    Ok(msg) => {

                        let other_connection =
                            !msg.connection_id.is_empty()
                                && !connection_id.is_empty()
                                && &msg.connection_id != &connection_id;


                        // Only broadcast change notifications to listeners
                        // other than the caller
                        if other_connection {
                            if sender.send(Message::Binary(msg.buffer)).await.is_err() {
                                disconnect(
                                    state,
                                    address,
                                ).await;
                                return Ok(());
                            }
                        }
                    }
                    _ => {}
                }
            },
        }
    }
}
