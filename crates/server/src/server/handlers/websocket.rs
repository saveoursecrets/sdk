use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        Extension, OriginalUri, Query,
    },
    http::StatusCode,
    response::Response,
};
use axum_extra::{
    headers::{authorization::Bearer, Authorization},
    typed_header::TypedHeader,
};
use futures::{
    stream::{SplitSink, SplitStream},
    SinkExt, StreamExt,
};

use sos_protocol::sdk::signer::ecdsa::Address;
use std::{collections::HashMap, sync::Arc};
use tokio::sync::{broadcast, watch};

use super::{authenticate_endpoint, Caller, ConnectionQuery};
use crate::server::{Result, ServerBackend, ServerState};

/// State for the websocket connection for a single
/// authenticated client.
#[derive(Clone)]
pub struct WebSocketConnection {
    /// Broadcast sender for websocket message.
    ///
    /// Handlers can send messages via this sender to broadcast
    /// to all the connected sockets for the client.
    send_tx: broadcast::Sender<Vec<u8>>,

    /// Channel to close the write side task.
    close_tx: watch::Sender<Message>,
}

/// Stores the websocket connections for an account and
/// supports broadcasting to all other connections.
#[derive(Default)]
pub struct WebSocketAccount {
    connections: HashMap<String, WebSocketConnection>,
}

impl WebSocketAccount {
    /// Broadcast to all other connections.
    pub async fn broadcast(
        &self,
        caller: &Caller,
        message: Vec<u8>,
    ) -> Result<()> {
        for (conn_id, conn) in &self.connections {
            if conn_id.is_empty()
                || caller.connection_id().is_none()
                || conn_id == caller.connection_id().as_ref().unwrap()
            {
                continue;
            }
            if conn.send_tx.receiver_count() > 0 {
                let _ = conn.send_tx.send(message.clone());
            }
        }
        Ok(())
    }

    /// Number of connections for the account.
    pub fn len(&self) -> usize {
        self.connections.len()
    }

    /// Whether the account connections are empty.
    pub fn is_empty(&self) -> bool {
        self.connections.is_empty()
    }
}

/// Upgrade to a websocket connection.
pub async fn upgrade(
    Extension(state): Extension<ServerState>,
    Extension(backend): Extension<ServerBackend>,
    TypedHeader(bearer): TypedHeader<Authorization<Bearer>>,
    Query(query): Query<ConnectionQuery>,
    OriginalUri(uri): OriginalUri,
    ws: WebSocketUpgrade,
) -> std::result::Result<Response, StatusCode> {
    tracing::debug!("ws_server::upgrade_request");

    let uri = uri.path().to_string();
    let caller = authenticate_endpoint(
        bearer,
        uri.as_bytes(),
        Some(query.clone()),
        Arc::clone(&state),
        Arc::clone(&backend),
        true,
    )
    .await
    .map_err(|_| StatusCode::BAD_REQUEST)?;

    let address = caller.address().clone();
    let connection_id = query.connection_id;

    let (close_tx, _) = watch::channel(Message::Close(None));
    let (send_tx, _) = broadcast::channel(64);
    let conn = WebSocketConnection { send_tx, close_tx };

    {
        let mut writer = state.write().await;
        let account = writer
            .sockets
            .entry(address.clone())
            .or_insert(Default::default());

        if account.connections.get(&connection_id).is_some() {
            return Err(StatusCode::CONFLICT);
        }

        account
            .connections
            .insert(connection_id.clone(), conn.clone());
    }

    Ok(ws.on_upgrade(move |socket| {
        handle_socket(socket, state, address, connection_id, conn)
    }))
}

async fn disconnect(
    state: ServerState,
    address: &Address,
    connection_id: &str,
) {
    let mut writer = state.write().await;
    tracing::debug!(address = %address, "ws_server::disconnect");
    if let Some(account) = writer.sockets.get_mut(address) {
        tracing::debug!(
            address = %address,
            "ws_server::disconnect::remove_socket",
        );

        if let Some(conn) = account.connections.remove(connection_id) {
            tracing::info!(
                address = %address,
                connection_id = %connection_id,
                "ws_server::disconnect",
            );

            if let Err(error) = conn.close_tx.send(Message::Close(None)) {
                tracing::warn!(error = ?error);
            }
        }
    };
}

async fn handle_socket(
    socket: WebSocket,
    state: ServerState,
    address: Address,
    connection_id: String,
    conn: WebSocketConnection,
) {
    tracing::info!(
        address = %address,
        connection_id = %connection_id,
        "ws_server::connect",
    );

    let (writer, reader) = socket.split();
    tokio::spawn(write(
        Arc::clone(&state),
        address,
        connection_id.clone(),
        writer,
        conn.clone(),
    ));
    tokio::spawn(read(
        Arc::clone(&state),
        address,
        connection_id,
        reader,
        conn,
    ));
}

async fn read(
    state: ServerState,
    address: Address,
    connection_id: String,
    mut stream: SplitStream<WebSocket>,
    conn: WebSocketConnection,
) -> Result<()> {
    while let Some(msg) = stream.next().await {
        match msg {
            Ok(msg) => match msg {
                Message::Text(_) => {}
                Message::Binary(_) => {}
                Message::Ping(_) => {}
                Message::Pong(_) => {}
                Message::Close(frame) => {
                    if let Err(error) =
                        conn.close_tx.send(Message::Close(frame))
                    {
                        tracing::warn!(error = ?error);
                    }
                    tracing::trace!(
                        address = %address,
                        "ws_server::disconnect::close_message",
                    );
                    disconnect(state, &address, &connection_id).await;
                    return Ok(());
                }
            },
            Err(e) => {
                tracing::trace!(
                    address = %address,
                    "ws_server::disconnect::read_error",
                );
                disconnect(state, &address, &connection_id).await;
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
    mut sink: SplitSink<WebSocket, Message>,
    conn: WebSocketConnection,
) -> Result<()> {
    let mut close_rx = conn.close_tx.subscribe();
    let mut outgoing = conn.send_tx.subscribe();

    loop {
        tokio::select! {
            _ = close_rx.changed() => {
                let msg = close_rx.borrow().clone();
                let _ = sink.send(msg).await;
                break;
            }
            event = outgoing.recv() => {
                match event {
                    Ok(msg) => {
                        if sink.send(Message::Binary(msg)).await.is_err() {
                            tracing::trace!(
                                address = %address,
                                "ws_server::disconnect::send_error",
                            );
                            disconnect(
                                state,
                                &address,
                                &connection_id,
                            ).await;
                            break;
                        }
                    }
                    _ => {}
                }
            },
        }
    }

    Ok(())
}
