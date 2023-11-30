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

use mpc_protocol::channel::encrypt_server_channel;
use sos_sdk::encode;
use tracing::{span, Level};
use web3_address::ethereum::Address;

use crate::{
    rpc::ServerEnvelope,
    server::{
        authenticate::{self, QueryMessage},
        Result, ServerState,
    },
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
    Extension(state): Extension<ServerState>,
    Query(query): Query<QueryMessage>,
    ws: WebSocketUpgrade,
) -> std::result::Result<Response, StatusCode> {
    let span = span!(Level::DEBUG, "ws_server");
    let _enter = span.enter();

    tracing::debug!("upgrade request");

    let mut writer = state.write().await;
    let server_public_key = writer.keypair.public_key().to_vec();
    let client_public_key = hex::decode(&query.public_key)
        .map_err(|_| StatusCode::BAD_REQUEST)?;

    let transport = writer
        .transports
        .get_mut(&client_public_key)
        .ok_or(StatusCode::UNAUTHORIZED)?;
    transport
        .valid()
        .then_some(())
        .ok_or(StatusCode::UNAUTHORIZED)?;

    // Parse the bearer token
    let token =
        authenticate::BearerToken::new(&query.bearer, &client_public_key)
            .await
            .map_err(|_| StatusCode::BAD_REQUEST)?;

    let address = token.address;

    // Prevent this session from expiring because
    // we need it to last as long as the socket connection
    transport.set_keep_alive(true);

    // Refresh the transport on activity
    transport.refresh();

    let (close_tx, close_rx) = mpsc::channel::<Message>(32);

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
        handle_socket(
            socket,
            state,
            rx,
            address,
            server_public_key,
            client_public_key,
            close_tx,
            close_rx,
        )
    }))
}

async fn disconnect(
    state: ServerState,
    address: Address,
    public_key: Vec<u8>,
) {
    let span = span!(Level::DEBUG, "ws_server");
    let _enter = span.enter();

    let mut writer = state.write().await;

    tracing::debug!("server websocket disconnect");

    // Sessions for websocket connections have the keep alive
    // flag so we must remove them on disconnect
    writer.transports.remove_channel(&public_key);

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
    outgoing: Receiver<Vec<u8>>,
    address: Address,
    server_public_key: Vec<u8>,
    client_public_key: Vec<u8>,
    close_tx: mpsc::Sender<Message>,
    close_rx: mpsc::Receiver<Message>,
) {
    let (writer, reader) = socket.split();
    tokio::spawn(write(
        Arc::clone(&state),
        address,
        server_public_key,
        client_public_key.clone(),
        writer,
        outgoing,
        close_rx,
    ));
    tokio::spawn(read(
        Arc::clone(&state),
        address,
        client_public_key,
        reader,
        close_tx,
    ));
}

async fn read(
    state: ServerState,
    address: Address,
    public_key: Vec<u8>,
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
                    return Ok(());
                }
            },
            Err(e) => {
                disconnect(state, address, public_key).await;
                return Err(e.into());
            }
        }
    }
    Ok(())
}

async fn write(
    state: ServerState,
    address: Address,
    server_public_key: Vec<u8>,
    client_public_key: Vec<u8>,
    mut sender: SplitSink<WebSocket, Message>,
    mut outgoing: Receiver<Vec<u8>>,
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
                        let mut writer = state.write().await;
                        let transport = writer
                            .transports
                            .get_mut(&client_public_key)
                            .expect("failed to locate websocket session");

                        let envelope =
                            encrypt_server_channel(
                                transport.protocol_mut(),
                                &msg,
                                false,
                            ).await?;

                        let message = ServerEnvelope {
                            public_key: server_public_key.clone(),
                            envelope,
                        };

                        drop(writer);

                        match encode(&message).await {
                            Ok(buffer) => {
                                if sender.send(Message::Binary(buffer)).await.is_err() {
                                    disconnect(
                                        state,
                                        address,
                                        client_public_key,
                                    ).await;
                                    return Ok(());
                                }
                            }
                            Err(e) => {
                                tracing::error!("{}", e);
                                disconnect(
                                    state,
                                    address,
                                    client_public_key,
                                ).await;
                                return Err(e.into());
                            }
                        }
                    }
                    _ => {}
                }
            },
        }
    }
}
