//! Relay forwards packets between peers over a websocket connection.
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
    select,
    stream::{SplitSink, SplitStream},
    FutureExt, SinkExt, StreamExt,
};

use serde::Deserialize;
use sos_sdk::{decode, signer::ecdsa::Address};
use std::{collections::HashMap, sync::Arc};
use tokio::sync::{
    broadcast::{self, Receiver, Sender},
    mpsc, RwLock,
};
use tracing::{span, Level};

use super::{authenticate_endpoint, ConnectionQuery};
use crate::{relay::RelayHeader, server::Result};

/// Query string for the relay service.
#[derive(Deserialize)]
pub struct RelayQuery {
    /// Connection public key.
    #[serde(with = "hex::serde")]
    pub public_key: Vec<u8>,
}

/// Connected clients.
pub type RelayConnections = HashMap<Vec<u8>, mpsc::Sender<Vec<u8>>>;

/// State for the relay service.
pub type RelayState = Arc<RwLock<RelayConnections>>;

/// Upgrade to a websocket connection.
pub async fn upgrade(
    Extension(state): Extension<RelayState>,
    Query(query): Query<RelayQuery>,
    ws: WebSocketUpgrade,
) -> std::result::Result<Response, StatusCode> {
    let span = span!(Level::DEBUG, "ws_relay");
    let _enter = span.enter();

    tracing::debug!("upgrade request");

    let (close_tx, close_rx) = mpsc::channel::<Message>(8);
    let (relay_tx, relay_rx) = mpsc::channel::<Vec<u8>>(64);

    {
        let mut writer = state.write().await;
        writer.insert(query.public_key.clone(), relay_tx.clone());
    }

    Ok(ws.on_upgrade(move |socket| {
        handle_socket(
            socket,
            state,
            query.public_key,
            relay_tx,
            relay_rx,
            close_tx,
            close_rx,
        )
    }))
}

async fn disconnect(state: RelayState, public_key: &[u8]) {
    let span = span!(Level::DEBUG, "ws_relay");
    let _enter = span.enter();
    tracing::debug!("websocket disconnect");
    let mut writer = state.write().await;
    writer.remove(public_key);
}

async fn handle_socket(
    socket: WebSocket,
    state: RelayState,
    public_key: Vec<u8>,
    relay_tx: mpsc::Sender<Vec<u8>>,
    relay_rx: mpsc::Receiver<Vec<u8>>,
    close_tx: mpsc::Sender<Message>,
    close_rx: mpsc::Receiver<Message>,
) {
    let (writer, reader) = socket.split();
    tokio::spawn(write(public_key.clone(), writer, relay_rx, close_rx));
    tokio::spawn(read(Arc::clone(&state), public_key, reader, close_tx));
}

async fn read(
    state: RelayState,
    public_key: Vec<u8>,
    mut receiver: SplitStream<WebSocket>,
    close_tx: mpsc::Sender<Message>,
) -> Result<()> {
    while let Some(msg) = receiver.next().await {
        match msg {
            Ok(msg) => match msg {
                Message::Text(_) => {}
                Message::Binary(buffer) => {
                    if let Ok(header) = decode::<RelayHeader>(&buffer).await {
                        let reader = state.read().await;
                        if let Some(tx) = reader.get(&header.to_public_key) {
                            if let Err(e) = tx.send(buffer).await {
                                tracing::warn!(error = ?e);
                            }
                        }
                    }
                }
                Message::Ping(_) => {}
                Message::Pong(_) => {}
                Message::Close(frame) => {
                    let _ = close_tx.send(Message::Close(frame)).await;
                    disconnect(state, &public_key).await;
                    return Ok(());
                }
            },
            Err(e) => {
                disconnect(state, &public_key).await;
                return Err(e.into());
            }
        }
    }
    Ok(())
}

async fn write(
    public_key: Vec<u8>,
    mut sender: SplitSink<WebSocket, Message>,
    mut relay_rx: mpsc::Receiver<Vec<u8>>,
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
            event = relay_rx.recv().fuse() => {
                if let Some(buf) = event {
                    if let Err(e) = sender.send(Message::Binary(buf)).await {
                        tracing::warn!(error = ?e);
                    }
                }
            },
        }
    }
}
