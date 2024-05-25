//! Relay forwards packets between peers over a websocket connection.
use crate::relay::RelayHeader;
use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        Extension, Query,
    },
    http::StatusCode,
    response::Response,
};
use futures::{stream::SplitSink, SinkExt, StreamExt};
use serde::Deserialize;
use sos_sdk::decode;
use std::{collections::HashMap, sync::Arc};
use tokio::sync::Mutex;

/// Query string for the relay service.
#[derive(Deserialize)]
pub struct RelayQuery {
    /// Connection public key.
    #[serde(with = "hex::serde")]
    pub public_key: Vec<u8>,
}

/// Connected clients.
pub type RelayConnections = HashMap<Vec<u8>, SplitSink<WebSocket, Message>>;

/// State for the relay service.
pub type RelayState = Arc<Mutex<RelayConnections>>;

/// Upgrade to a websocket connection.
pub async fn upgrade(
    Extension(state): Extension<RelayState>,
    Query(query): Query<RelayQuery>,
    ws: WebSocketUpgrade,
) -> std::result::Result<Response, StatusCode> {
    tracing::debug!("ws_relay::upgrade_request");
    Ok(ws.on_upgrade(move |socket| {
        handle_socket(socket, state, query.public_key)
    }))
}

async fn handle_socket(
    socket: WebSocket,
    state: RelayState,
    public_key: Vec<u8>,
) {
    let (writer, mut reader) = socket.split();

    {
        let mut state = state.lock().await;
        state.insert(public_key.clone(), writer);
    }

    while let Some(msg) = reader.next().await {
        match msg {
            Ok(msg) => match msg {
                Message::Text(_) => {}
                Message::Binary(buffer) => {
                    if let Ok(header) = decode::<RelayHeader>(&buffer).await {
                        let mut writer = state.lock().await;
                        if let Some(tx) =
                            writer.get_mut(&header.to_public_key)
                        {
                            if let Err(e) =
                                tx.send(Message::Binary(buffer)).await
                            {
                                tracing::warn!(error = ?e);
                            }
                        }
                    }
                }
                Message::Ping(_) => {}
                Message::Pong(_) => {}
                Message::Close(_) => {
                    tracing::trace!("ws_relay::disconnect::close_message");
                    disconnect(Arc::clone(&state), &public_key).await;
                }
            },
            Err(_) => {
                tracing::trace!("ws_relay::disconnect::read_error");
                disconnect(Arc::clone(&state), &public_key).await;
            }
        }
    }
}

async fn disconnect(state: RelayState, public_key: &[u8]) {
    tracing::debug!("ws_relay::disconnect");
    let mut writer = state.lock().await;
    writer.remove(public_key);
}
