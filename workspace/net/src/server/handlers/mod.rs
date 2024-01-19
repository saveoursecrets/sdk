use axum::{
    extract::Extension,
    response::{IntoResponse, Redirect},
    Json,
};

//use axum_macros::debug_handler;

use crate::server::{
    authenticate::{self, BearerToken},
    Error, Result, ServerBackend,
};
use axum_extra::headers::{authorization::Bearer, Authorization};
use serde::Deserialize;
use serde_json::json;
use sos_sdk::signer::ecdsa::Address;

pub mod account;
pub mod files;

#[cfg(feature = "listen")]
pub(crate) mod websocket;

#[cfg(feature = "listen")]
use crate::{
    server::{handlers::websocket::BroadcastMessage, ServerState, State},
    ChangeNotification,
};

/// Query string for connections.
#[derive(Debug, Deserialize)]
pub struct ConnectionQuery {
    pub connection_id: String,
}

/// Serve the home page.
pub(crate) async fn home() -> impl IntoResponse {
    Redirect::permanent("/api/v1")
}

/// Serve the API identity page.
pub(crate) async fn api() -> impl IntoResponse {
    let name = env!("CARGO_PKG_NAME");
    let version = env!("CARGO_PKG_VERSION");
    Json(json!({"name": name, "version": version}))
}

/// Get the number of websocket connections.
pub(crate) async fn connections(
    Extension(state): Extension<ServerState>,
) -> impl IntoResponse {
    let reader = state.read().await;
    let num_connections = reader
        .sockets
        .values()
        .fold(0, |acc, conn| acc + conn.clients);
    Json(json!(num_connections))
}

/// Type to represent the caller of a service request.
pub struct Caller {
    token: BearerToken,
    connection_id: String,
}

impl Caller {
    /// Account address of the caller.
    pub fn address(&self) -> &Address {
        &self.token.address
    }

    /// Connection identifier.
    pub fn connection_id(&self) -> &str {
        &self.connection_id
    }
}

/// Authenticate an endpoint.
async fn authenticate_endpoint(
    bearer: Authorization<Bearer>,
    signed_data: &[u8],
    query: ConnectionQuery,
    state: ServerState,
    backend: ServerBackend,
    restricted: bool,
) -> Result<Caller> {
    let token = authenticate::bearer(bearer, signed_data)
        .await
        .map_err(|_| Error::BadRequest)?;

    // Deny unauthorized account addresses
    {
        let reader = state.read().await;
        if !reader.config.access.is_allowed_access(&token.address) {
            return Err(Error::Forbidden);
        }
    }

    // Restricted services require a device signature
    match (restricted, &token.device_signature) {
        (true, None) => {
            return Err(Error::Forbidden);
        }
        (true, Some(device_signature)) => {
            let reader = backend.read().await;
            reader
                .verify_device(&token.address, device_signature, &signed_data)
                .await?;
        }
        _ => {}
    }

    let owner = Caller {
        token,
        connection_id: query.connection_id,
    };

    Ok(owner)
}

/// Send change notifications to connected clients.
#[cfg(feature = "listen")]
pub(crate) fn send_notification(
    writer: &mut State,
    caller: &Caller,
    notification: ChangeNotification,
) {
    // Send notification on the websockets channel
    match serde_json::to_vec(&notification) {
        Ok(buffer) => {
            if let Some(conn) = writer.sockets.get(caller.address()) {
                let message = BroadcastMessage {
                    buffer,
                    connection_id: caller.connection_id().to_owned(),
                };
                if conn.tx.send(message).is_err() {
                    tracing::debug!("websocket events channel dropped");
                }
            }
        }
        Err(e) => {
            tracing::error!("{}", e);
        }
    }
}
