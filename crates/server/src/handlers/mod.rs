use axum::{
    extract::Extension,
    response::{IntoResponse, Redirect},
    Json,
};

//use axum_macros::debug_handler;

use crate::{
    authenticate::{self, BearerToken},
    Error, Result, ServerBackend,
};
use axum_extra::headers::{authorization::Bearer, Authorization};
use http::HeaderMap;
use serde::Deserialize;
use serde_json::json;
use sos_core::AccountId;
use sos_protocol::constants::X_SOS_ACCOUNT_ID;

pub mod account;
pub mod files;

#[cfg(feature = "pairing")]
pub(crate) mod relay;
pub(crate) mod websocket;

// 32MB limit for the body size
const BODY_LIMIT: usize = 33554432;

#[cfg(feature = "listen")]
use sos_protocol::{ChangeNotification, WireEncodeDecode};

use crate::server::{ServerState, State};

fn parse_account_id(headers: &HeaderMap) -> Option<AccountId> {
    headers
        .get(X_SOS_ACCOUNT_ID)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<AccountId>().ok())
}

/// Query string for connections.
#[derive(Debug, Deserialize, Clone)]
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
#[cfg(feature = "listen")]
pub(crate) async fn connections(
    Extension(state): Extension<ServerState>,
) -> impl IntoResponse {
    let reader = state.read().await;
    let num_connections = reader
        .sockets
        .values()
        .fold(0, |acc, conn| acc + conn.len());
    Json(json!(num_connections))
}

/// Type to represent the caller of a service request.
pub struct Caller {
    token: BearerToken,
    connection_id: Option<String>,
}

impl Caller {
    /// Account identifier of the caller.
    pub fn account_id(&self) -> &AccountId {
        &self.token.account_id
    }

    /// Connection identifier.
    pub fn connection_id(&self) -> Option<&str> {
        self.connection_id.as_ref().map(|s| &s[..])
    }
}

/// Authenticate an endpoint.
async fn authenticate_endpoint(
    account_id: Option<AccountId>,
    bearer: Authorization<Bearer>,
    signed_data: &[u8],
    query: Option<ConnectionQuery>,
    state: ServerState,
    backend: ServerBackend,
) -> Result<Caller> {
    let token = authenticate::bearer(account_id, bearer)
        .await
        .map_err(|_| Error::BadRequest)?;

    // Deny unauthorized account ids
    {
        let reader = state.read().await;
        if let Some(access) = &reader.config.access {
            if !access.is_allowed_access(&token.account_id) {
                return Err(Error::Forbidden);
            }
        }
    }

    let reader = backend.read().await;
    reader
        .verify_device(
            &token.account_id,
            &token.device_signature,
            &signed_data,
        )
        .await?;

    let owner = Caller {
        token,
        connection_id: query.map(|q| q.connection_id),
    };

    Ok(owner)
}

/// Send change notifications to connected clients.
#[cfg(feature = "listen")]
pub(crate) async fn send_notification(
    reader: &State,
    caller: &Caller,
    notification: ChangeNotification,
) {
    // Send notification on the websockets channel
    match notification.encode().await {
        Ok(buffer) => {
            if let Some(account) = reader.sockets.get(caller.account_id()) {
                if let Err(error) = account.broadcast(caller, buffer).await {
                    tracing::warn!(error = ?error);
                }
            }
        }
        Err(e) => {
            tracing::error!(error = %e, "send_notification");
        }
    }
}
