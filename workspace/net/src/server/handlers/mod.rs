use axum::{
    extract::Extension,
    response::{IntoResponse, Redirect},
    Json,
};

//use axum_macros::debug_handler;

use super::ServerState;
use crate::server::{
    authenticate::{self, BearerToken},
    Error, Result,
};
use axum_extra::{
    headers::{authorization::Bearer, Authorization},
    typed_header::TypedHeader,
};
use serde_json::json;
use sos_sdk::signer::ecdsa::Address;

pub(crate) mod account;
pub(crate) mod files;
pub(crate) mod service;

#[cfg(feature = "listen")]
pub(crate) mod websocket;

/// Serve the home page.
pub(crate) async fn home(
    Extension(_): Extension<ServerState>,
) -> impl IntoResponse {
    Redirect::permanent("/api")
}

/// Serve the API identity page.
pub(crate) async fn api(
    Extension(state): Extension<ServerState>,
) -> impl IntoResponse {
    let reader = state.read().await;
    Json(json!(&reader.info))
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
) -> Result<Caller> {
    let token = authenticate::bearer(bearer, signed_data)
        .await
        .map_err(|_| Error::BadRequest)?;

    // Call the target service for a reply
    let owner = Caller {
        token,
        connection_id: String::new(),
        //connection_id: query.connection_id,
    };

    Ok(owner)
}
