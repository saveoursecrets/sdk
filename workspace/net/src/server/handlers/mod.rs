use axum::{
    extract::Extension,
    response::{IntoResponse, Redirect},
    Json,
};

//use axum_macros::debug_handler;

use super::ServerState;
use serde_json::json;

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
