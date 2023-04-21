use axum::{
    extract::Extension,
    response::{IntoResponse, Redirect},
    Json,
};

//use axum_macros::debug_handler;

use serde_json::json;

use std::sync::Arc;
use tokio::sync::RwLock;

use super::State;

pub(crate) mod service;

pub(crate) mod websocket;

/// Serve the home page.
pub(crate) async fn home(
    Extension(state): Extension<Arc<RwLock<State>>>,
) -> impl IntoResponse {
    Redirect::temporary("/api")
}

/// Serve the API identity page.
pub(crate) async fn api(
    Extension(state): Extension<Arc<RwLock<State>>>,
) -> impl IntoResponse {
    let reader = state.read().await;
    Json(json!(&reader.info))
}
