use axum::{
    extract::Extension,
    response::{IntoResponse, Redirect},
    Json,
};

#[cfg(feature = "gui")]
use axum::{
    body::{Body, Bytes},
    http::{Request, Response},
};

//use axum_macros::debug_handler;

use serde_json::json;

use std::sync::Arc;
use tokio::sync::RwLock;

use super::State;

#[cfg(feature = "gui")]
use super::assets::Assets;

pub(crate) mod service;

pub(crate) mod websocket;

/// Serve the home page.
pub(crate) async fn home(
    Extension(state): Extension<Arc<RwLock<State>>>,
) -> impl IntoResponse {
    let reader = state.read().await;
    if cfg!(feature = "gui") {
        if reader.config.gui {
            Redirect::temporary("/gui")
        } else {
            Redirect::temporary("/api")
        }
    } else {
        Redirect::temporary("/api")
    }
}

/// Serve bundled static assets.
#[cfg(feature = "gui")]
pub(crate) async fn assets(
    Extension(state): Extension<Arc<RwLock<State>>>,
    request: Request<Body>,
) -> Response<Body> {
    let reader = state.read().await;
    if reader.config.gui {
        let mut path = request.uri().path().to_string();
        if path.ends_with('/') {
            path.push_str("index.html");
        }

        let key = path.trim_start_matches("/gui/");
        tracing::debug!(key, "static asset");

        if let Some(asset) = Assets::get(key) {
            let content_type =
                mime_guess::from_path(key).first().unwrap_or_else(|| {
                    "application/octet-stream".parse().unwrap()
                });

            let bytes = Bytes::from(asset.data.as_ref().to_vec());
            Response::builder()
                .header("content-type", content_type.as_ref())
                .status(StatusCode::OK)
                .body(Body::from(bytes))
                .unwrap()
        } else {
            Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(Body::empty())
                .unwrap()
        }
    } else {
        Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Body::empty())
            .unwrap()
    }
}

/// Serve the API identity page.
pub(crate) async fn api(
    Extension(state): Extension<Arc<RwLock<State>>>,
) -> impl IntoResponse {
    let reader = state.read().await;
    Json(json!(&reader.info))
}
