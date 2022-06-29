use axum::{
    body::{Body, Bytes},
    extract::{Extension, Path, TypedHeader},
    headers::{authorization::Bearer, Authorization},
    http::{
        header::{HeaderMap, AUTHORIZATION, CONTENT_TYPE},
        HeaderValue, Method, Request, Response, StatusCode,
    },
    response::{IntoResponse, Redirect},
    routing::{get, put},
    Json, Router,
};

use tower_http::cors::{CorsLayer, Origin};

//use axum_macros::debug_handler;

use serde::Serialize;
use serde_json::json;
use sos_core::{
    address::AddressStr,
    decode,
    events::{AuditEvent, AuditProvider, ChangeEvent, SyncEvent},
    patch::Patch,
    secret::SecretId,
    vault::{Header, VaultCommit},
};

use std::{borrow::Cow, collections::HashMap, net::SocketAddr, sync::Arc};
use tokio::sync::RwLock;
use uuid::Uuid;

use sos_audit::AuditLogFile;

use crate::{
    State,
    assets::Assets,
    authenticate::{self, Authentication},
    handlers::{
        account::AccountHandler,
        auth::AuthHandler,
        sse::{sse_handler, SseConnection},
        wal::WalHandler,
    },
    headers::{
        ChangeSequence, SignedMessage, X_CHANGE_SEQUENCE, X_COMMIT_HASH,
        X_COMMIT_PROOF, X_SIGNED_MESSAGE,
    },
    Backend, ServerConfig,
};

pub(crate) mod account;
pub(crate) mod auth;
pub(crate) mod sse;
pub(crate) mod wal;

// Serve the home page.
pub(crate) async fn home(
    Extension(state): Extension<Arc<RwLock<State>>>,
) -> impl IntoResponse {
    let reader = state.read().await;
    if reader.config.gui {
        Redirect::temporary("/gui")
    } else {
        Redirect::temporary("/api")
    }
}

// Serve bundled static assets.
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

// Serve the API identity page.
pub(crate) async fn api(
    Extension(state): Extension<Arc<RwLock<State>>>,
) -> impl IntoResponse {
    let reader = state.read().await;
    Json(json!(&reader.info))
}
