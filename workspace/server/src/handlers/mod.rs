use axum::{
    body::{Body, Bytes},
    extract::Extension,
    http::{header::HeaderMap, HeaderValue, Request, Response, StatusCode},
    response::{IntoResponse, Redirect},
    Json,
};

//use axum_macros::debug_handler;

use serde_json::json;

use std::sync::Arc;
use tokio::sync::{RwLock, RwLockWriteGuard};

use crate::{
    assets::Assets,
    headers::{X_COMMIT_PROOF, X_MATCH_PROOF},
    State,
};

use sos_core::{
    commit_tree::CommitProof,
    encode,
    events::{AuditEvent, AuditProvider, ChangeNotification},
};

pub(crate) mod account;
pub(crate) mod auth;
pub(crate) mod sse;
pub(crate) mod wal;

fn append_commit_headers(
    headers: &mut HeaderMap,
    proof: &CommitProof,
) -> Result<(), StatusCode> {
    let value =
        encode(proof).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let x_commit_proof = HeaderValue::from_str(&base64::encode(&value))
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    headers.insert(X_COMMIT_PROOF.clone(), x_commit_proof);
    Ok(())
}

fn append_match_header(
    headers: &mut HeaderMap,
    proof: &CommitProof,
) -> Result<(), StatusCode> {
    let value =
        encode(proof).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let x_match_proof = HeaderValue::from_str(&base64::encode(&value))
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    headers.insert(X_MATCH_PROOF.clone(), x_match_proof);
    Ok(())
}

async fn append_audit_logs<'a>(
    writer: &mut RwLockWriteGuard<'a, State>,
    events: Vec<AuditEvent>,
) -> Result<(), StatusCode> {
    writer
        .audit_log
        .append_audit_events(&events)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(())
}

fn send_notification<'a>(
    writer: &mut RwLockWriteGuard<'a, State>,
    notification: ChangeNotification,
) {
    // Send notification on the SSE channel
    if let Some(conn) = writer.sse.get(notification.address()) {
        if let Err(_) = conn.tx.send(notification) {
            tracing::debug!("server sent events channel dropped");
        }
    }
}

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
