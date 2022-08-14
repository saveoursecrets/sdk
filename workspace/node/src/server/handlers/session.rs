//! Handlers and service for session authentication.
use axum::{body::Bytes, extract::Extension, http::StatusCode};

use std::sync::Arc;
use tokio::sync::RwLock;

use crate::server::{
    services::{public_service, SessionService},
    State,
};

pub(crate) struct SessionHandler;
impl SessionHandler {
    /// Entry point for the session service.
    pub(crate) async fn post(
        Extension(state): Extension<Arc<RwLock<State>>>,
        body: Bytes,
    ) -> Result<(StatusCode, Bytes), StatusCode> {
        let service = SessionService {};
        Ok(public_service(service, state, body).await?)
    }
}
