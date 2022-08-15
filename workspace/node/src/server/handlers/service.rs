use axum::{
    body::Bytes,
    extract::{Extension, TypedHeader},
    http::StatusCode,
};

//use axum_macros::debug_handler;

use std::sync::Arc;
use tokio::sync::RwLock;

use crate::server::{
    headers::Session,
    services::{
        private_service, public_service, AccountService, SessionService,
        VaultService, WalService,
    },
    State,
};

// Handlers for account events.
pub(crate) struct ServiceHandler;
impl ServiceHandler {
    /// Handle requests for the session service.
    pub(crate) async fn session(
        Extension(state): Extension<Arc<RwLock<State>>>,
        body: Bytes,
    ) -> Result<(StatusCode, Bytes), StatusCode> {
        let service = SessionService {};
        Ok(public_service(service, state, body).await?)
    }

    /// Handle requests for the account service.
    pub(crate) async fn account(
        Extension(state): Extension<Arc<RwLock<State>>>,
        TypedHeader(session_id): TypedHeader<Session>,
        body: Bytes,
    ) -> Result<(StatusCode, Bytes), StatusCode> {
        let service = AccountService {};
        Ok(private_service(service, state, session_id.id(), body).await?)
    }

    /// Handle requests for the vault service.
    pub(crate) async fn vault(
        Extension(state): Extension<Arc<RwLock<State>>>,
        TypedHeader(session_id): TypedHeader<Session>,
        body: Bytes,
    ) -> Result<(StatusCode, Bytes), StatusCode> {
        let service = VaultService {};
        Ok(private_service(service, state, session_id.id(), body).await?)
    }

    /// Handle requests for the WAL service.
    pub(crate) async fn wal(
        Extension(state): Extension<Arc<RwLock<State>>>,
        TypedHeader(session_id): TypedHeader<Session>,
        body: Bytes,
    ) -> Result<(StatusCode, Bytes), StatusCode> {
        let service = WalService {};
        Ok(private_service(service, state, session_id.id(), body).await?)
    }
}
