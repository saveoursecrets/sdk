use axum::{
    body::Bytes,
    extract::{Extension, TypedHeader},
    headers::{authorization::Bearer, Authorization},
    http::StatusCode,
};

//use axum_macros::debug_handler;

use std::sync::Arc;
use tokio::sync::RwLock;

use crate::server::{
    services::{
        private_service, public_service, AccountService, EventLogService,
        HandshakeService, VaultService,
    },
    State,
};

// Handlers for account events.
pub(crate) struct ServiceHandler;
impl ServiceHandler {
    /// Handle requests for the noise protocol handshake.
    pub(crate) async fn handshake(
        Extension(state): Extension<Arc<RwLock<State>>>,
        body: Bytes,
    ) -> Result<(StatusCode, Bytes), StatusCode> {
        let service = HandshakeService {};
        public_service(service, state, body).await
    }

    /// Handle requests for the account service.
    pub(crate) async fn account(
        Extension(state): Extension<Arc<RwLock<State>>>,
        TypedHeader(bearer): TypedHeader<Authorization<Bearer>>,
        body: Bytes,
    ) -> Result<(StatusCode, Bytes), StatusCode> {
        let service = AccountService {};
        private_service(service, state, bearer, body).await
    }

    /// Handle requests for the vault service.
    pub(crate) async fn vault(
        Extension(state): Extension<Arc<RwLock<State>>>,
        TypedHeader(bearer): TypedHeader<Authorization<Bearer>>,
        body: Bytes,
    ) -> Result<(StatusCode, Bytes), StatusCode> {
        let service = VaultService {};
        private_service(service, state, bearer, body).await
    }

    /// Handle requests for the events service.
    pub(crate) async fn events(
        Extension(state): Extension<Arc<RwLock<State>>>,
        TypedHeader(bearer): TypedHeader<Authorization<Bearer>>,
        body: Bytes,
    ) -> Result<(StatusCode, Bytes), StatusCode> {
        let service = EventLogService {};
        private_service(service, state, bearer, body).await
    }
}
