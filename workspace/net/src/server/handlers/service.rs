use axum::{
    body::Bytes,
    extract::{Extension, TypedHeader},
    headers::{authorization::Bearer, Authorization},
    response::IntoResponse,
};

//use axum_macros::debug_handler;

use crate::server::{
    services::{
        private_service, public_service, AccountService, EventLogService,
        HandshakeService, VaultService,
    },
    ServerBackend, ServerState,
};

// Handlers for account events.
pub(crate) struct ServiceHandler;
impl ServiceHandler {
    /// Handle requests for the noise protocol handshake.
    pub(crate) async fn handshake(
        Extension(state): Extension<ServerState>,
        body: Bytes,
    ) -> impl IntoResponse {
        let service = HandshakeService {};
        match public_service(service, state, body).await {
            Ok(result) => result.into_response(),
            Err(error) => error.into_response(),
        }
    }

    /// Handle requests for the account service.
    pub(crate) async fn account(
        Extension(state): Extension<ServerState>,
        Extension(backend): Extension<ServerBackend>,
        TypedHeader(bearer): TypedHeader<Authorization<Bearer>>,
        body: Bytes,
    ) -> impl IntoResponse {
        let service = AccountService {};
        match private_service(service, state, backend, bearer, body).await {
            Ok(result) => result.into_response(),
            Err(error) => error.into_response(),
        }
    }

    /// Handle requests for the vault service.
    pub(crate) async fn vault(
        Extension(state): Extension<ServerState>,
        Extension(backend): Extension<ServerBackend>,
        TypedHeader(bearer): TypedHeader<Authorization<Bearer>>,
        body: Bytes,
    ) -> impl IntoResponse {
        let service = VaultService {};
        match private_service(service, state, backend, bearer, body).await {
            Ok(result) => result.into_response(),
            Err(error) => error.into_response(),
        }
    }

    /// Handle requests for the events service.
    pub(crate) async fn events(
        Extension(state): Extension<ServerState>,
        Extension(backend): Extension<ServerBackend>,
        TypedHeader(bearer): TypedHeader<Authorization<Bearer>>,
        body: Bytes,
    ) -> impl IntoResponse {
        let service = EventLogService {};
        match private_service(service, state, backend, bearer, body).await {
            Ok(result) => result.into_response(),
            Err(error) => error.into_response(),
        }
    }
}
