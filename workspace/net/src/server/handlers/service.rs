use axum::{
    body::Bytes,
    extract::{Extension, TypedHeader, Query},
    headers::{authorization::Bearer, Authorization},
    response::IntoResponse,
};

//use axum_macros::debug_handler;

use serde::Deserialize;
use crate::server::{
    services::{
        private_service, public_service, AccountService, DeviceService,
        HandshakeService, SyncService,
    },
    ServerBackend, ServerState,
};

/// Query string for service connections.
#[derive(Debug, Deserialize)]
pub struct ServiceQuery {
    pub connection_id: String,
}


    //Query(query): Query<ServiceQuery>,

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
        match private_service(service, state, backend, bearer, body, false)
            .await
        {
            Ok(result) => result.into_response(),
            Err(error) => error.into_response(),
        }
    }

    /// Handle requests for the device service.
    pub(crate) async fn device(
        Extension(state): Extension<ServerState>,
        Extension(backend): Extension<ServerBackend>,
        TypedHeader(bearer): TypedHeader<Authorization<Bearer>>,
        body: Bytes,
    ) -> impl IntoResponse {
        let service = DeviceService {};
        match private_service(service, state, backend, bearer, body, true)
            .await
        {
            Ok(result) => result.into_response(),
            Err(error) => error.into_response(),
        }
    }

    /// Handle requests for the sync service.
    pub(crate) async fn sync(
        Extension(state): Extension<ServerState>,
        Extension(backend): Extension<ServerBackend>,
        TypedHeader(bearer): TypedHeader<Authorization<Bearer>>,
        body: Bytes,
    ) -> impl IntoResponse {
        let service = SyncService {};
        match private_service(service, state, backend, bearer, body, true)
            .await
        {
            Ok(result) => result.into_response(),
            Err(error) => error.into_response(),
        }
    }
}
