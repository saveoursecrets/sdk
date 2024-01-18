use axum::{
    body::Bytes,
    extract::{Extension, Query},
    response::IntoResponse,
};

use axum_extra::{
    headers::{authorization::Bearer, Authorization},
    typed_header::TypedHeader,
};

//use axum_macros::debug_handler;

use crate::server::{
    services::{private_service, SyncService},
    ServerBackend, ServerState,
};
use serde::Deserialize;

/// Query string for service connections.
#[derive(Debug, Deserialize)]
pub struct ServiceQuery {
    pub connection_id: String,
}

// Handlers for account events.
pub(crate) struct ServiceHandler;
impl ServiceHandler {
    /// Handle requests for the sync service.
    pub(crate) async fn sync(
        Extension(state): Extension<ServerState>,
        Extension(backend): Extension<ServerBackend>,
        TypedHeader(bearer): TypedHeader<Authorization<Bearer>>,
        Query(query): Query<ServiceQuery>,
        body: Bytes,
    ) -> impl IntoResponse {
        let service = SyncService {};
        match private_service(
            service, state, backend, bearer, query, body, true,
        )
        .await
        {
            Ok(result) => result.into_response(),
            Err(error) => error.into_response(),
        }
    }
}
