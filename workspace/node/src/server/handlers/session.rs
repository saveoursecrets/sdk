//! Handlers and service for session authentication.
use axum::{
    body::Bytes,
    extract::{Extension, Path, TypedHeader},
    headers::{authorization::Bearer, Authorization},
    http::{header::HeaderMap, StatusCode},
};

use async_trait::async_trait;
use std::sync::{Arc, RwLock};

use sos_core::rpc::{RequestMessage, ResponseMessage, Service};

use crate::server::State;

/// Session negotiation service.
struct SessionService {}

#[async_trait]
impl Service for SessionService {
    type State = Arc<RwLock<State>>;

    fn handle<'a>(
        &self,
        state: &Self::State,
        request: RequestMessage<'a>,
    ) -> sos_core::Result<Option<ResponseMessage<'a>>> {
        todo!()
    }
}

/// Entry point for the session service.
pub(crate) async fn entry(
    Extension(state): Extension<Arc<RwLock<State>>>,
    body: Bytes,
) -> Result<(StatusCode, HeaderMap, Bytes), StatusCode> {
    todo!()
}
