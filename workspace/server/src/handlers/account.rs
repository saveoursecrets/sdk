use axum::{
    body::Bytes,
    extract::{Extension, TypedHeader},
    headers::{authorization::Bearer, Authorization},
    http::{header::HeaderMap, StatusCode},
};

//use axum_macros::debug_handler;

use sos_core::{
    events::{AuditEvent, ChangeEvent},
    vault::Header,
};

use std::sync::Arc;
use tokio::sync::RwLock;

use crate::{
    authenticate::{self},
    State,
};

use super::{append_audit_logs, append_commit_headers, send_notifications};

// Handlers for account events.
pub(crate) struct AccountHandler;
impl AccountHandler {
    /// Create a new user account.
    pub(crate) async fn put_account(
        Extension(state): Extension<Arc<RwLock<State>>>,
        TypedHeader(authorization): TypedHeader<Authorization<Bearer>>,
        body: Bytes,
    ) -> Result<(StatusCode, HeaderMap), StatusCode> {
        if let Ok((status_code, token)) =
            authenticate::bearer(authorization, &body)
        {
            if let (StatusCode::OK, Some(token)) = (status_code, token) {
                let mut writer = state.write().await;
                if writer.backend.account_exists(&token.address).await {
                    return Err(StatusCode::CONFLICT);
                }

                let summary = Header::read_summary_slice(&body)
                    .map_err(|_| StatusCode::BAD_REQUEST)?;

                let (sync_event, proof) = writer
                    .backend
                    .create_account(&token.address, summary.id(), &body)
                    .await
                    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

                let change_event = ChangeEvent::CreateVault {
                    vault_id: *summary.id(),
                    address: token.address,
                };

                let log = AuditEvent::from_sync_event(
                    &sync_event,
                    token.address,
                    *summary.id(),
                );

                append_audit_logs(&mut writer, vec![log]).await?;
                send_notifications(&mut writer, vec![change_event]);

                let mut headers = HeaderMap::new();
                append_commit_headers(&mut headers, &proof)?;
                Ok((StatusCode::OK, headers))
            } else {
                Err(status_code)
            }
        } else {
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}
