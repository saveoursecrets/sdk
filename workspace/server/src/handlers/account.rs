use axum::{
    body::Bytes,
    extract::{Extension, TypedHeader},
    headers::{authorization::Bearer, Authorization},
    http::StatusCode,
};

//use axum_macros::debug_handler;

use sos_core::{
    events::{AuditEvent, AuditProvider, EventKind},
    vault::Vault,
};

use std::sync::Arc;
use tokio::sync::RwLock;

use crate::{
    authenticate::{self},
    Backend, State,
};

// Handlers for account events.
pub(crate) struct AccountHandler;
impl AccountHandler {
    /// Create a new user account.
    pub(crate) async fn put_account(
        Extension(state): Extension<Arc<RwLock<State>>>,
        TypedHeader(authorization): TypedHeader<Authorization<Bearer>>,
        body: Bytes,
    ) -> Result<StatusCode, StatusCode> {
        if let Ok((status_code, token)) =
            authenticate::bearer(authorization, &body)
        {
            if let (StatusCode::OK, Some(token)) = (status_code, token) {
                let mut writer = state.write().await;
                if writer.backend.account_exists(&token.address).await {
                    return Err(StatusCode::CONFLICT);
                }

                if let Ok(vault) = Vault::read_buffer(&body) {
                    let uuid = vault.id();
                    if let Ok(_) = writer
                        .backend
                        .create_account(&token.address, &uuid, &body)
                        .await
                    {
                        let log = AuditEvent::new(
                            EventKind::CreateAccount,
                            token.address,
                            None,
                        );
                        writer
                            .audit_log
                            .append_audit_event(log)
                            .await
                            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
                        Ok(StatusCode::OK)
                    } else {
                        Err(StatusCode::INTERNAL_SERVER_ERROR)
                    }
                } else {
                    Err(StatusCode::BAD_REQUEST)
                }
            } else {
                Err(status_code)
            }
        } else {
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}
