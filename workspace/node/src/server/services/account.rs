use axum::http::StatusCode;

use sos_core::{
    address::AddressStr,
    constants::{ACCOUNT_CREATE, ACCOUNT_LIST_VAULTS},
    events::{ChangeEvent, ChangeNotification, EventKind},
    rpc::{RequestMessage, ResponseMessage, Service},
    vault::Header,
    AuditEvent,
};

use async_trait::async_trait;
use std::sync::Arc;
use tokio::sync::RwLock;

use super::{append_audit_logs, send_notification};
use crate::server::State;

/// Account management service.
///
/// * `Account.create`: Create a new account.
/// * `Account.list_vaults`: List vault summaries for an account.
///
pub struct AccountService;

#[async_trait]
impl Service for AccountService {
    type State = (AddressStr, Arc<RwLock<State>>);

    async fn handle<'a>(
        &self,
        state: Self::State,
        request: RequestMessage<'a>,
    ) -> sos_core::Result<ResponseMessage<'a>> {
        let (address, state) = state;

        let mut writer = state.write().await;

        match request.method() {
            ACCOUNT_CREATE => {
                if writer.backend.account_exists(&address).await {
                    return Ok((StatusCode::CONFLICT, request.id()).into());
                }

                let summary = Header::read_summary_slice(request.body())?;

                let (sync_event, proof) = writer
                    .backend
                    .create_account(&address, summary.id(), request.body())
                    .await
                    .map_err(Box::from)?;

                let reply: ResponseMessage<'_> =
                    (request.id(), &proof).try_into()?;

                let notification = ChangeNotification::new(
                    &address,
                    summary.id(),
                    proof,
                    vec![ChangeEvent::CreateVault],
                );

                let log = AuditEvent::from_sync_event(
                    &sync_event,
                    address,
                    *summary.id(),
                );

                append_audit_logs(&mut writer, vec![log])
                    .await
                    .map_err(Box::from)?;
                send_notification(&mut writer, notification);

                Ok(reply)
            }
            ACCOUNT_LIST_VAULTS => {
                if !writer.backend.account_exists(&address).await {
                    return Ok((StatusCode::NOT_FOUND, request.id()).into());
                }

                let summaries =
                    writer.backend.list(&address).await.map_err(Box::from)?;

                let reply: ResponseMessage<'_> =
                    (request.id(), summaries).try_into()?;

                let log =
                    AuditEvent::new(EventKind::LoginResponse, address, None);
                append_audit_logs(&mut writer, vec![log])
                    .await
                    .map_err(Box::from)?;

                Ok(reply)
            }
            _ => Err(sos_core::Error::Message("unknown method".to_owned())),
        }
    }
}
