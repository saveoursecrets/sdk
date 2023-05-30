use axum::http::StatusCode;

use sos_sdk::{
    constants::{ACCOUNT_CREATE, ACCOUNT_LIST_VAULTS},
    events::{AuditEvent, ChangeEvent, ChangeNotification, Event, EventKind},
    rpc::{RequestMessage, ResponseMessage, Service},
    vault::Header,
};

use async_trait::async_trait;

use super::{append_audit_logs, send_notification, PrivateState};
use crate::server::BackendHandler;

/// Account management service.
///
/// * `Account.create`: Create a new account.
/// * `Account.list_vaults`: List vault summaries for an account.
///
pub struct AccountService;

#[async_trait]
impl Service for AccountService {
    type State = PrivateState;

    async fn handle<'a>(
        &self,
        state: Self::State,
        request: RequestMessage<'a>,
    ) -> sos_sdk::Result<ResponseMessage<'a>> {
        let (caller, state) = state;

        let mut writer = state.write().await;

        match request.method() {
            ACCOUNT_CREATE => {
                if writer
                    .backend
                    .handler()
                    .account_exists(caller.address())
                    .await
                {
                    return Ok((StatusCode::CONFLICT, request.id()).into());
                }

                let summary =
                    Header::read_summary_slice(request.body()).await?;

                let (sync_event, proof) = writer
                    .backend
                    .handler_mut()
                    .create_account(
                        caller.address(),
                        summary.id(),
                        request.body(),
                    )
                    .await
                    .map_err(Box::from)?;

                let reply: ResponseMessage<'_> =
                    (request.id(), &proof).try_into()?;

                let vault_id = *summary.id();

                let notification = ChangeNotification::new(
                    caller.address(),
                    caller.session_id(),
                    &vault_id,
                    proof,
                    vec![ChangeEvent::CreateVault(summary)],
                );

                let event = Event::Write(vault_id, sync_event);
                let log: AuditEvent = (caller.address(), &event).into();

                append_audit_logs(&mut writer, vec![log])
                    .await
                    .map_err(Box::from)?;
                send_notification(&mut writer, &caller, notification);

                Ok(reply)
            }
            ACCOUNT_LIST_VAULTS => {
                if !writer
                    .backend
                    .handler()
                    .account_exists(caller.address())
                    .await
                {
                    return Ok((StatusCode::NOT_FOUND, request.id()).into());
                }

                let summaries = writer
                    .backend
                    .handler()
                    .list(caller.address())
                    .await
                    .map_err(Box::from)?;

                let reply: ResponseMessage<'_> =
                    (request.id(), summaries).try_into()?;

                let log = AuditEvent::new(
                    EventKind::LoginResponse,
                    caller.address,
                    None,
                );
                append_audit_logs(&mut writer, vec![log])
                    .await
                    .map_err(Box::from)?;

                Ok(reply)
            }
            _ => Err(sos_sdk::Error::RpcUnknownMethod(
                request.method().to_owned(),
            )),
        }
    }
}
