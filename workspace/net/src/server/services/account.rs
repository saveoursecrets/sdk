use axum::http::StatusCode;
use std::collections::HashMap;

use sos_sdk::{
    account::AccountStatus,
    constants::{ACCOUNT_CREATE, ACCOUNT_LIST_VAULTS, ACCOUNT_STATUS},
    events::{AuditEvent, ChangeEvent, ChangeNotification, Event, EventKind},
    vault::Header,
};

use async_trait::async_trait;

use super::{append_audit_logs, send_notification, PrivateState};
use crate::{
    rpc::{RequestMessage, ResponseMessage, Service},
    server::{BackendHandler, Error, ServerBackend},
};

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
    ) -> crate::Result<ResponseMessage<'a>> {
        let (caller, (state, backend)) = state;

        match request.method() {
            ACCOUNT_STATUS => {
                let account_exists = {
                    let reader = backend.read().await;
                    reader
                        .handler()
                        .account_exists(caller.address())
                        .await
                        .map_err(Box::from)?
                };

                let result: AccountStatus = if account_exists {
                    let reader = backend.read().await;
                    let summaries = reader
                        .handler()
                        .list(caller.address())
                        .await
                        .map_err(Box::from)?;

                    let mut proofs = HashMap::new();
                    let accounts = reader.accounts();
                    let backend = accounts.read().await;
                    for summary in summaries {
                        let event_log = backend
                            .get(caller.address())
                            .ok_or_else(|| {
                                Error::AccountNotExist(*caller.address())
                            })
                            .map_err(Box::from)?
                            .get(summary.id())
                            .ok_or_else(|| {
                                Error::VaultNotExist(*summary.id())
                            })
                            .map_err(Box::from)?;

                        let proof = event_log.tree().head()?;
                        proofs.insert(*summary.id(), proof);
                    }
                    AccountStatus {
                        exists: true,
                        proofs,
                    }
                } else {
                    Default::default()
                };

                let reply: ResponseMessage<'_> =
                    (request.id(), result).try_into()?;

                Ok(reply)
            }
            ACCOUNT_CREATE => {
                {
                    let reader = backend.read().await;
                    if reader
                        .handler()
                        .account_exists(caller.address())
                        .await
                        .map_err(Box::from)?
                    {
                        return Ok(
                            (StatusCode::CONFLICT, request.id()).into()
                        );
                    }
                }

                let summary =
                    Header::read_summary_slice(request.body()).await?;

                let mut writer = backend.write().await;
                let (sync_event, proof) = writer
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
                    caller.public_key(),
                    &vault_id,
                    proof,
                    vec![ChangeEvent::CreateVault(summary, None)],
                );

                let event = Event::Write(vault_id, sync_event);
                let log: AuditEvent = (caller.address(), &event).into();

                {
                    let mut writer = state.write().await;
                    append_audit_logs(&mut writer, vec![log])
                        .await
                        .map_err(Box::from)?;
                    send_notification(&mut writer, &caller, notification);
                }

                Ok(reply)
            }
            ACCOUNT_LIST_VAULTS => {
                let reader = backend.read().await;
                if !reader
                    .handler()
                    .account_exists(caller.address())
                    .await
                    .map_err(Box::from)?
                {
                    return Ok((StatusCode::NOT_FOUND, request.id()).into());
                }

                let summaries = reader
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

                {
                    let mut writer = state.write().await;
                    append_audit_logs(&mut writer, vec![log])
                        .await
                        .map_err(Box::from)?;
                }

                Ok(reply)
            }
            _ => Err(crate::Error::RpcUnknownMethod(
                request.method().to_owned(),
            )),
        }
    }
}
