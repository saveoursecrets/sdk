use axum::http::StatusCode;
use std::collections::HashMap;

use sos_sdk::{
    constants::{ACCOUNT_CREATE, ACCOUNT_LIST_VAULTS, ACCOUNT_STATUS},
    crypto::SecureAccessKey,
    events::{AuditEvent, Event, EventKind},
    storage::AccountStatus,
    vault::Header,
};

use async_trait::async_trait;

use super::Service;
use super::{append_audit_logs, PrivateState};
use crate::{
    rpc::{RequestMessage, ResponseMessage},
    server::{BackendHandler, Error, Result},
};

#[cfg(feature = "listen")]
use crate::events::{ChangeEvent, ChangeNotification};

#[cfg(feature = "listen")]
use super::send_notification;

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
    ) -> Result<ResponseMessage<'a>> {
        let (caller, (state, backend)) = state;

        match request.method() {
            ACCOUNT_CREATE => {
                {
                    let reader = backend.read().await;
                    if reader
                        .handler()
                        .account_exists(caller.address())
                        .await?
                    {
                        return Ok(
                            (StatusCode::CONFLICT, request.id()).into()
                        );
                    }
                }

                let secure_key = request.parameters::<SecureAccessKey>()?;

                let summary =
                    Header::read_summary_slice(request.body()).await?;

                let mut writer = backend.write().await;

                let (sync_event, proof) = writer
                    .handler_mut()
                    .create_account(
                        caller.address(),
                        summary.id(),
                        request.body(),
                        secure_key,
                    )
                    .await?;

                let reply: ResponseMessage<'_> =
                    (request.id(), &proof).try_into()?;

                let vault_id = *summary.id();

                #[cfg(feature = "listen")]
                let notification = ChangeNotification::new(
                    caller.address(),
                    caller.public_key(),
                    &vault_id,
                    proof,
                    vec![ChangeEvent::CreateVault(summary)],
                );

                let event = Event::Write(vault_id, sync_event);
                let log: AuditEvent = (caller.address(), &event).into();

                {
                    let mut writer = state.write().await;
                    append_audit_logs(&mut writer, vec![log]).await?;

                    #[cfg(feature = "listen")]
                    send_notification(&mut writer, &caller, notification);
                }

                Ok(reply)
            }
            ACCOUNT_STATUS => {
                let account_exists = {
                    let reader = backend.read().await;
                    reader.handler().account_exists(caller.address()).await?
                };

                let result: AccountStatus = if account_exists {
                    let reader = backend.read().await;
                    let accounts = reader.accounts();
                    let reader = accounts.read().await;
                    let account = reader.get(caller.address()).unwrap();
                    let account = account.read().await;
                    account.folders.account_status().await?
                } else {
                    Default::default()
                };

                let reply: ResponseMessage<'_> =
                    (request.id(), result).try_into()?;

                Ok(reply)
            }
            ACCOUNT_LIST_VAULTS => {
                let reader = backend.read().await;
                if !reader.handler().account_exists(caller.address()).await? {
                    return Ok((StatusCode::NOT_FOUND, request.id()).into());
                }

                let summaries =
                    reader.handler().list_folders(caller.address()).await?;

                let reply: ResponseMessage<'_> =
                    (request.id(), summaries).try_into()?;

                let log = AuditEvent::new(
                    EventKind::ListVaults,
                    caller.address,
                    None,
                );

                {
                    let mut writer = state.write().await;
                    append_audit_logs(&mut writer, vec![log]).await?;
                }

                Ok(reply)
            }
            _ => Err(Error::RpcUnknownMethod(request.method().to_owned())),
        }
    }
}
