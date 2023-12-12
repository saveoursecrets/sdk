use axum::http::StatusCode;

use sos_sdk::{
    constants::{ACCOUNT_CREATE, ACCOUNT_LIST_VAULTS, ACCOUNT_STATUS},
    decode,
    device::DevicePublicKey,
    sync::ChangeSet,
};

use async_trait::async_trait;

use super::{PrivateState, Service};
use crate::{
    rpc::{RequestMessage, ResponseMessage},
    server::{BackendHandler, Error, Result},
};

//#[cfg(feature = "listen")]
//use crate::events::{ChangeEvent, ChangeNotification};

//#[cfg(feature = "listen")]
//use super::send_notification;

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
        let (caller, (_state, backend)) = state;

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

                let device_public_key =
                    request.parameters::<DevicePublicKey>()?;

                let account: ChangeSet = decode(request.body()).await?;

                let mut writer = backend.write().await;
                writer
                    .handler_mut()
                    .create_account(
                        caller.address(),
                        account,
                        device_public_key,
                    )
                    .await?;

                let reply: ResponseMessage<'_> =
                    (request.id(), ()).try_into()?;

                /*
                let vault_id = *summary.id();

                #[cfg(feature = "listen")]
                {
                    let notification = ChangeNotification::new(
                        caller.address(),
                        caller.public_key(),
                        &vault_id,
                        proof,
                        vec![ChangeEvent::CreateFolder(event.clone())],
                    );

                    let mut writer = state.write().await;
                    send_notification(&mut writer, &caller, notification);
                }
                */

                Ok(reply)
            }
            ACCOUNT_STATUS => {
                let account_exists = {
                    let reader = backend.read().await;
                    reader.handler().account_exists(caller.address()).await?
                };

                let result = if account_exists {
                    let reader = backend.read().await;
                    let accounts = reader.accounts();
                    let reader = accounts.read().await;
                    let account = reader.get(caller.address()).unwrap();
                    let account = account.read().await;
                    Some(account.folders.sync_status().await?)
                } else {
                    None
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

                Ok(reply)
            }
            _ => Err(Error::RpcUnknownMethod(request.method().to_owned())),
        }
    }
}
