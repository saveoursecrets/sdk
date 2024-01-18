use axum::http::StatusCode;
use std::borrow::Cow;

use sos_sdk::{
    constants::{ACCOUNT_CREATE, ACCOUNT_FETCH, DEVICE_PATCH, SYNC_STATUS},
    decode, encode,
    sync::{ChangeSet, SyncStorage},
};

use super::{PrivateState, Service};
use crate::{
    rpc::{RequestMessage, ResponseMessage},
    server::{Error, Result},
};
use async_trait::async_trait;

#[cfg(feature = "device")]
use sos_sdk::sync::DeviceDiff;

/// Account management service.
///
/// This service requires an account signature but **does not**
/// require a device signature.
///
/// * `Account.create`: Create a new account.
/// * `Account.fetch`: Fetch an existing account.
/// * `Device.patch`: Apply a patch to the devices event log.
/// * `Sync.status`: Account sync status.
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
            /*
            ACCOUNT_CREATE => {
                {
                    let reader = backend.read().await;
                    if reader.account_exists(caller.address()).await? {
                        return Ok(
                            (StatusCode::CONFLICT, request.id()).into()
                        );
                    }
                }

                let account: ChangeSet = decode(request.body()).await?;

                let mut writer = backend.write().await;
                writer.create_account(caller.address(), account).await?;

                let reply: ResponseMessage<'_> =
                    (request.id(), ()).try_into()?;

                Ok(reply)
            }
            ACCOUNT_FETCH => {
                let reader = backend.read().await;
                let account: ChangeSet =
                    reader.fetch_account(caller.address()).await?;
                let buffer = encode(&account).await?;
                let reply = ResponseMessage::new(
                    request.id(),
                    StatusCode::OK,
                    Some(Ok(())),
                    Cow::Owned(buffer),
                )?;
                Ok(reply)
            }
            */
            #[cfg(feature = "device")]
            DEVICE_PATCH => {
                let diff: DeviceDiff = decode(request.body()).await?;
                let reader = backend.read().await;
                reader.patch_devices(caller.address(), &diff).await?;
                let reply: ResponseMessage<'_> =
                    (request.id(), ()).try_into()?;
                Ok(reply)
            }
            /*
            SYNC_STATUS => {
                let account_exists = {
                    let reader = backend.read().await;
                    reader.account_exists(caller.address()).await?
                };

                let result = if account_exists {
                    let reader = backend.read().await;
                    let accounts = reader.accounts();
                    let reader = accounts.read().await;
                    let account = reader.get(caller.address()).unwrap();
                    let account = account.read().await;
                    Some(account.storage.sync_status().await?)
                } else {
                    None
                };

                let reply: ResponseMessage<'_> =
                    (request.id(), result).try_into()?;
                Ok(reply)
            }
            */
            _ => Err(Error::RpcUnknownMethod(request.method().to_owned())),
        }
    }
}
