use axum::http::StatusCode;

use sos_sdk::{
    constants::{ACCOUNT_CREATE, DEVICE_TRUST, SYNC_STATUS},
    decode,
    device::DevicePublicKey,
    sync::{ChangeSet, SyncStorage},
};

use async_trait::async_trait;

use super::{PrivateState, Service};
use crate::{
    rpc::{RequestMessage, ResponseMessage},
    server::{Error, Result},
};

/// Account management service.
///
/// This service requires an account signature but **does not**
/// require a device signature.
///
/// * `Account.create`: Create a new account.
/// * `Device.trust`: Trust the public key of a device.
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
            ACCOUNT_CREATE => {
                {
                    let reader = backend.read().await;
                    if reader.account_exists(caller.address()).await? {
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
                    .create_account(
                        caller.address(),
                        account,
                        device_public_key,
                    )
                    .await?;

                let reply: ResponseMessage<'_> =
                    (request.id(), ()).try_into()?;

                Ok(reply)
            }
            DEVICE_TRUST => {
                let device_public_key =
                    request.parameters::<DevicePublicKey>()?;
                let mut writer = backend.write().await;
                let result = writer
                    .trust_device(caller.address(), device_public_key)
                    .await?;
                let reply: ResponseMessage<'_> =
                    (request.id(), result).try_into()?;
                Ok(reply)
            }
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
            _ => Err(Error::RpcUnknownMethod(request.method().to_owned())),
        }
    }
}
