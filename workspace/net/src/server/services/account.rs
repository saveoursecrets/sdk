use axum::http::StatusCode;

use sos_sdk::{
    constants::ACCOUNT_CREATE,
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

/// Account management service.
///
/// * `Account.create`: Create a new account.
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

                Ok(reply)
            }
            _ => Err(Error::RpcUnknownMethod(request.method().to_owned())),
        }
    }
}
