use sos_sdk::{constants::DEVICE_REVOKE, device::DevicePublicKey};

use async_trait::async_trait;

use super::{PrivateState, Service};
use crate::{
    rpc::{RequestMessage, ResponseMessage},
    server::{Error, Result},
};

/// Device management service for an account.
///
/// This service is restricted; it requires account
/// and device signatures.
///
/// * `Device.revoke`: Revoke trust in a device public key.
pub struct DeviceService;

#[async_trait]
impl Service for DeviceService {
    type State = PrivateState;

    async fn handle<'a>(
        &self,
        state: Self::State,
        request: RequestMessage<'a>,
    ) -> Result<ResponseMessage<'a>> {
        let (caller, (_state, backend)) = state;

        match request.method() {
            DEVICE_REVOKE => {
                let device_public_key =
                    request.parameters::<DevicePublicKey>()?;
                let mut writer = backend.write().await;
                let result = writer
                    .revoke_device(caller.address(), device_public_key)
                    .await?;
                let reply: ResponseMessage<'_> =
                    (request.id(), result).try_into()?;
                Ok(reply)
            }
            _ => Err(Error::RpcUnknownMethod(request.method().to_owned())),
        }
    }
}
