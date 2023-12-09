use sos_sdk::{
    constants::{DEVICE_REVOKE, DEVICE_TRUST},
    device::DevicePublicKey,
};

use async_trait::async_trait;

use super::{PrivateState, Service};
use crate::{
    rpc::{RequestMessage, ResponseMessage},
    server::{BackendHandler, Error, Result},
};

/// Device management service for an account.
///
/// * `Device.trust`: Trust the public key of a device.
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
            DEVICE_TRUST => {
                let device_public_key =
                    request.parameters::<DevicePublicKey>()?;
                let mut writer = backend.write().await;
                let result = writer
                    .handler_mut()
                    .trust_device(caller.address(), device_public_key)
                    .await?;
                let reply: ResponseMessage<'_> =
                    (request.id(), result).try_into()?;
                Ok(reply)
            }
            DEVICE_REVOKE => {
                let device_public_key =
                    request.parameters::<DevicePublicKey>()?;
                let mut writer = backend.write().await;
                let result = writer
                    .handler_mut()
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
