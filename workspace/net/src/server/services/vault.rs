use axum::http::StatusCode;

use sos_sdk::{
    constants::{VAULT_CREATE, VAULT_DELETE},
    vault::Header,
};

use async_trait::async_trait;
use uuid::Uuid;

use super::{PrivateState, Service};
use crate::{
    rpc::{RequestMessage, ResponseMessage},
    server::{BackendHandler, Error, Result},
};

#[cfg(feature = "listen")]
use crate::events::{ChangeEvent, ChangeNotification};

#[cfg(feature = "listen")]
use super::send_notification;

/// Vault management service.
///
/// * `Vault.create`: Create a new vault.
/// * `Vault.delete`: Delete a vault.
/// * `Vault.save`: Save a vault.
///
pub struct VaultService;

#[async_trait]
impl Service for VaultService {
    type State = PrivateState;

    async fn handle<'a>(
        &self,
        state: Self::State,
        request: RequestMessage<'a>,
    ) -> Result<ResponseMessage<'a>> {
        let (caller, (state, backend)) = state;

        match request.method() {
            VAULT_CREATE => {
                // Check it looks like a vault payload
                let summary =
                    Header::read_summary_slice(request.body()).await?;

                let (exists, proof) = {
                    let reader = backend.read().await;
                    reader
                        .handler()
                        .folder_exists(caller.address(), summary.id())
                        .await?
                };

                if exists.is_some() {
                    // Send commit proof back with conflict response
                    Ok((StatusCode::CONFLICT, request.id(), proof)
                        .try_into()?)
                } else {
                    let mut writer = backend.write().await;
                    let (event, proof) = writer
                        .handler_mut()
                        .create_folder(
                            caller.address(),
                            summary.id(),
                            request.body(),
                        )
                        .await?;

                    let reply: ResponseMessage<'_> =
                        (request.id(), &proof).try_into()?;

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

                    Ok(reply)
                }
            }
            VAULT_DELETE => {
                let vault_id = request.parameters::<Uuid>()?;

                let proof = {
                    let reader = backend.read().await;
                    let (exists, proof) = reader
                        .handler()
                        .folder_exists(caller.address(), &vault_id)
                        .await?;

                    if exists.is_none() {
                        return Ok(
                            (StatusCode::NOT_FOUND, request.id()).into()
                        );
                    }

                    proof.ok_or(Error::NoCommitProof)?
                };

                let mut writer = backend.write().await;
                writer
                    .handler_mut()
                    .delete_folder(caller.address(), &vault_id)
                    .await?;

                let reply: ResponseMessage<'_> =
                    (request.id(), &proof).try_into()?;

                #[cfg(feature = "listen")]
                {
                    let notification = ChangeNotification::new(
                        caller.address(),
                        caller.public_key(),
                        &vault_id,
                        proof,
                        vec![ChangeEvent::DeleteVault],
                    );

                    let mut writer = state.write().await;
                    send_notification(&mut writer, &caller, notification);
                }

                Ok(reply)
            }
            _ => Err(Error::RpcUnknownMethod(request.method().to_owned())),
        }
    }
}
