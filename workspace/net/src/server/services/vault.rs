use axum::http::StatusCode;

use sos_sdk::{
    constants::{VAULT_CREATE, VAULT_DELETE, VAULT_SAVE},
    crypto::SecureAccessKey,
    events::{AuditData, AuditEvent, Event, EventKind},
    vault::Header,
};

use async_trait::async_trait;
use uuid::Uuid;

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
                let secure_key =
                    request.parameters::<Option<SecureAccessKey>>()?;

                // Check it looks like a vault payload
                let summary =
                    Header::read_summary_slice(request.body()).await?;

                let reader = backend.read().await;
                let (exists, proof) = reader
                    .handler()
                    .folder_exists(caller.address(), summary.id())
                    .await?;
                drop(reader);

                if exists {
                    // Send commit proof back with conflict response
                    Ok((StatusCode::CONFLICT, request.id(), proof)
                        .try_into()?)
                } else {
                    let mut writer = backend.write().await;
                    let (sync_event, proof) = writer
                        .handler_mut()
                        .create_folder(
                            caller.address(),
                            summary.id(),
                            request.body(),
                        )
                        .await?;

                    let reply: ResponseMessage<'_> =
                        (request.id(), Some(&proof)).try_into()?;

                    let vault_id = *summary.id();

                    #[cfg(feature = "listen")]
                    let notification = ChangeNotification::new(
                        caller.address(),
                        caller.public_key(),
                        &vault_id,
                        proof,
                        vec![ChangeEvent::CreateVault(summary, secure_key)],
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
            }
            VAULT_DELETE => {
                let vault_id = request.parameters::<Uuid>()?;

                let proof = {
                    let reader = backend.read().await;
                    let (exists, proof) = reader
                        .handler()
                        .folder_exists(caller.address(), &vault_id)
                        .await?;

                    if !exists {
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
                let notification = ChangeNotification::new(
                    caller.address(),
                    caller.public_key(),
                    &vault_id,
                    proof,
                    vec![ChangeEvent::DeleteVault],
                );

                let log = AuditEvent::new(
                    EventKind::DeleteVault,
                    *caller.address(),
                    Some(AuditData::Vault(vault_id)),
                );

                {
                    let mut writer = state.write().await;
                    append_audit_logs(&mut writer, vec![log]).await?;

                    #[cfg(feature = "listen")]
                    send_notification(&mut writer, &caller, notification);
                }

                Ok(reply)
            }
            VAULT_SAVE => {
                let vault_id = request.parameters::<Uuid>()?;

                // Check it looks like a vault payload
                let summary =
                    Header::read_summary_slice(request.body()).await?;

                if &vault_id != summary.id() {
                    return Ok((StatusCode::BAD_REQUEST, request.id()).into());
                }

                {
                    let reader = backend.read().await;
                    let (exists, _) = reader
                        .handler()
                        .folder_exists(caller.address(), summary.id())
                        .await?;
                    if !exists {
                        return Ok(
                            (StatusCode::NOT_FOUND, request.id()).into()
                        );
                    }
                }

                let mut writer = backend.write().await;
                let (sync_event, proof) = writer
                    .handler_mut()
                    .import_folder(caller.address(), request.body())
                    .await?;

                let reply: ResponseMessage<'_> =
                    (request.id(), Some(&proof)).try_into()?;

                let vault_id = *summary.id();

                #[cfg(feature = "listen")]
                let notification = ChangeNotification::new(
                    caller.address(),
                    caller.public_key(),
                    &vault_id,
                    proof,
                    vec![ChangeEvent::UpdateVault(summary)],
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
            _ => Err(Error::RpcUnknownMethod(request.method().to_owned())),
        }
    }
}
