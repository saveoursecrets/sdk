use axum::http::StatusCode;

use sos_sdk::{
    constants::{VAULT_CREATE, VAULT_DELETE, VAULT_SAVE},
    events::{
        AuditData, AuditEvent, ChangeEvent, ChangeNotification, Event,
        EventKind,
    },
    rpc::{RequestMessage, ResponseMessage, Service},
    vault::Header,
};

use async_trait::async_trait;
use uuid::Uuid;

use super::{append_audit_logs, send_notification, PrivateState};
use crate::server::{BackendHandler, Error};

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
    ) -> sos_sdk::Result<ResponseMessage<'a>> {
        let (caller, state) = state;

        match request.method() {
            VAULT_CREATE => {
                // Check it looks like a vault payload
                let summary = Header::read_summary_slice(request.body())?;

                let reader = state.read().await;
                let (exists, proof) = reader
                    .backend
                    .handler()
                    .event_log_exists(caller.address(), summary.id())
                    .await
                    .map_err(Box::from)?;
                drop(reader);

                if exists {
                    // Send commit proof back with conflict response
                    Ok((StatusCode::CONFLICT, request.id(), proof)
                        .try_into()?)
                } else {
                    let mut writer = state.write().await;
                    let (sync_event, proof) = writer
                        .backend
                        .handler_mut()
                        .create_event_log(
                            caller.address(),
                            summary.id(),
                            request.body(),
                        )
                        .await
                        .map_err(Box::from)?;

                    let reply: ResponseMessage<'_> =
                        (request.id(), Some(&proof)).try_into()?;

                    let vault_id = *summary.id();

                    let notification = ChangeNotification::new(
                        caller.address(),
                        caller.session_id(),
                        &vault_id,
                        proof,
                        vec![ChangeEvent::CreateVault(summary)],
                    );

                    let event = Event::Write(vault_id, sync_event);
                    let log: AuditEvent = (caller.address(), &event).into();

                    append_audit_logs(&mut writer, vec![log])
                        .await
                        .map_err(Box::from)?;
                    send_notification(&mut writer, &caller, notification);

                    Ok(reply)
                }
            }
            VAULT_DELETE => {
                let vault_id = request.parameters::<Uuid>()?;

                let mut writer = state.write().await;
                let (exists, proof) = writer
                    .backend
                    .handler()
                    .event_log_exists(caller.address(), &vault_id)
                    .await
                    .map_err(Box::from)?;

                if !exists {
                    return Ok((StatusCode::NOT_FOUND, request.id()).into());
                }

                let proof =
                    proof.ok_or(Error::NoCommitProof).map_err(Box::from)?;

                writer
                    .backend
                    .handler_mut()
                    .delete_event_log(caller.address(), &vault_id)
                    .await
                    .map_err(Box::from)?;

                let reply: ResponseMessage<'_> =
                    (request.id(), &proof).try_into()?;

                let notification = ChangeNotification::new(
                    caller.address(),
                    caller.session_id(),
                    &vault_id,
                    proof,
                    vec![ChangeEvent::DeleteVault],
                );

                let log = AuditEvent::new(
                    EventKind::DeleteVault,
                    *caller.address(),
                    Some(AuditData::Vault(vault_id)),
                );

                append_audit_logs(&mut writer, vec![log])
                    .await
                    .map_err(Box::from)?;
                send_notification(&mut writer, &caller, notification);

                Ok(reply)
            }
            VAULT_SAVE => {
                let vault_id = request.parameters::<Uuid>()?;

                // Check it looks like a vault payload
                let summary = Header::read_summary_slice(request.body())?;

                if &vault_id != summary.id() {
                    return Ok((StatusCode::BAD_REQUEST, request.id()).into());
                }

                let reader = state.read().await;
                let (exists, _) = reader
                    .backend
                    .handler()
                    .event_log_exists(caller.address(), summary.id())
                    .await
                    .map_err(Box::from)?;

                drop(reader);

                if !exists {
                    return Ok((StatusCode::NOT_FOUND, request.id()).into());
                }

                let mut writer = state.write().await;
                let (sync_event, proof) = writer
                    .backend
                    .handler_mut()
                    .set_vault(caller.address(), request.body())
                    .await
                    .map_err(Box::from)?;

                let reply: ResponseMessage<'_> =
                    (request.id(), Some(&proof)).try_into()?;

                let notification = ChangeNotification::new(
                    caller.address(),
                    caller.session_id(),
                    summary.id(),
                    proof,
                    vec![ChangeEvent::UpdateVault],
                );

                let event = Event::Write(vault_id, sync_event);
                let log: AuditEvent = (caller.address(), &event).into();

                append_audit_logs(&mut writer, vec![log])
                    .await
                    .map_err(Box::from)?;
                send_notification(&mut writer, &caller, notification);

                Ok(reply)
            }
            _ => Err(sos_sdk::Error::RpcUnknownMethod(
                request.method().to_owned(),
            )),
        }
    }
}
