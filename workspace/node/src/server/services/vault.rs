use axum::http::StatusCode;

use sos_core::{
    constants::{VAULT_CREATE, VAULT_DELETE, VAULT_SAVE},
    events::{ChangeEvent, ChangeNotification, EventKind},
    rpc::{RequestMessage, ResponseMessage, Service},
    vault::Header,
    AuditData, AuditEvent,
};

use async_trait::async_trait;
use uuid::Uuid;

use super::{append_audit_logs, send_notification, PrivateState};
use crate::server::Error;

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
    ) -> sos_core::Result<ResponseMessage<'a>> {
        let (caller, state) = state;

        match request.method() {
            VAULT_CREATE => {
                // Check it looks like a vault payload
                let summary = Header::read_summary_slice(request.body())?;

                let reader = state.read().await;
                let (exists, proof) = reader
                    .backend
                    .wal_exists(caller.address(), summary.id())
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
                        .create_wal(
                            caller.address(),
                            summary.id(),
                            request.body(),
                        )
                        .await
                        .map_err(Box::from)?;

                    let reply: ResponseMessage<'_> =
                        (request.id(), Some(&proof)).try_into()?;

                    let notification = ChangeNotification::new(
                        caller.address(),
                        summary.id(),
                        proof,
                        vec![ChangeEvent::CreateVault],
                    );

                    let log = AuditEvent::from_sync_event(
                        &sync_event,
                        *caller.address(),
                        *summary.id(),
                    );

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
                    .wal_exists(caller.address(), &vault_id)
                    .await
                    .map_err(Box::from)?;

                if !exists {
                    return Ok((StatusCode::NOT_FOUND, request.id()).into());
                }

                let proof =
                    proof.ok_or(Error::NoCommitProof).map_err(Box::from)?;

                writer
                    .backend
                    .delete_wal(caller.address(), &vault_id)
                    .await
                    .map_err(Box::from)?;

                let reply: ResponseMessage<'_> =
                    (request.id(), &proof).try_into()?;

                let notification = ChangeNotification::new(
                    caller.address(),
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
                    .wal_exists(caller.address(), summary.id())
                    .await
                    .map_err(Box::from)?;

                drop(reader);

                if !exists {
                    return Ok((StatusCode::NOT_FOUND, request.id()).into());
                }

                let mut writer = state.write().await;
                let (sync_event, proof) = writer
                    .backend
                    .set_vault(caller.address(), request.body())
                    .await
                    .map_err(Box::from)?;

                let reply: ResponseMessage<'_> =
                    (request.id(), Some(&proof)).try_into()?;

                let notification = ChangeNotification::new(
                    caller.address(),
                    summary.id(),
                    proof,
                    vec![ChangeEvent::UpdateVault],
                );

                let log = AuditEvent::from_sync_event(
                    &sync_event,
                    *caller.address(),
                    *summary.id(),
                );

                append_audit_logs(&mut writer, vec![log])
                    .await
                    .map_err(Box::from)?;
                send_notification(&mut writer, &caller, notification);

                Ok(reply)
            }
            _ => Err(sos_core::Error::Message("unknown method".to_owned())),
        }
    }
}
