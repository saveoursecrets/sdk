use axum::http::StatusCode;
use sos_sdk::{
    audit::{AuditData, AuditEvent},
    commit::{CommitHash, CommitProof, Comparison},
    constants::{WAL_LOAD, WAL_PATCH, WAL_SAVE, WAL_STATUS},
    decode,
    events::{ChangeEvent, ChangeNotification, EventKind, SyncEvent},
    patch::Patch,
    rpc::{RequestMessage, ResponseMessage, Service},
    wal::WalProvider,
};
use web3_address::ethereum::Address;

use async_trait::async_trait;
use std::borrow::Cow;
use uuid::Uuid;

use super::{append_audit_logs, send_notification, PrivateState};
use crate::server::BackendHandler;

enum PatchResult {
    Conflict(CommitProof, Option<CommitProof>),
    Success(
        Address,
        Vec<AuditEvent>,
        Vec<ChangeEvent>,
        Vec<CommitHash>,
        CommitProof,
        Option<String>,
    ),
}

/// WAL management service.
///
/// * `Wal.load`: Load the WAL for a vault.
/// * `Wal.patch`: Apply a patch to the WAL for a vault.
/// * `Wal.save`: Save a WAL buffer.
///
pub struct WalService;

#[async_trait]
impl Service for WalService {
    type State = PrivateState;

    async fn handle<'a>(
        &self,
        state: Self::State,
        request: RequestMessage<'a>,
    ) -> sos_sdk::Result<ResponseMessage<'a>> {
        let (caller, state) = state;

        match request.method() {
            WAL_LOAD => {
                let (vault_id, commit_proof) =
                    request.parameters::<(Uuid, Option<CommitProof>)>()?;

                let reader = state.read().await;
                let (exists, _) = reader
                    .backend
                    .handler()
                    .wal_exists(caller.address(), &vault_id)
                    .await
                    .map_err(Box::from)?;
                drop(reader);

                if !exists {
                    return Ok((StatusCode::NOT_FOUND, request.id()).into());
                }

                let reader = state.read().await;

                let wal = reader
                    .backend
                    .wal_read(caller.address(), &vault_id)
                    .await
                    .map_err(Box::from)?;

                let proof = wal.tree().head().map_err(Box::from)?;

                tracing::debug!(root = %proof.root_hex(),
                    "get_wal server root");

                // Client is asking for data from a specific commit hash
                let result = if let Some(proof) = commit_proof {
                    //let proof: CommitProof = proof.into();

                    tracing::debug!(root = %proof.root_hex(),
                        "get_wal client root");

                    let comparison =
                        wal.tree().compare(&proof).map_err(Box::from)?;

                    match comparison {
                        Comparison::Equal => {
                            Ok((StatusCode::NOT_MODIFIED, vec![]))
                        }
                        Comparison::Contains(_, mut leaves) => {
                            if leaves.len() == 1 {
                                let leaf = leaves.remove(0);
                                if let Some(partial) =
                                    wal.diff(leaf).map_err(Box::from)?
                                {
                                    Ok((StatusCode::OK, partial))
                                // Could not find a record corresponding
                                // to the leaf node
                                } else {
                                    Ok((StatusCode::CONFLICT, vec![]))
                                }
                            } else {
                                Err(StatusCode::BAD_REQUEST)
                            }
                        }
                        // Could not find leaf node in the commit tree
                        Comparison::Unknown => {
                            Ok((StatusCode::CONFLICT, vec![]))
                        }
                    }
                // Otherwise get the entire WAL buffer
                } else if let Ok(buffer) = reader
                    .backend
                    .handler()
                    .get_wal(caller.address(), &vault_id)
                    .await
                {
                    Ok((StatusCode::OK, buffer))
                } else {
                    Err(StatusCode::INTERNAL_SERVER_ERROR)
                };

                drop(reader);

                match result {
                    Ok((status, buffer)) => {
                        if status == StatusCode::OK {
                            let mut writer = state.write().await;
                            let log = AuditEvent::new(
                                EventKind::ReadWal,
                                caller.address,
                                Some(AuditData::Vault(vault_id)),
                            );
                            append_audit_logs(&mut writer, vec![log])
                                .await
                                .map_err(Box::from)?;
                        }

                        let reply = ResponseMessage::new(
                            request.id(),
                            status,
                            Some(Ok(Some(&proof))),
                            Cow::Owned(buffer),
                        )?;
                        Ok(reply)
                    }
                    Err(status) => Ok((status, request.id()).into()),
                }
            }
            WAL_STATUS => {
                let (vault_id, commit_proof) =
                    request.parameters::<(Uuid, Option<CommitProof>)>()?;

                let reader = state.read().await;

                let (exists, _) = reader
                    .backend
                    .handler()
                    .wal_exists(caller.address(), &vault_id)
                    .await
                    .map_err(Box::from)?;

                if !exists {
                    return Ok((StatusCode::NOT_FOUND, request.id()).into());
                }

                let wal = reader
                    .backend
                    .wal_read(caller.address(), &vault_id)
                    .await
                    .map_err(Box::from)?;

                let proof = wal.tree().head().map_err(Box::from)?;

                let match_proof = if let Some(client_proof) = commit_proof {
                    wal.tree().contains(&client_proof).map_err(Box::from)?
                } else {
                    None
                };

                let reply: ResponseMessage<'_> =
                    (request.id(), (proof, match_proof)).try_into()?;
                Ok(reply)
            }
            WAL_PATCH => {
                let (vault_id, commit_proof) =
                    request.parameters::<(Uuid, CommitProof)>()?;

                let reader = state.read().await;
                let (exists, _) = reader
                    .backend
                    .handler()
                    .wal_exists(caller.address(), &vault_id)
                    .await
                    .map_err(Box::from)?;
                drop(reader);
                if !exists {
                    return Ok((StatusCode::NOT_FOUND, request.id()).into());
                }

                let result: sos_sdk::Result<PatchResult> = {
                    let mut writer = state.write().await;

                    let wal = writer
                        .backend
                        .wal_write(caller.address(), &vault_id)
                        .await
                        .map_err(Box::from)?;

                    let comparison = wal
                        .tree()
                        .compare(&commit_proof)
                        .map_err(Box::from)?;

                    match comparison {
                        Comparison::Equal => {
                            // TODO: |_| StatusCode::BAD_REQUEST
                            let patch: Patch<'static> =
                                decode(request.body()).map_err(Box::from)?;

                            let change_set = patch.0;

                            // Setting vault name requires special handling
                            // as we need to update the vault header on disc
                            // as well so summary listings are kept up to date
                            let vault_name =
                                change_set.iter().find_map(|event| {
                                    if let SyncEvent::SetVaultName(name) =
                                        event
                                    {
                                        Some(name.to_string())
                                    } else {
                                        None
                                    }
                                });

                            // Audit log events
                            let audit_logs = change_set
                                .iter()
                                .map(|event| {
                                    AuditEvent::from_sync_event(
                                        event,
                                        caller.address,
                                        vault_id,
                                    )
                                })
                                .collect::<Vec<_>>();

                            // Changes events for the SSE channel
                            let change_events = change_set
                                .iter()
                                .filter_map(|event| {
                                    ChangeEvent::from_sync_event(event)
                                })
                                .collect::<Vec<_>>();

                            // Changes to apply to the WAL log
                            let mut changes = Vec::new();
                            for event in change_set {
                                changes.push(event);
                            }

                            // Apply the change set of WAL events to the log
                            let commits = wal
                                .apply(changes, None)
                                .map_err(Box::from)?;

                            // Get a new commit proof for the last leaf hash
                            let proof =
                                wal.tree().head().map_err(Box::from)?;

                            Ok(PatchResult::Success(
                                caller.address,
                                audit_logs,
                                change_events,
                                commits,
                                proof,
                                vault_name,
                            ))
                        }
                        Comparison::Contains(indices, _leaves) => {
                            let proof =
                                wal.tree().head().map_err(Box::from)?;
                            // Prepare the proof that this WAL contains the
                            // matched leaf node
                            let match_proof = wal
                                .tree()
                                .proof(&indices)
                                .map_err(Box::from)?;
                            Ok(PatchResult::Conflict(
                                proof,
                                Some(match_proof),
                            ))
                        }
                        Comparison::Unknown => {
                            let proof =
                                wal.tree().head().map_err(Box::from)?;
                            Ok(PatchResult::Conflict(proof, None))
                        }
                    }
                };

                match result? {
                    PatchResult::Success(
                        address,
                        logs,
                        change_events,
                        _commits,
                        proof,
                        name,
                    ) => {
                        let mut writer = state.write().await;

                        // Must update the vault name in it's summary
                        if let Some(name) = name {
                            writer
                                .backend
                                .handler_mut()
                                .set_vault_name(&address, &vault_id, name)
                                .await
                                .map_err(Box::from)?;
                        }

                        // Append audit logs
                        append_audit_logs(&mut writer, logs)
                            .await
                            .map_err(Box::from)?;

                        let value: (&CommitProof, Option<CommitProof>) =
                            (&proof, None);
                        let reply: ResponseMessage<'_> =
                            (request.id(), value).try_into()?;

                        let notification = ChangeNotification::new(
                            &address,
                            caller.session_id(),
                            &vault_id,
                            proof,
                            change_events,
                        );

                        // Send notifications on the SSE channel
                        send_notification(&mut writer, &caller, notification);

                        Ok(reply)
                    }
                    PatchResult::Conflict(proof, match_proof) => Ok((
                        StatusCode::CONFLICT,
                        request.id(),
                        (proof, match_proof),
                    )
                        .try_into()?),
                }
            }
            WAL_SAVE => {
                let (vault_id, commit_proof) =
                    request.parameters::<(Uuid, CommitProof)>()?;

                let reader = state.read().await;
                let (exists, _) = reader
                    .backend
                    .handler()
                    .wal_exists(caller.address(), &vault_id)
                    .await
                    .map_err(Box::from)?;
                drop(reader);
                if !exists {
                    return Ok((StatusCode::NOT_FOUND, request.id()).into());
                }

                let mut writer = state.write().await;
                // TODO: better error to status code mapping
                let server_proof = writer
                    .backend
                    .handler_mut()
                    .replace_wal(
                        caller.address(),
                        &vault_id,
                        commit_proof.root,
                        request.body(),
                    )
                    .await
                    .map_err(Box::from)?;

                let reply: ResponseMessage<'_> =
                    (request.id(), server_proof).try_into()?;
                Ok(reply)
            }
            _ => Err(sos_sdk::Error::RpcUnknownMethod(
                request.method().to_owned(),
            )),
        }
    }
}
