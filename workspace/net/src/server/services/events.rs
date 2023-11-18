use axum::http::StatusCode;
use sos_sdk::{
    commit::{CommitHash, CommitProof, Comparison},
    constants::{
        EVENT_LOG_DIFF, EVENT_LOG_LOAD, EVENT_LOG_PATCH, EVENT_LOG_SAVE,
        EVENT_LOG_STATUS,
    },
    decode, encode,
    events::{
        AuditData, AuditEvent, ChangeEvent, ChangeNotification, Event,
        EventKind, Patch, WriteEvent,
    },
    rpc::{RequestMessage, ResponseMessage, Service},
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

/// Event log management service.
///
/// * `Events.load`: Load the events for a vault.
/// * `Events.patch`: Apply a patch to the event log for a vault.
/// * `Events.diff`: Get patch of events on the remote that differ from a local vault.
/// * `Events.save`: Save an event log buffer.
///
pub struct EventLogService;

#[async_trait]
impl Service for EventLogService {
    type State = PrivateState;

    async fn handle<'a>(
        &self,
        state: Self::State,
        request: RequestMessage<'a>,
    ) -> sos_sdk::Result<ResponseMessage<'a>> {
        let (caller, state) = state;

        match request.method() {
            EVENT_LOG_LOAD => {
                let (vault_id, commit_proof) =
                    request.parameters::<(Uuid, Option<CommitProof>)>()?;

                let reader = state.read().await;
                let (exists, _) = reader
                    .backend
                    .handler()
                    .event_log_exists(caller.address(), &vault_id)
                    .await
                    .map_err(Box::from)?;
                drop(reader);

                if !exists {
                    return Ok((StatusCode::NOT_FOUND, request.id()).into());
                }

                let reader = state.read().await;

                let event_log = reader
                    .backend
                    .event_log_read(caller.address(), &vault_id)
                    .await
                    .map_err(Box::from)?;

                let proof = event_log.tree().head().map_err(Box::from)?;

                tracing::debug!(root = %proof.root_hex(),
                    "get_event_log server root");

                // Client is asking for data from a specific commit hash
                let result = if let Some(proof) = commit_proof {
                    //let proof: CommitProof = proof.into();

                    tracing::debug!(root = %proof.root_hex(),
                        "get_event_log client root");

                    let comparison = event_log
                        .tree()
                        .compare(&proof)
                        .map_err(Box::from)?;

                    match comparison {
                        Comparison::Equal => {
                            Ok((StatusCode::NOT_MODIFIED, vec![]))
                        }
                        Comparison::Contains(_, mut leaves) => {
                            if leaves.len() == 1 {
                                let leaf = leaves.remove(0);
                                if let Some(partial) = event_log
                                    .diff(leaf)
                                    .await
                                    .map_err(Box::from)?
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
                // Otherwise get the entire event log buffer
                } else if let Ok(buffer) = reader
                    .backend
                    .handler()
                    .get_event_log(caller.address(), &vault_id)
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
                                EventKind::ReadEventLog,
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
            EVENT_LOG_STATUS => {
                let (vault_id, commit_proof) =
                    request.parameters::<(Uuid, Option<CommitProof>)>()?;

                let reader = state.read().await;

                let (exists, _) = reader
                    .backend
                    .handler()
                    .event_log_exists(caller.address(), &vault_id)
                    .await
                    .map_err(Box::from)?;

                if !exists {
                    return Ok((StatusCode::NOT_FOUND, request.id()).into());
                }

                let event_log = reader
                    .backend
                    .event_log_read(caller.address(), &vault_id)
                    .await
                    .map_err(Box::from)?;

                let proof = event_log.tree().head().map_err(Box::from)?;

                let match_proof = if let Some(client_proof) = commit_proof {
                    event_log
                        .tree()
                        .contains(&client_proof)
                        .map_err(Box::from)?
                } else {
                    None
                };

                let reply: ResponseMessage<'_> =
                    (request.id(), (proof, match_proof)).try_into()?;
                Ok(reply)
            }
            EVENT_LOG_DIFF => {
                let (vault_id, last_commit, client_proof) = request
                    .parameters::<(Uuid, CommitHash, CommitProof)>()?;

                let reader = state.read().await;

                let (exists, _) = reader
                    .backend
                    .handler()
                    .event_log_exists(caller.address(), &vault_id)
                    .await
                    .map_err(Box::from)?;

                if !exists {
                    return Ok((StatusCode::NOT_FOUND, request.id()).into());
                }

                let event_log = reader
                    .backend
                    .event_log_read(caller.address(), &vault_id)
                    .await
                    .map_err(Box::from)?;

                let proof = event_log.tree().head().map_err(Box::from)?;

                let comparison = event_log
                    .tree()
                    .compare(&client_proof)
                    .map_err(Box::from)?;

                let patch: Option<Patch> = match comparison {
                    Comparison::Equal => Some(Default::default()),
                    Comparison::Contains(_indices, _leaves) => {
                        let match_proof = event_log
                            .tree()
                            .contains(&client_proof)
                            .map_err(Box::from)?;

                        if match_proof.is_some() {
                            Some(
                                event_log
                                    .patch_until(Some(&last_commit))
                                    .await?,
                            )
                        } else {
                            None
                        }
                    }
                    Comparison::Unknown => None,
                };

                if let Some(patch) = patch {
                    let buffer = encode(&patch).await?;
                    let reply = ResponseMessage::new(
                        request.id(),
                        StatusCode::OK,
                        Some(Ok(patch.0.len())),
                        Cow::Owned(buffer),
                    )?;
                    Ok(reply)
                } else {
                    Ok((StatusCode::CONFLICT, request.id()).into())
                }
            }
            EVENT_LOG_PATCH => {
                let (vault_id, commit_proof) =
                    request.parameters::<(Uuid, CommitProof)>()?;

                let reader = state.read().await;
                let (exists, _) = reader
                    .backend
                    .handler()
                    .event_log_exists(caller.address(), &vault_id)
                    .await
                    .map_err(Box::from)?;
                drop(reader);
                if !exists {
                    return Ok((StatusCode::NOT_FOUND, request.id()).into());
                }

                let result: sos_sdk::Result<PatchResult> = {
                    let mut writer = state.write().await;

                    let event_log = writer
                        .backend
                        .event_log_write(caller.address(), &vault_id)
                        .await
                        .map_err(Box::from)?;

                    let comparison = event_log
                        .tree()
                        .compare(&commit_proof)
                        .map_err(Box::from)?;

                    match comparison {
                        Comparison::Equal => {
                            // TODO: |_| StatusCode::BAD_REQUEST
                            let patch: Patch = decode(request.body())
                                .await
                                .map_err(Box::from)?;

                            let mut change_set = Vec::new();
                            for record in &patch.0 {
                                change_set.push(record.decode_event().await?);
                            }

                            // Setting vault name requires special handling
                            // as we need to update the vault header on disc
                            // as well so summary listings are kept up to date
                            let vault_name =
                                change_set.iter().find_map(|event| {
                                    if let WriteEvent::SetVaultName(name) =
                                        event
                                    {
                                        Some(name.to_string())
                                    } else {
                                        None
                                    }
                                });

                            // Changes events for the SSE channel
                            let mut change_events: Vec<ChangeEvent> =
                                Vec::new();
                            for event in change_set.iter() {
                                let event =
                                    ChangeEvent::try_from_write_event(event)
                                        .await;
                                if event.is_ok() {
                                    change_events.push(event?);
                                }
                            }

                            // Audit log events
                            let audit_logs: Vec<AuditEvent> = change_set
                                .iter()
                                .map(|event| {
                                    let event = Event::Write(
                                        vault_id.clone(),
                                        event.clone(),
                                    );
                                    (caller.address(), &event).into()
                                })
                                .collect();

                            // Changes to apply to the event log
                            let mut changes = Vec::new();
                            for event in change_set {
                                changes.push(event);
                            }

                            // Apply the change set of event log events to the log
                            let commits = event_log
                                .apply(changes, None)
                                .await
                                .map_err(Box::from)?;

                            // Get a new commit proof for the last leaf hash
                            let proof =
                                event_log.tree().head().map_err(Box::from)?;

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
                                event_log.tree().head().map_err(Box::from)?;
                            // Prepare the proof that this event log contains the
                            // matched leaf node
                            let match_proof = event_log
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
                                event_log.tree().head().map_err(Box::from)?;
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
                            caller.public_key(),
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
            EVENT_LOG_SAVE => {
                let (vault_id, commit_proof) =
                    request.parameters::<(Uuid, CommitProof)>()?;

                let reader = state.read().await;
                let (exists, _) = reader
                    .backend
                    .handler()
                    .event_log_exists(caller.address(), &vault_id)
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
                    .replace_event_log(
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
