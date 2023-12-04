use axum::http::StatusCode;
use sos_sdk::{
    commit::{CommitHash, CommitProof, Comparison},
    constants::{
        EVENT_LOG_DIFF, EVENT_LOG_LOAD, EVENT_LOG_PATCH, EVENT_LOG_STATUS,
    },
    decode, encode,
    events::{AuditData, AuditEvent, Event, EventKind, WriteEvent},
};
use web3_address::ethereum::Address;

use async_trait::async_trait;
use std::{borrow::Cow, sync::Arc};
use uuid::Uuid;

use super::Service;
use super::{append_audit_logs, PrivateState};
use crate::{
    events::Patch,
    rpc::{RequestMessage, ResponseMessage},
    server::{BackendHandler, Error, Result},
};

#[cfg(feature = "listen")]
use crate::events::{ChangeEvent, ChangeNotification};

#[cfg(feature = "listen")]
use super::send_notification;

enum PatchResult {
    Conflict(CommitProof, Option<CommitProof>),
    Success {
        address: Address,
        audit_logs: Vec<AuditEvent>,
        #[cfg(feature = "listen")]
        change_events: Vec<ChangeEvent>,
        commits: Vec<CommitHash>,
        proof: CommitProof,
        vault_name: Option<String>,
    },
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
    ) -> Result<ResponseMessage<'a>> {
        let (caller, (state, backend)) = state;

        match request.method() {
            EVENT_LOG_LOAD => {
                let vault_id = request.parameters::<Uuid>()?;

                {
                    let reader = backend.read().await;
                    let (exists, _) = reader
                        .handler()
                        .folder_exists(caller.address(), &vault_id)
                        .await?;

                    if !exists {
                        return Ok(
                            (StatusCode::NOT_FOUND, request.id()).into()
                        );
                    }
                }

                let proof = {
                    let reader = backend.read().await;
                    let accounts = reader.accounts();
                    let reader = accounts.read().await;
                    let account = reader
                        .get(caller.address())
                        .ok_or_else(|| Error::NoAccount(*caller.address()))?;

                    let account = account.read().await;
                    let folder = account
                        .folders
                        .find(|s| s.id() == &vault_id)
                        .ok_or_else(|| {
                            Error::NoFolder(*caller.address(), vault_id)
                        })?;

                    let (_, proof) =
                        account.folders.commit_state(&folder).await?;
                    proof
                };

                let result = {
                    let reader = backend.read().await;
                    // Otherwise get the entire event log buffer
                    if let Ok(buffer) = reader
                        .handler()
                        .read_events_buffer(caller.address(), &vault_id)
                        .await
                    {
                        Ok((StatusCode::OK, buffer))
                    } else {
                        Err(StatusCode::INTERNAL_SERVER_ERROR)
                    }
                };

                match result {
                    Ok((status, buffer)) => {
                        if status == StatusCode::OK {
                            let mut writer = state.write().await;
                            let log = AuditEvent::new(
                                EventKind::ReadEventLog,
                                caller.address,
                                Some(AuditData::Vault(vault_id)),
                            );
                            append_audit_logs(&mut writer, vec![log]).await?;
                        }

                        let reply = ResponseMessage::new(
                            request.id(),
                            status,
                            Some(Ok(&proof)),
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

                {
                    let reader = backend.read().await;
                    let (exists, _) = reader
                        .handler()
                        .folder_exists(caller.address(), &vault_id)
                        .await?;

                    if !exists {
                        return Ok(
                            (StatusCode::NOT_FOUND, request.id()).into()
                        );
                    }
                }

                let (last_commit, proof, match_proof) = {
                    let reader = backend.read().await;
                    let accounts = reader.accounts();
                    let reader = accounts.read().await;
                    let account = reader
                        .get(caller.address())
                        .ok_or_else(|| Error::NoAccount(*caller.address()))?;

                    let account = account.read().await;
                    let folder = account
                        .folders
                        .find(|s| s.id() == &vault_id)
                        .ok_or_else(|| {
                            Error::NoFolder(*caller.address(), vault_id)
                        })?;

                    let (last_commit, proof) =
                        account.folders.commit_state(&folder).await?;

                    let match_proof = if let Some(client_proof) = commit_proof
                    {
                        account
                            .folders
                            .commit_tree(&folder)
                            .unwrap()
                            .contains(&client_proof)?
                    } else {
                        None
                    };
                    (last_commit, proof, match_proof)
                };

                let reply: ResponseMessage<'_> =
                    (request.id(), (last_commit, proof, match_proof))
                        .try_into()?;
                Ok(reply)
            }
            EVENT_LOG_DIFF => {
                let (vault_id, last_commit, client_proof) = request
                    .parameters::<(Uuid, CommitHash, CommitProof)>()?;

                {
                    let reader = backend.read().await;
                    let (exists, _) = reader
                        .handler()
                        .folder_exists(caller.address(), &vault_id)
                        .await?;
                    if !exists {
                        return Ok(
                            (StatusCode::NOT_FOUND, request.id()).into()
                        );
                    }
                }

                let patch = {
                    let reader = backend.read().await;
                    let accounts = reader.accounts();
                    let reader = accounts.read().await;
                    let account = reader
                        .get(caller.address())
                        .ok_or_else(|| Error::NoAccount(*caller.address()))?;

                    let account = account.read().await;
                    let folder = account
                        .folders
                        .find(|s| s.id() == &vault_id)
                        .ok_or_else(|| {
                            Error::NoFolder(*caller.address(), vault_id)
                        })?;

                    let comparison = account
                        .folders
                        .commit_tree(&folder)
                        .unwrap()
                        .compare(&client_proof)?;

                    let patch: Option<Patch> = match comparison {
                        Comparison::Equal => Some(Default::default()),
                        Comparison::Contains(_indices, _leaves) => {
                            let match_proof = account
                                .folders
                                .commit_tree(&folder)
                                .unwrap()
                                .contains(&client_proof)?;

                            let event_log = account
                                .folders
                                .cache()
                                .get(folder.id())
                                .unwrap();

                            if match_proof.is_some() {
                                Some(
                                    event_log
                                        .patch_until(Some(&last_commit))
                                        .await?
                                        .into(),
                                )
                            } else {
                                None
                            }
                        }
                        Comparison::Unknown => None,
                    };

                    patch
                };

                if let Some(patch) = patch {
                    let buffer = encode(&patch).await?;
                    let reply = ResponseMessage::new(
                        request.id(),
                        StatusCode::OK,
                        Some(Ok(patch.len())),
                        Cow::Owned(buffer),
                    )?;
                    Ok(reply)
                } else {
                    Ok((StatusCode::CONFLICT, request.id()).into())
                }
            }
            EVENT_LOG_PATCH => {
                let (vault_id, before_proof) =
                    request.parameters::<(Uuid, CommitProof)>()?;

                {
                    let reader = backend.read().await;
                    let (exists, _) = reader
                        .handler()
                        .folder_exists(caller.address(), &vault_id)
                        .await?;
                    if !exists {
                        return Ok(
                            (StatusCode::NOT_FOUND, request.id()).into()
                        );
                    }
                }

                let result: Result<PatchResult> = {
                    // Clone the account so we can release
                    // the outer lock on the the backend and
                    // the account as soon as possible
                    let account = {
                        let reader = backend.read().await;
                        let accounts = reader.accounts();
                        let reader = accounts.read().await;
                        let account =
                            reader.get(caller.address()).ok_or_else(
                                || Error::NoAccount(*caller.address()),
                            )?;
                        Arc::clone(account)
                    };

                    let mut account = account.write().await;
                    let folder = account
                        .folders
                        .find(|s| s.id() == &vault_id)
                        .ok_or_else(|| {
                            Error::NoFolder(*caller.address(), vault_id)
                        })?;

                    let comparison = account
                        .folders
                        .commit_tree(&folder)
                        .unwrap()
                        .compare(&before_proof)?;

                    let folder_id = *folder.id();

                    match comparison {
                        Comparison::Equal => {
                            // TODO: |_| StatusCode::BAD_REQUEST
                            let patch: Patch = decode(request.body()).await?;

                            let mut change_set = Vec::new();
                            for record in patch.iter() {
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
                            #[cfg(feature = "listen")]
                            let change_events = {
                                let mut change_events: Vec<ChangeEvent> =
                                    Vec::new();
                                for event in change_set.iter() {
                                    let event =
                                        ChangeEvent::try_from_write_event(
                                            event,
                                        )
                                        .await;
                                    if event.is_ok() {
                                        change_events.push(event?);
                                    }
                                }
                                change_events
                            };

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

                            let event_log = account
                                .folders
                                .cache_mut()
                                .get_mut(&folder_id)
                                .unwrap();

                            // Apply the change set of events to the log
                            let commits = event_log
                                .apply(changes.iter().collect())
                                .await?;

                            // Get a new commit proof for the last leaf hash
                            let proof = event_log.tree().head()?;

                            Ok(PatchResult::Success {
                                address: caller.address,
                                audit_logs,
                                #[cfg(feature = "listen")]
                                change_events,
                                commits,
                                proof,
                                vault_name,
                            })
                        }
                        Comparison::Contains(indices, _leaves) => {
                            let tree =
                                account.folders.commit_tree(&folder).unwrap();

                            let proof = tree.head()?;
                            // Prepare the proof that this event log contains the
                            // matched leaf node
                            let match_proof = tree.proof(&indices)?;
                            Ok(PatchResult::Conflict(
                                proof,
                                Some(match_proof),
                            ))
                        }
                        Comparison::Unknown => {
                            let tree =
                                account.folders.commit_tree(&folder).unwrap();
                            let proof = tree.head()?;
                            Ok(PatchResult::Conflict(proof, None))
                        }
                    }
                };

                match result? {
                    PatchResult::Success {
                        address,
                        audit_logs: logs,
                        #[cfg(feature = "listen")]
                        change_events,
                        proof,
                        vault_name: name,
                        ..
                    } => {
                        // Must update the vault name in it's summary
                        if let Some(name) = name {
                            let mut writer = backend.write().await;
                            writer
                                .handler_mut()
                                .rename_folder(&address, &vault_id, name)
                                .await?;
                        }

                        let value: (&CommitProof, Option<CommitProof>) =
                            (&proof, None);
                        let reply: ResponseMessage<'_> =
                            (request.id(), value).try_into()?;

                        #[cfg(feature = "listen")]
                        let notification = ChangeNotification::new(
                            &address,
                            caller.public_key(),
                            &vault_id,
                            proof,
                            change_events,
                        );

                        {
                            let mut writer = state.write().await;
                            // Append audit logs
                            append_audit_logs(&mut writer, logs).await?;

                            // Send notifications on the SSE channel
                            #[cfg(feature = "listen")]
                            send_notification(
                                &mut writer,
                                &caller,
                                notification,
                            );
                        }

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
            _ => Err(Error::RpcUnknownMethod(request.method().to_owned())),
        }
    }
}
