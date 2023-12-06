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

use super::{PrivateState, Service};
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
        change_set: Vec<WriteEvent>,
        proof: CommitProof,
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

                    if exists.is_none() {
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

                    if exists.is_none() {
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
                    if exists.is_none() {
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
                    if exists.is_none() {
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

                    let (folder, comparison) = {
                        let account = account.read().await;
                        let folder = account
                            .folders
                            .find(|s| s.id() == &vault_id)
                            .cloned()
                            .ok_or_else(|| {
                                Error::NoFolder(*caller.address(), vault_id)
                            })?;

                        let comparison = account
                            .folders
                            .commit_tree(&folder)
                            .unwrap()
                            .compare(&before_proof)?;

                        (folder, comparison)
                    };

                    match comparison {
                        Comparison::Equal => {
                            // TODO: |_| StatusCode::BAD_REQUEST
                            let patch: Patch = decode(request.body()).await?;

                            let mut account = account.write().await;
                            let mut change_set = Vec::new();
                            for record in patch.iter() {
                                let event = record.decode_event().await?;

                                // Setting vault name requires special
                                // handling as we need to update the
                                // vault header on disc and must be
                                // performed here so that the new
                                // commit proof computation is included
                                // in change notifications
                                if let WriteEvent::SetVaultName(name) = &event
                                {
                                    account
                                        .folders
                                        .rename_folder(
                                            &folder,
                                            name.to_owned(),
                                        )
                                        .await?;
                                } else {
                                    let event_log = account
                                        .folders
                                        .cache_mut()
                                        .get_mut(folder.id())
                                        .unwrap();
                                    event_log.apply(vec![&event]).await?;
                                }

                                change_set.push(event);
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

                            // Get a new commit proof after applying changes
                            let event_log = account
                                .folders
                                .cache_mut()
                                .get_mut(folder.id())
                                .unwrap();
                            let proof = event_log.tree().head()?;

                            account
                                .folders
                                .paths()
                                .append_audit_events(audit_logs)
                                .await?;

                            Ok(PatchResult::Success {
                                address: caller.address,
                                #[cfg(feature = "listen")]
                                change_set,
                                proof,
                            })
                        }
                        Comparison::Contains(indices, _leaves) => {
                            let account = account.read().await;
                            let tree =
                                account.folders.commit_tree(&folder).unwrap();

                            let proof = tree.head()?;
                            // Prepare the proof that this event
                            // log contains the matched leaf node
                            let match_proof = tree.proof(&indices)?;
                            Ok(PatchResult::Conflict(
                                proof,
                                Some(match_proof),
                            ))
                        }
                        Comparison::Unknown => {
                            let account = account.read().await;
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
                        #[cfg(feature = "listen")]
                        change_set,
                        proof,
                        ..
                    } => {
                        let value: (&CommitProof, Option<CommitProof>) =
                            (&proof, None);
                        let reply: ResponseMessage<'_> =
                            (request.id(), value).try_into()?;

                        #[cfg(feature = "listen")]
                        {
                            let notification = {
                                // Note that we must compute the change
                                // events after setting the folder name
                                // so the commit proof is correct
                                let mut change_events = Vec::new();
                                for event in &change_set {
                                    let event =
                                        ChangeEvent::try_from_write_event(
                                            event,
                                        )
                                        .await;
                                    if event.is_ok() {
                                        change_events.push(event?);
                                    }
                                }

                                ChangeNotification::new(
                                    &address,
                                    caller.public_key(),
                                    &vault_id,
                                    proof,
                                    change_events,
                                )
                            };
                            let mut writer = state.write().await;
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
