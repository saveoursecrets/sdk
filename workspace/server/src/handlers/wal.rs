//! Handlers for the wal routes.
use axum::{
    body::Bytes,
    extract::{Extension, Path, TypedHeader},
    headers::{authorization::Bearer, Authorization},
    http::{header::HeaderMap, StatusCode},
};

//use axum_macros::debug_handler;

use sos_core::{
    address::AddressStr,
    commit_tree::{CommitProof, Comparison},
    decode,
    events::{
        AuditData, AuditEvent, ChangeEvent, ChangeNotification, EventKind,
        SyncEvent, WalEvent,
    },
    vault::Header,
    CommitHash, Patch,
};

use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::{
    authenticate,
    headers::{CommitProofHeader, SignedMessage},
    State,
};

use super::{
    append_audit_logs, append_commit_headers, append_match_header,
    send_notification,
};

enum PatchResult {
    Conflict(CommitProof, Option<CommitProof>),
    Success(
        AddressStr,
        Vec<AuditEvent>,
        Vec<ChangeEvent>,
        Vec<CommitHash>,
        CommitProof,
        Option<String>,
    ),
}

// Handlers for WAL log events.
pub(crate) struct WalHandler;
impl WalHandler {
    /// Create a WAL file.
    pub(crate) async fn put_wal(
        Extension(state): Extension<Arc<RwLock<State>>>,
        TypedHeader(authorization): TypedHeader<Authorization<Bearer>>,
        body: Bytes,
    ) -> Result<(StatusCode, HeaderMap), StatusCode> {
        if let Ok((status_code, token)) =
            authenticate::bearer(authorization, &body)
        {
            if let (StatusCode::OK, Some(token)) = (status_code, token) {
                // Check it looks like a vault payload
                let summary = Header::read_summary_slice(&body)
                    .map_err(|_| StatusCode::BAD_REQUEST)?;

                let reader = state.read().await;
                let (exists, proof) = reader
                    .backend
                    .wal_exists(&token.address, summary.id())
                    .await
                    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

                drop(reader);

                if exists {
                    let mut headers = HeaderMap::new();
                    if let Some(proof) = &proof {
                        append_commit_headers(&mut headers, proof)?;
                    }
                    Ok((StatusCode::CONFLICT, headers))
                } else {
                    let mut writer = state.write().await;
                    let (sync_event, proof) = writer
                        .backend
                        .create_wal(&token.address, summary.id(), &body)
                        .await
                        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

                    let notification = ChangeNotification::new(
                        &token.address,
                        summary.id(),
                        vec![ChangeEvent::CreateVault],
                    );

                    let log = AuditEvent::from_sync_event(
                        &sync_event,
                        token.address,
                        *summary.id(),
                    );

                    append_audit_logs(&mut writer, vec![log]).await?;
                    send_notification(&mut writer, notification);

                    let mut headers = HeaderMap::new();
                    append_commit_headers(&mut headers, &proof)?;
                    Ok((StatusCode::OK, headers))
                }
            } else {
                Err(status_code)
            }
        } else {
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }

    /// Read the buffer of a WAL file.
    ///
    /// If an `x-commit-hash` header is present then we attempt to
    /// fetch a tail of the log after the `x-commit-hash` record.
    ///
    /// When the `x-commit-hash` header is given the `x-commit-proof`
    /// header must also be sent.
    ///
    /// If neither header is present then the entire contents of the
    /// WAL file are returned.
    ///
    /// If an `x-commit-hash` header is present but the WAL does
    /// not contain the leaf node specified in `x-commit-proof` then
    /// a CONFLICT status code is returned.
    ///
    /// The `x-commit-hash` MUST be the root hash in the client WAL
    /// log and the `x-commit-proof` MUST contain the merkle proof for the
    /// most recent leaf node on the client.
    ///
    /// If the client and server root hashes match then a NOT_MODIFIED
    /// status code is returned.
    ///
    /// If the server has a root hash in it's WAL commit tree (which
    /// should always be the case) then it returns it's root hash in
    /// the `x-commit-hash` and a proof of the last leaf node in the
    /// `x-commit-proof` header.
    pub(crate) async fn get_wal(
        Extension(state): Extension<Arc<RwLock<State>>>,
        TypedHeader(authorization): TypedHeader<Authorization<Bearer>>,
        TypedHeader(message): TypedHeader<SignedMessage>,
        commit_proof: Option<TypedHeader<CommitProofHeader>>,
        Path(vault_id): Path<Uuid>,
    ) -> Result<(StatusCode, HeaderMap, Bytes), StatusCode> {
        if let Ok((status_code, token)) =
            authenticate::bearer(authorization, &message)
        {
            if let (StatusCode::OK, Some(token)) = (status_code, token) {
                let reader = state.read().await;

                let wal = reader
                    .backend
                    .wal_read(&token.address, &vault_id)
                    .await
                    .map_err(|_| StatusCode::NOT_FOUND)?;

                // Always send the `x-commit-hash` and `x-commit-proof`
                // headers to the client
                let mut headers = HeaderMap::new();
                let proof = wal
                    .tree()
                    .head()
                    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

                tracing::debug!(root = %proof.root_hex(),
                    "get_wal server root");

                append_commit_headers(&mut headers, &proof)?;

                // Client is asking for data from a specific commit hash
                let result = if let Some(TypedHeader(proof)) = commit_proof {
                    let proof: CommitProof = proof.into();

                    tracing::debug!(root = %proof.root_hex(),
                        "get_wal client root");

                    let comparison = wal
                        .tree()
                        .compare(proof)
                        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

                    match comparison {
                        Comparison::Equal => {
                            Ok((StatusCode::NOT_MODIFIED, vec![]))
                        }
                        Comparison::Contains(_, mut leaves) => {
                            if leaves.len() == 1 {
                                let leaf = leaves.remove(0);
                                if let Some(partial) =
                                    wal.diff(leaf).map_err(|_| {
                                        StatusCode::INTERNAL_SERVER_ERROR
                                    })?
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
                } else if let Ok(buffer) =
                    reader.backend.get_wal(&token.address, &vault_id).await
                {
                    Ok((StatusCode::OK, buffer))
                } else {
                    Err(StatusCode::INTERNAL_SERVER_ERROR)
                };

                drop(reader);

                let (status, buffer) = result?;

                if status == StatusCode::OK {
                    let mut writer = state.write().await;
                    let log = AuditEvent::new(
                        EventKind::ReadWal,
                        token.address,
                        Some(AuditData::Vault(vault_id)),
                    );
                    append_audit_logs(&mut writer, vec![log]).await?;
                }

                Ok((status, headers, Bytes::from(buffer)))
            } else {
                Err(status_code)
            }
        } else {
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }

    /// Attempt to append a series of events to a WAL file.
    pub(crate) async fn patch_wal(
        Extension(state): Extension<Arc<RwLock<State>>>,
        TypedHeader(authorization): TypedHeader<Authorization<Bearer>>,
        TypedHeader(proof): TypedHeader<CommitProofHeader>,
        Path(vault_id): Path<Uuid>,
        body: Bytes,
    ) -> Result<(StatusCode, HeaderMap), StatusCode> {
        let result = if let Ok((status_code, token)) =
            authenticate::bearer(authorization, &body)
        {
            if let (StatusCode::OK, Some(token)) = (status_code, token) {
                let mut writer = state.write().await;
                let wal = writer
                    .backend
                    .wal_write(&token.address, &vault_id)
                    .await
                    .map_err(|_| StatusCode::NOT_FOUND)?;

                let comparison = wal
                    .tree()
                    .compare(proof.into())
                    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

                match comparison {
                    Comparison::Equal => {
                        let patch: Patch = decode(&body)
                            .map_err(|_| StatusCode::BAD_REQUEST)?;

                        let change_set = patch.0;

                        // Setting vault name requires special handling
                        // as we need to update the vault header on disc
                        // as well so summary listings are kept up to date
                        let vault_name =
                            change_set.iter().find_map(|event| {
                                if let SyncEvent::SetVaultName(name) = event {
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
                                    token.address,
                                    vault_id,
                                )
                            })
                            .collect::<Vec<_>>();

                        // Changes events for the SSE channel
                        let change_events = change_set
                            .iter()
                            .map(|event| ChangeEvent::from_sync_event(event))
                            .filter(|e| e.is_some())
                            .map(|e| e.unwrap())
                            .collect::<Vec<_>>();

                        // Changes to apply to the WAL log
                        let mut changes = Vec::new();
                        for event in change_set {
                            if let Ok::<WalEvent<'_>, sos_core::Error>(
                                wal_event,
                            ) = event.try_into()
                            {
                                changes.push(wal_event);
                            }
                        }

                        // Apply the change set of WAL events to the log
                        let commits = wal
                            .apply(changes, None)
                            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

                        // Get a new commit proof for the last leaf hash
                        let proof = wal
                            .tree()
                            .head()
                            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

                        Ok(PatchResult::Success(
                            token.address,
                            audit_logs,
                            change_events,
                            commits,
                            proof,
                            vault_name,
                        ))
                    }
                    Comparison::Contains(indices, _leaves) => {
                        let proof = wal
                            .tree()
                            .head()
                            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
                        // Prepare the proof that this WAL contains the
                        // matched leaf node
                        let match_proof = wal
                            .tree()
                            .proof(&indices)
                            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
                        Ok(PatchResult::Conflict(proof, Some(match_proof)))

                        /*
                        // FIXME: remove this and restore the above
                        Ok(PatchResult::Conflict(proof, None))
                        */
                    }
                    Comparison::Unknown => {
                        let proof = wal
                            .tree()
                            .head()
                            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
                        Ok(PatchResult::Conflict(proof, None))
                    }
                }
            } else {
                Err(status_code)
            }
        } else {
            Err(StatusCode::INTERNAL_SERVER_ERROR)
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
                        .set_vault_name(&address, &vault_id, name)
                        .await
                        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
                }

                // Append audit logs
                append_audit_logs(&mut writer, logs).await?;

                let notification = ChangeNotification::new(
                    &address,
                    &vault_id,
                    change_events,
                );

                // Send notifications on the SSE channel
                send_notification(&mut writer, notification);

                // Always send the `x-commit-hash` and `x-commit-proof`
                // headers to the client with the new updated commit
                // after applying the patch events.
                //
                // Clients can use this to verify the integrity when moving
                // staged events to their cached WAL
                let mut headers = HeaderMap::new();
                append_commit_headers(&mut headers, &proof)?;
                Ok((StatusCode::OK, headers))
            }
            PatchResult::Conflict(proof, match_proof) => {
                let mut headers = HeaderMap::new();
                append_commit_headers(&mut headers, &proof)?;

                // Send a proof that this WAL contains the
                // root hash sent by the client.
                //
                // The client can use this to determine that it
                // is safe to pull changes from the server.
                if let Some(match_proof) = match_proof {
                    append_match_header(&mut headers, &match_proof)?;
                }

                Ok((StatusCode::CONFLICT, headers))
            }
        }
    }

    /// Attempt to write an entire WAL file.
    ///
    /// This is the equivalent of a force push and should only be
    /// used by clients after they have created a completely different
    /// commit tree which can happen if they compact a locally cached
    /// WAL (to prune history and save disc space) or if they change
    /// the password for a vault which would require creating a new
    /// commit tree.
    pub(crate) async fn post_wal(
        Extension(state): Extension<Arc<RwLock<State>>>,
        TypedHeader(authorization): TypedHeader<Authorization<Bearer>>,
        TypedHeader(proof): TypedHeader<CommitProofHeader>,
        Path(vault_id): Path<Uuid>,
        body: Bytes,
    ) -> Result<(StatusCode, HeaderMap), StatusCode> {
        if let Ok((status_code, token)) =
            authenticate::bearer(authorization, &body)
        {
            if let (StatusCode::OK, Some(token)) = (status_code, token) {
                let mut writer = state.write().await;
                let proof: CommitProof = proof.into();

                // TODO: better error to status code mapping
                let server_proof = writer
                    .backend
                    .replace_wal(
                        &token.address,
                        &vault_id,
                        proof.0.into(),
                        body.as_ref(),
                    )
                    .await
                    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

                let mut headers = HeaderMap::new();
                append_commit_headers(&mut headers, &server_proof)?;

                Ok((StatusCode::OK, headers))
            } else {
                Err(status_code)
            }
        } else {
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }

    /// Get the root commit and merkle proof for the WAL file.
    pub(crate) async fn head_wal(
        Extension(state): Extension<Arc<RwLock<State>>>,
        TypedHeader(authorization): TypedHeader<Authorization<Bearer>>,
        TypedHeader(message): TypedHeader<SignedMessage>,
        commit_proof: Option<TypedHeader<CommitProofHeader>>,
        Path(vault_id): Path<Uuid>,
    ) -> Result<(StatusCode, HeaderMap), StatusCode> {
        if let Ok((status_code, token)) =
            authenticate::bearer(authorization, &message)
        {
            if let (StatusCode::OK, Some(token)) = (status_code, token) {
                let reader = state.read().await;
                let wal = reader
                    .backend
                    .wal_read(&token.address, &vault_id)
                    .await
                    .map_err(|_| StatusCode::NOT_FOUND)?;

                let mut headers = HeaderMap::new();
                let proof = wal
                    .tree()
                    .head()
                    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

                append_commit_headers(&mut headers, &proof)?;

                if let Some(TypedHeader(client_proof)) = commit_proof {
                    let comparison = wal
                        .tree()
                        .compare(client_proof.into())
                        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

                    match comparison {
                        Comparison::Contains(indices, _leaves) => {
                            let match_proof =
                                wal.tree().proof(&indices).map_err(|_| {
                                    StatusCode::INTERNAL_SERVER_ERROR
                                })?;
                            append_match_header(&mut headers, &match_proof)?;
                        }
                        _ => {}
                    }
                }
                Ok((StatusCode::OK, headers))
            } else {
                Err(status_code)
            }
        } else {
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }

    /// Delete a WAL file.
    pub(crate) async fn delete_wal(
        Extension(state): Extension<Arc<RwLock<State>>>,
        Path(vault_id): Path<Uuid>,
        TypedHeader(authorization): TypedHeader<Authorization<Bearer>>,
        TypedHeader(message): TypedHeader<SignedMessage>,
    ) -> Result<(StatusCode, HeaderMap), StatusCode> {
        if let Ok((status_code, token)) =
            authenticate::bearer(authorization, &message)
        {
            if let (StatusCode::OK, Some(token)) = (status_code, token) {
                let mut writer = state.write().await;

                let (exists, proof) = writer
                    .backend
                    .wal_exists(&token.address, &vault_id)
                    .await
                    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

                if !exists {
                    return Err(StatusCode::NOT_FOUND);
                }

                writer
                    .backend
                    .delete_wal(&token.address, &vault_id)
                    .await
                    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

                let notification = ChangeNotification::new(
                    &token.address,
                    &vault_id,
                    vec![ChangeEvent::DeleteVault],
                );

                let log = AuditEvent::new(
                    EventKind::DeleteVault,
                    token.address,
                    Some(AuditData::Vault(vault_id)),
                );

                append_audit_logs(&mut writer, vec![log]).await?;
                send_notification(&mut writer, notification);

                let mut headers = HeaderMap::new();
                if let Some(proof) = &proof {
                    append_commit_headers(&mut headers, proof)?;
                }
                Ok((StatusCode::OK, headers))
            } else {
                Err(status_code)
            }
        } else {
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}
