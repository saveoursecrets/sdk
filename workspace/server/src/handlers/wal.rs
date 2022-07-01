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
    commit_tree::{decode_proof, CommitProof, Comparison},
    decode,
    events::{
        AuditData, AuditEvent, ChangeEvent, EventKind, Patch, SyncEvent,
        WalEvent,
    },
    vault::{CommitHash, Header},
};

use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::{
    authenticate,
    headers::{CommitHashHeader, CommitProofHeader, SignedMessage},
    State,
};

use super::{append_audit_logs, append_commit_headers, send_notifications};

enum PatchResult {
    Conflict(CommitProof),
    Success(
        Vec<AuditEvent>,
        Vec<ChangeEvent>,
        Vec<CommitHash>,
        CommitProof,
        Option<(AddressStr, String)>,
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

                    let change_event = ChangeEvent::CreateVault {
                        vault_id: *summary.id(),
                        address: token.address,
                    };

                    let log = AuditEvent::from_sync_event(
                        &sync_event,
                        token.address,
                        *summary.id(),
                    );

                    append_audit_logs(&mut writer, vec![log]).await?;
                    send_notifications(&mut writer, vec![change_event]);

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
        root_hash: Option<TypedHeader<CommitHashHeader>>,
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
                append_commit_headers(&mut headers, &proof)?;

                // Client is asking for data from a specific commit hash
                let result = if let Some(TypedHeader(root_hash)) = root_hash {
                    let root_hash: [u8; 32] = root_hash.into();
                    if let Some(TypedHeader(commit_proof)) = commit_proof {
                        let proof = decode_proof(commit_proof.as_ref())
                            .map_err(|_| StatusCode::BAD_REQUEST)?;

                        let comparison = wal
                            .tree()
                            .compare(CommitProof(root_hash, proof))
                            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

                        match comparison {
                            Comparison::Equal => {
                                Ok((StatusCode::NOT_MODIFIED, vec![]))
                            }
                            Comparison::Contains(_, leaf) => {
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
                            }
                            // Could not find leaf node in the commit tree
                            Comparison::Unknown => {
                                Ok((StatusCode::CONFLICT, vec![]))
                            }
                        }
                    } else {
                        Err(StatusCode::BAD_REQUEST)
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
        TypedHeader(root_hash): TypedHeader<CommitHashHeader>,
        TypedHeader(commit_proof): TypedHeader<CommitProofHeader>,
        Path(vault_id): Path<Uuid>,
        body: Bytes,
    ) -> Result<(StatusCode, HeaderMap, Bytes), StatusCode> {
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

                let root_hash: [u8; 32] = root_hash.into();
                let proof = decode_proof(commit_proof.as_ref())
                    .map_err(|_| StatusCode::BAD_REQUEST)?;

                let comparison = wal
                    .tree()
                    .compare(CommitProof(root_hash, proof))
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

                        // Notifications for the SSE channel
                        let notifications = change_set
                            .iter()
                            .map(|event| {
                                ChangeEvent::from_sync_event(
                                    &vault_id,
                                    &token.address,
                                    event,
                                )
                            })
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
                            audit_logs,
                            notifications,
                            commits,
                            proof,
                            vault_name.map(|name| (token.address, name)),
                        ))
                    }
                    Comparison::Unknown | Comparison::Contains(_, _) => {
                        let proof = wal
                            .tree()
                            .head()
                            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
                        Ok(PatchResult::Conflict(proof))
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
                logs,
                notifications,
                commits,
                proof,
                name,
            ) => {
                let mut writer = state.write().await;

                // Must update the vault name in it's summary
                if let Some((address, name)) = name {
                    writer
                        .backend
                        .set_vault_name(&address, &vault_id, name)
                        .await
                        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
                }

                // Append audit logs
                append_audit_logs(&mut writer, logs).await?;

                // Send notifications on the SSE channel
                send_notifications(&mut writer, notifications);

                // TODO: is sending the commits overkill as the new root
                // TODO: hash in `x-commit-hash` is enough for the client
                // TODO: to verify that applying cached changes to the WAL
                // TODO: matches the changes that are applied here.

                // Create a response buffer of all the commit hashes
                // derived from the events that were applied to the WAL
                let mut buffer = Vec::with_capacity(commits.len() * 32);
                for hash in commits {
                    buffer.extend_from_slice(hash.as_ref());
                }

                // Always send the `x-commit-hash` and `x-commit-proof`
                // headers to the client with the new updated commit
                // after applying the patch events.
                //
                // Clients can use this to verify the integrity when moving
                // staged events to their cached WAL
                let mut headers = HeaderMap::new();
                append_commit_headers(&mut headers, &proof)?;
                Ok((StatusCode::OK, headers, Bytes::from(buffer)))
            }
            PatchResult::Conflict(proof) => {
                let mut headers = HeaderMap::new();
                append_commit_headers(&mut headers, &proof)?;
                Ok((StatusCode::CONFLICT, headers, Bytes::from(vec![])))
            }
        }
    }

    /// Attempt to write an entire WAL file.
    ///
    /// This is the equivalent of a force push and should only be
    /// used by clients after they have created a completely different
    /// commit tree which can happen if they compact a locally cached
    /// WAL to prune history and save disc space.
    pub(crate) async fn post_wal(
        Extension(state): Extension<Arc<RwLock<State>>>,
        TypedHeader(authorization): TypedHeader<Authorization<Bearer>>,
        TypedHeader(root_hash): TypedHeader<CommitHashHeader>,
        Path(vault_id): Path<Uuid>,
        body: Bytes,
    ) -> Result<StatusCode, StatusCode> {
        if let Ok((status_code, token)) =
            authenticate::bearer(authorization, &body)
        {
            if let (StatusCode::OK, Some(token)) = (status_code, token) {
                let writer = state.write().await;
                // TODO: better error to status code mapping
                writer
                    .backend
                    .replace_wal(
                        &token.address,
                        &vault_id,
                        root_hash.into(),
                        body.as_ref(),
                    )
                    .await
                    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
                Ok(StatusCode::OK)
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

                // Always send the `x-commit-hash` and `x-commit-proof`
                // headers to the client
                let mut headers = HeaderMap::new();
                let proof = wal
                    .tree()
                    .head()
                    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
                append_commit_headers(&mut headers, &proof)?;

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

                let change_event = ChangeEvent::DeleteVault {
                    vault_id: vault_id.clone(),
                    address: token.address,
                };

                let log = AuditEvent::new(
                    EventKind::DeleteVault,
                    token.address,
                    Some(AuditData::Vault(vault_id)),
                );

                append_audit_logs(&mut writer, vec![log]).await?;
                send_notifications(&mut writer, vec![change_event]);

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
