use axum::http::StatusCode;
use std::{borrow::Cow, collections::HashMap};

use sos_sdk::{
    commit::CommitProof,
    constants::SYNC_RESOLVE,
    decode, encode,
    events::AccountEvent,
    sync::{
        AccountDiff, CheckedPatch, FolderDiff, FolderPatch, SyncComparison,
        SyncDiff, SyncStatus, ApplyDiffOptions,
    },
    vault::VaultId,
};

use async_trait::async_trait;

use super::{PrivateState, Service};
use crate::{
    rpc::{RequestMessage, ResponseMessage},
    server::{Error, Result},
};
use std::sync::Arc;

/// Sync service.
///
/// * `Sync.resolve`: Apply a diff from a client and reply with a diff.
///
pub struct SyncService;

#[async_trait]
impl Service for SyncService {
    type State = PrivateState;

    async fn handle<'a>(
        &self,
        state: Self::State,
        request: RequestMessage<'a>,
    ) -> Result<ResponseMessage<'a>> {
        let (caller, (_state, backend)) = state;

        match request.method() {
            SYNC_RESOLVE => {
                let account = {
                    let reader = backend.read().await;
                    let accounts = reader.accounts();
                    let reader = accounts.read().await;
                    let account = reader
                        .get(caller.address())
                        .ok_or_else(|| Error::NoAccount(*caller.address()))?;
                    Arc::clone(account)
                };

                let mut remote_status = request.parameters::<SyncStatus>()?;
                let mut diff: SyncDiff = decode(request.body()).await?;

                // Apply the diff to the storage
                {
                    let mut writer = account.write().await;
                    writer
                        .folders
                        .apply_diff(
                            &diff,
                            ApplyDiffOptions {
                                // Must replay the account events here 
                                // so the folder event logs are available
                                // before we perform a comparison below
                                replay_account_events: true,
                            },
                        )
                        .await?;
                }

                // Generate a new diff so the client can apply changes
                // that exist in remote but not in the local
                let (local_status, diff) = {
                    let reader = account.read().await;
                    let comparison =
                        SyncComparison::new(&reader.folders, remote_status)
                            .await?;
                    let diff = comparison.diff(&reader.folders).await?;
                    (comparison.local_status, diff)
                };

                let buffer = encode(&diff).await?;
                let reply = ResponseMessage::new(
                    request.id(),
                    StatusCode::OK,
                    Some(Ok(&local_status)),
                    Cow::Owned(buffer),
                )?;
                Ok(reply)
            }
            _ => Err(Error::RpcUnknownMethod(request.method().to_owned())),
        }
    }
}
