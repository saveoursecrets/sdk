use axum::http::StatusCode;
use std::{borrow::Cow, collections::HashMap};

use sos_sdk::{
    commit::CommitProof,
    constants::SYNC_PULL,
    decode, encode,
    sync::{
        AccountDiff, CheckedPatch, FolderDiff, FolderPatch, SyncDiff,
        SyncStatus,
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
/// * `Sync.pull`: Pull changes from a remote account.
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
            SYNC_PULL => {
                let account = {
                    let reader = backend.read().await;
                    let accounts = reader.accounts();
                    let reader = accounts.read().await;
                    let account = reader
                        .get(caller.address())
                        .ok_or_else(|| Error::NoAccount(*caller.address()))?;
                    Arc::clone(account)
                };

                let local_status = request.parameters::<SyncStatus>()?;
                let reader = account.read().await;
                
                /*
                // FIXME: do not trust the client-side proof as `before`
                // FIXME: instead get the proof of the last commit
                // FIXME: from each event log

                let identity: FolderDiff = {
                    let identity_log = reader.folders.identity_log();
                    let reader = identity_log.read().await;
                    let after = reader.tree().head()?;
                    if &after == &local_status.identity.1 {
                        FolderDiff::Even
                    } else {
                        FolderDiff::Patch {
                            patch: reader
                                .diff(Some(&local_status.identity.0))
                                .await?,
                            after,
                            before: local_status.identity.1.clone(),
                        }
                    }
                };

                let account: AccountDiff = {
                    let account_log = reader.folders.account_log();
                    let reader = account_log.read().await;
                    let after = reader.tree().head()?;
                    if &after == &local_status.account.1 {
                        AccountDiff::Even
                    } else {
                        AccountDiff::Patch {
                            patch: reader
                                .diff(Some(&local_status.account.0))
                                .await?,
                            after,
                            before: local_status.account.1.clone(),
                        }
                    }
                };

                let folders: HashMap<VaultId, FolderDiff> = {
                    let mut folders = HashMap::new();
                    for (id, commit_state) in local_status.folders {
                        let event_log =
                            reader.folders.cache().get(&id).ok_or_else(
                                || Error::NoFolder(*caller.address(), id),
                            )?;

                        let after = event_log.tree().head()?;

                        let folder = if &after == &commit_state.1 {
                            FolderDiff::Even
                        } else {
                            FolderDiff::Patch {
                                patch: event_log
                                    .diff(Some(&commit_state.0))
                                    .await?,
                                after,
                                before: commit_state.1,
                            }
                        };

                        folders.insert(id, folder);
                    }
                    folders
                };

                let diff = SyncDiff {
                    account,
                    identity,
                    folders,
                };

                let buffer = encode(&diff).await?;
                let reply = ResponseMessage::new(
                    request.id(),
                    StatusCode::OK,
                    Some(Ok(())),
                    Cow::Owned(buffer),
                )?;
                Ok(reply)
                */

                todo!();
            }
            _ => Err(Error::RpcUnknownMethod(request.method().to_owned())),
        }
    }
}
