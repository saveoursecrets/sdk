use axum::http::StatusCode;
use std::{borrow::Cow, collections::HashMap};

use sos_sdk::{
    commit::CommitProof,
    constants::SYNC_RESOLVE,
    decode, encode,
    sync::{
        AccountDiff, CheckedPatch, FolderDiff, FolderPatch, SyncComparison,
        SyncDiff, SyncStatus,
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

                println!("SYNC_RESOLVE");

                let local_status = request.parameters::<SyncStatus>()?;

                println!("got local status: {:#?}",
                    decode::<SyncDiff>(request.body()).await);

                let diff: SyncDiff = decode(request.body()).await?;

                println!("decoded the diff");

                // Apply the diff to the storage
                {
                    let mut writer = account.write().await;
                    writer.folders.apply_diff(&diff).await?;
                }

                println!("applied the diff");

                // Generate a new diff so the client can apply changes
                // that exist in remote but not in the local
                let (remote_status, diff) = {
                    let reader = account.read().await;
                    let remote_status = reader.folders.sync_status().await?;
                    let comparison =
                        SyncComparison::new(&reader.folders, local_status)
                            .await?;
                    let diff = comparison.diff(&reader.folders).await?;
                    (remote_status, diff)
                };

                let buffer = encode(&diff).await?;
                let reply = ResponseMessage::new(
                    request.id(),
                    StatusCode::OK,
                    Some(Ok(&remote_status)),
                    Cow::Owned(buffer),
                )?;
                Ok(reply)
            }
            _ => Err(Error::RpcUnknownMethod(request.method().to_owned())),
        }
    }
}
