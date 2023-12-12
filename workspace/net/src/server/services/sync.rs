use axum::http::StatusCode;

use sos_sdk::{
    commit::CommitProof,
    constants::SYNC_PULL,
    decode,
    sync::{CheckedPatch, FolderPatch, SyncStatus},
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
/// * `Sync.pull`: Pull changes to an account.
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

                todo!();

                /*
                let patch: FolderPatch = decode(request.body()).await?;

                let reader = account.read().await;
                let identity_log = reader.folders.identity_log();
                let mut identity = identity_log.write().await;
                let result =
                    identity.patch_checked(&commit_proof, &patch).await?;

                match result {
                    CheckedPatch::Success(proof, _) => {
                        let value: (&CommitProof, Option<CommitProof>) =
                            (&proof, None);
                        let reply: ResponseMessage<'_> =
                            (request.id(), value).try_into()?;
                        Ok(reply)
                    }
                    CheckedPatch::Conflict { head, contains } => Ok((
                        StatusCode::CONFLICT,
                        request.id(),
                        (head, contains),
                    )
                        .try_into()?),
                }
                */
            }
            _ => Err(Error::RpcUnknownMethod(request.method().to_owned())),
        }
    }
}
