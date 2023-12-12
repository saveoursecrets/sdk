use axum::http::StatusCode;

use sos_sdk::{
    commit::CommitProof,
    constants::IDENTITY_PATCH,
    decode,
    device::DevicePublicKey,
    sync::{ChangeSet, CheckedPatch, FolderPatch, SyncStatus},
    vault::Header,
};

use async_trait::async_trait;

use super::{PrivateState, Service};
use crate::{
    rpc::{RequestMessage, ResponseMessage},
    server::{BackendHandler, Error, Result},
};
use std::sync::Arc;

#[cfg(feature = "listen")]
use crate::events::{ChangeEvent, ChangeNotification};

#[cfg(feature = "listen")]
use super::send_notification;

/// Identity events management service.
///
/// * `Identity.patch`: Apply a patch to the identity events log.
///
pub struct IdentityService;

#[async_trait]
impl Service for IdentityService {
    type State = PrivateState;

    async fn handle<'a>(
        &self,
        state: Self::State,
        request: RequestMessage<'a>,
    ) -> Result<ResponseMessage<'a>> {
        let (caller, (state, backend)) = state;

        match request.method() {
            IDENTITY_PATCH => {
                let account = {
                    let reader = backend.read().await;
                    let accounts = reader.accounts();
                    let reader = accounts.read().await;
                    let account = reader
                        .get(caller.address())
                        .ok_or_else(|| Error::NoAccount(*caller.address()))?;
                    Arc::clone(account)
                };

                let commit_proof = request.parameters::<CommitProof>()?;
                let patch: FolderPatch = decode(request.body()).await?;

                let mut writer = account.write().await;
                let identity_log = writer.folders.identity_log();
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
            }
            _ => Err(Error::RpcUnknownMethod(request.method().to_owned())),
        }
    }
}
