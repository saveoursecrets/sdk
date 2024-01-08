use axum::http::StatusCode;
use std::borrow::Cow;

use sos_sdk::{
    constants::SYNC_RESOLVE,
    decode, encode,
    sync::{self, SyncDiff, SyncStatus},
};

use async_trait::async_trait;

use super::{PrivateState, Service};
use crate::{
    rpc::{RequestMessage, ResponseMessage},
    server::{Error, Result},
};
use std::sync::Arc;

#[cfg(feature = "listen")]
use crate::events::ChangeNotification;

#[cfg(feature = "listen")]
use super::send_notification;

/// Sync service.
///
/// This service is restricted; it requires account
/// and device signatures.
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
        let (caller, (state, backend)) = state;

        match request.method() {
            SYNC_RESOLVE => {
                println!("SYNC RESOLVE WAS CALLED...");

                let account = {
                    let reader = backend.read().await;
                    let accounts = reader.accounts();
                    let reader = accounts.read().await;
                    let account = reader
                        .get(caller.address())
                        .ok_or_else(|| Error::NoAccount(*caller.address()))?;
                    Arc::clone(account)
                };

                let remote_status = request.parameters::<SyncStatus>()?;
                let diff: SyncDiff = decode(request.body()).await?;

                // Apply the diff to the storage
                let num_changes = {
                    let mut writer = account.write().await;
                    writer.storage.merge(&diff).await?
                };

                // Generate a new diff so the client can apply changes
                // that exist in remote but not in the local
                let (local_status, diff) = {
                    let reader = account.read().await;
                    let (_, local_status, diff) =
                        sync::diff(&reader.storage, remote_status).await?;
                    (local_status, diff)
                };

                #[cfg(feature = "listen")]
                if num_changes > 0 {
                    let notification = ChangeNotification::new(
                        caller.address(),
                        caller.public_key(),
                    );
                    let mut writer = state.write().await;
                    send_notification(&mut *writer, &caller, notification);
                }

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
