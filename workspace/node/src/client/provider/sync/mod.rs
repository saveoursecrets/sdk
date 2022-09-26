use super::{Error, Result};
use crate::client::net::{MaybeRetry, RpcClient};

use http::StatusCode;

use sos_core::{
    commit_tree::{CommitPair, Comparison},
    vault::Summary,
    wal::WalProvider,
    PatchProvider,
};

use crate::{client::provider::StorageProvider, retry, sync::SyncStatus};

mod change;
mod patch;
mod pull;
mod push;
mod status;

pub use change::*;
pub use patch::*;
pub use pull::*;
pub use push::*;
pub use status::*;

/// Get a comparison between a local WAL and remote WAL.
///
/// If a patch file has unsaved events then the number
/// of pending events is returned along with the `SyncStatus`.
pub async fn status<W, P>(
    client: &mut RpcClient,
    summary: &Summary,
    wal_file: &W,
    patch_file: &P,
) -> Result<(SyncStatus, Option<usize>)>
where
    W: WalProvider + Send + Sync + 'static,
    P: PatchProvider + Send + Sync + 'static,
{
    let client_proof = wal_file.tree().head()?;
    let (status, (server_proof, match_proof)) = retry!(
        || client.status(summary.id(), Some(client_proof.clone())),
        client
    );
    //.await?;
    status
        .is_success()
        .then_some(())
        .ok_or(Error::ResponseCode(status.into()))?;

    let equals = client_proof.root() == server_proof.root();

    let pair = CommitPair {
        local: client_proof,
        remote: server_proof.clone(),
    };

    let status = if equals {
        SyncStatus::Equal(pair)
    } else {
        if let Some(_) = match_proof {
            let (diff, _) =
                pair.remote.len().overflowing_sub(pair.local.len());
            SyncStatus::Behind(pair, diff)
        } else {
            let comparison = wal_file.tree().compare(server_proof)?;
            let is_ahead = match comparison {
                Comparison::Contains(_, _) => true,
                _ => false,
            };

            if is_ahead {
                let (diff, _) =
                    pair.local.len().overflowing_sub(pair.remote.len());
                SyncStatus::Ahead(pair, diff)
            } else {
                SyncStatus::Diverged(pair)
            }
        }
    };

    let pending_events = if patch_file.has_events()? {
        Some(patch_file.count_events()?)
    } else {
        None
    };

    Ok((status, pending_events))
}
