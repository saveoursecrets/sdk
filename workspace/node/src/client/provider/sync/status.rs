use super::{Error, Result};
use crate::client::net::{MaybeRetry, RpcClient};

use http::StatusCode;

use sos_core::{
    commit::CommitRelationship, vault::Summary, wal::WalProvider,
    PatchProvider,
};

use crate::retry;

/// Get a comparison between a local WAL and remote WAL.
///
/// If a patch file has unsaved events then the number
/// of pending events is returned along with the `CommitRelationship`.
#[allow(dead_code)]
pub async fn status<W, P>(
    client: &mut RpcClient,
    summary: &Summary,
    wal_file: &W,
    patch_file: &P,
) -> Result<(CommitRelationship, Option<usize>)>
where
    W: WalProvider + Send + Sync + 'static,
    P: PatchProvider + Send + Sync + 'static,
{
    let client_proof = wal_file.tree().head()?;
    let (status, (server_proof, match_proof)) = retry!(
        || client.status(summary.id(), Some(client_proof.clone())),
        client
    );

    status
        .is_success()
        .then_some(())
        .ok_or(Error::ResponseCode(status.into()))?;

    let status = wal_file.tree().relationship(server_proof, match_proof)?;

    let pending_events = if patch_file.has_events()? {
        Some(patch_file.count_events()?)
    } else {
        None
    };

    Ok((status, pending_events))
}
