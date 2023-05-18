use super::{Error, Result};
use crate::client::net::{MaybeRetry, RpcClient};

use http::StatusCode;

use sos_sdk::{
    commit::{CommitProof, Comparison, SyncInfo, SyncKind},
    patch::PatchProvider,
    vault::Summary,
    wal::WalProvider,
};

use crate::{client::provider::assert_proofs_eq, retry};

use super::apply_patch_file;

/// Upload changes to the remote server.
pub async fn push<W, P>(
    client: &mut RpcClient,
    summary: &Summary,
    wal_file: &mut W,
    patch_file: &mut P,
    force: bool,
) -> Result<SyncInfo>
where
    W: WalProvider + Send + Sync + 'static,
    P: PatchProvider + Send + Sync + 'static,
{
    let client_proof = wal_file.tree().head()?;

    let (status, (server_proof, _match_proof)) =
        retry!(|| client.status(summary.id(), None), client);
    status
        .is_success()
        .then_some(())
        .ok_or(Error::ResponseCode(status.into()))?;

    let equals = client_proof.root() == server_proof.root();

    let comparison = wal_file.tree().compare(&server_proof)?;
    let can_push_safely = matches!(comparison, Comparison::Contains(_, _));

    let status = if force {
        SyncKind::Force
    } else if equals {
        SyncKind::Equal
    } else if can_push_safely {
        SyncKind::Safe
    } else {
        SyncKind::Unsafe
    };

    let mut info = SyncInfo {
        before: (client_proof, server_proof),
        after: None,
        status,
    };

    if force || !equals {
        if force || can_push_safely {
            let result_proof = force_push(client, summary, wal_file).await?;
            info.after = Some(result_proof);

            // If we have unsaved staged events try to apply them
            apply_patch_file(client, summary, wal_file, patch_file).await?;

            Ok(info)
        } else {
            Ok(info)
        }
    } else {
        Ok(info)
    }
}

pub async fn force_push<W>(
    client: &mut RpcClient,
    summary: &Summary,
    wal_file: &mut W,
) -> Result<CommitProof>
where
    W: WalProvider + Send + Sync + 'static,
{
    // TODO: load any unsaved events from the patch file and
    // TODO: apply them to the WAL!

    let client_proof = wal_file.tree().head()?;
    let body = std::fs::read(wal_file.path())?;
    let (status, server_proof) = retry!(
        || client.save_wal(summary.id(), client_proof.clone(), body.clone()),
        client
    );

    let server_proof = server_proof.ok_or(Error::ServerProof)?;
    status
        .is_success()
        .then_some(())
        .ok_or(Error::ResponseCode(status.into()))?;

    assert_proofs_eq(&client_proof, &server_proof)?;
    Ok(client_proof)
}
