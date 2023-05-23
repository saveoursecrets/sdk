use super::{Error, Result};
use crate::client::net::{MaybeRetry, RpcClient};

use http::StatusCode;

use sos_sdk::{
    commit::{CommitProof, Comparison, SyncInfo, SyncKind},
    events::EventLogFile,
    patch::PatchFile,
    vault::Summary,
    vfs,
};

use crate::{client::provider::assert_proofs_eq, retry};

use super::apply_patch_file;

/// Upload changes to the remote server.
pub async fn push(
    client: &mut RpcClient,
    summary: &Summary,
    event_log_file: &mut EventLogFile,
    patch_file: &mut PatchFile,
    force: bool,
) -> Result<SyncInfo> {
    let client_proof = event_log_file.tree().head()?;

    let (status, (server_proof, _match_proof)) =
        retry!(|| client.status(summary.id(), None), client);
    status
        .is_success()
        .then_some(())
        .ok_or(Error::ResponseCode(status.into()))?;

    let equals = client_proof.root() == server_proof.root();

    let comparison = event_log_file.tree().compare(&server_proof)?;
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
            let result_proof =
                force_push(client, summary, event_log_file).await?;
            info.after = Some(result_proof);

            // If we have unsaved staged events try to apply them
            apply_patch_file(client, summary, event_log_file, patch_file)
                .await?;

            Ok(info)
        } else {
            Ok(info)
        }
    } else {
        Ok(info)
    }
}

pub async fn force_push(
    client: &mut RpcClient,
    summary: &Summary,
    event_log_file: &mut EventLogFile,
) -> Result<CommitProof> {
    // TODO: load any unsaved events from the patch file and
    // TODO: apply them to the event log!

    let client_proof = event_log_file.tree().head()?;
    let body = vfs::read(event_log_file.path()).await?;
    let (status, server_proof) = retry!(
        || client.save_event_log(
            summary.id(),
            client_proof.clone(),
            body.clone()
        ),
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
