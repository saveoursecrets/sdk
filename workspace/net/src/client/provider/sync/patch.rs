use super::{Error, Result};
use crate::client::net::{MaybeRetry, RpcClient};

use http::StatusCode;

use sos_sdk::{
    commit::CommitHash, events::EventLogFile, events::WriteEvent,
    patch::PatchFile, vault::Summary,
};

use crate::{client::provider::assert_proofs_eq, retry};

/// Apply a patch and error on failure.
pub async fn patch(
    client: &mut RpcClient,
    summary: &Summary,
    event_log_file: &mut EventLogFile,
    patch_file: &mut PatchFile,
    events: Vec<WriteEvent<'static>>,
) -> Result<()> {
    let status =
        apply_patch(client, summary, event_log_file, patch_file, events)
            .await?;
    status
        .is_success()
        .then_some(())
        .ok_or(Error::ResponseCode(status.into()))?;
    Ok(())
}

/// Attempt to apply a patch and return the status code.
pub(crate) async fn apply_patch(
    client: &mut RpcClient,
    summary: &Summary,
    event_log_file: &mut EventLogFile,
    patch_file: &mut PatchFile,
    events: Vec<WriteEvent<'static>>,
) -> Result<StatusCode> {
    let patch = patch_file.append(events)?;

    let client_proof = event_log_file.tree().head()?;

    let (status, (server_proof, match_proof)) = retry!(
        || client.apply_patch(
            *summary.id(),
            client_proof.clone(),
            patch.clone().into_owned(),
        ),
        client
    );

    match status {
        StatusCode::OK => {
            let server_proof = server_proof.ok_or(Error::ServerProof)?;

            // Apply changes to the local event log file
            let mut changes = Vec::new();
            for event in patch.0 {
                changes.push(event);
            }

            // Pass the expected root hash so changes are reverted
            // if the root hashes do not match
            event_log_file
                .apply(changes, Some(CommitHash(server_proof.root)))
                .await?;

            patch_file.truncate()?;

            let client_proof = event_log_file.tree().head()?;
            assert_proofs_eq(&client_proof, &server_proof)?;
            Ok(status)
        }
        StatusCode::CONFLICT => {
            let server_proof = server_proof.ok_or(Error::ServerProof)?;

            // Server replied with a proof that they have a
            // leaf node corresponding to our root hash which
            // indicates that we are behind the remote so we
            // can try to pull again and try to patch afterwards
            if match_proof.is_some() {
                Err(Error::ConflictBehind {
                    summary: summary.clone(),
                    local: client_proof.into(),
                    remote: server_proof.into(),
                    events: patch.0.clone(),
                })

                /*
                tracing::debug!(
                    client_root = %client_proof.root_hex(),
                    server_root = %server_proof.root_hex(),
                    "conflict on patch, attempting sync");

                // Pull the event log from the server that we
                // are behind
                pull_event_log(client, summary, event_log_file).await?;

                tracing::debug!(vault_id = %summary.id(),
                    "conflict on patch, pulled remote event log");

                // Retry sending our local changes to
                // the remote event log
                let status = apply_patch(
                    client,
                    summary,
                    event_log_file,
                    patch_file,
                    patch.0.clone(),
                )
                .await?;

                tracing::debug!(status = %status,
                    "conflict on patch, retry patch status");

                if status.is_success() {

                    // FIXME

                    // If the retry was successful then
                    // we should update the in-memory vault
                    // so if reflects the pulled changes
                    // with our patch applied over the top
                    let updated_vault =
                        self.reduce_event_log(summary).await?;

                    if let Some(keeper) = self.current_mut() {
                        if keeper.id() == summary.id() {
                            let existing_vault = keeper.vault_mut();
                            *existing_vault = updated_vault;
                        }
                    }
                }
                */

                //Ok(status)
            } else {
                Err(Error::Conflict {
                    summary: summary.clone(),
                    local: client_proof.into(),
                    remote: server_proof.into(),
                })
            }
        }
        _ => Err(Error::ResponseCode(status.into())),
    }
}

/// Attempt to drain the patch file and apply events to
/// the remote server.
pub async fn apply_patch_file(
    client: &mut RpcClient,
    summary: &Summary,
    event_log_file: &mut EventLogFile,
    patch_file: &mut PatchFile,
) -> Result<()> {
    let has_events = patch_file.has_events()?;

    tracing::debug!(has_events, "apply patch file");

    // Got some events which haven't been saved so try
    // to apply them over the top of the new event log
    if has_events {
        // Must drain() the patch file as calling
        // patch_vault() will append them again in
        // case of failure
        let events = patch_file.drain()?.0;

        tracing::debug!(events = events.len(), "apply patch file events");

        patch(client, summary, event_log_file, patch_file, events).await?;
        Ok(())
    } else {
        Ok(())
    }
}
