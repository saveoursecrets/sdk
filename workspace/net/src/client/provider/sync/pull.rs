use super::{Error, Result};
use crate::client::net::{MaybeRetry, RpcClient};

use http::StatusCode;

use sos_sdk::{
    commit::{CommitProof, SyncInfo, SyncKind},
    constants::EVENT_LOG_IDENTITY,
    events::EventLogFile,
    formats::FileIdentity,
    patch::PatchFile,
    vault::Summary,
};

use crate::{client::provider::assert_proofs_eq, retry};

use super::apply_patch_file;

/// Download changes from the remote server.
pub async fn pull(
    client: &mut RpcClient,
    summary: &Summary,
    event_log_file: &mut EventLogFile,
    patch_file: &mut PatchFile,
    force: bool,
) -> Result<SyncInfo> {
    let client_proof = event_log_file.tree().head()?;

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

    let can_pull_safely = match_proof.is_some();
    let status = if force {
        SyncKind::Force
    } else if equals {
        SyncKind::Equal
    } else if can_pull_safely {
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
        if force || can_pull_safely {
            let result_proof =
                force_pull(client, summary, event_log_file).await?;
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

/// Fetch the remote event log file.
pub async fn pull_event_log(
    client: &mut RpcClient,
    summary: &Summary,
    event_log_file: &mut EventLogFile,
) -> Result<CommitProof> {
    let client_proof = if event_log_file.tree().root().is_some() {
        let proof = event_log_file.tree().head()?;
        tracing::debug!(root = %proof.root_hex(), "pull_event_log wants diff");
        Some(proof)
    } else {
        None
    };

    let (status, (server_proof, buffer)) = retry!(
        || client.load_event_log(summary.id(), client_proof.clone()),
        client
    );

    tracing::debug!(status = %status, "pull_event_log");

    match status {
        StatusCode::OK => {
            let buffer = buffer.unwrap();
            let server_proof = server_proof.ok_or(Error::ServerProof)?;
            tracing::debug!(
                server_root_hash = %server_proof.root_hex(), "pull_event_log");

            let client_proof = match client_proof {
                // If we sent a proof to the server then we
                // are expecting a diff of records
                Some(_proof) => {
                    tracing::debug!(bytes = ?buffer.len(),
                        "pull_event_log write diff event log records");

                    // Check the identity looks good
                    FileIdentity::read_slice(&buffer, &EVENT_LOG_IDENTITY)?;

                    // Append the diff bytes
                    event_log_file.append_buffer(buffer).await?;

                    event_log_file.tree().head()?
                }
                // Otherwise the server should send us the entire
                // event log file
                None => {
                    tracing::debug!(bytes = ?buffer.len(),
                        "pull_event_log write entire event log");

                    // Check the identity looks good
                    FileIdentity::read_slice(&buffer, &EVENT_LOG_IDENTITY)?;
                    event_log_file.write_buffer(&buffer).await?;
                    event_log_file.tree().head()?
                }
            };

            assert_proofs_eq(&client_proof, &server_proof)?;

            Ok(client_proof)
        }
        StatusCode::NOT_MODIFIED => {
            let server_proof = server_proof.ok_or(Error::ServerProof)?;
            let client_proof = event_log_file.tree().head()?;
            assert_proofs_eq(&client_proof, &server_proof)?;
            Ok(client_proof)
        }
        StatusCode::CONFLICT => {
            // If we are expecting a diff but got a conflict
            // from the server then the trees have diverged.
            //
            // We should pull from the server a complete fresh
            // tree at this point so we can get back in sync
            // however we need confirmation that this is allowed
            // from the user.
            if let Some(client_proof) = client_proof {
                let server_proof = server_proof.ok_or(Error::ServerProof)?;
                Err(Error::Conflict {
                    summary: summary.clone(),
                    local: client_proof.into(),
                    remote: server_proof.into(),
                })
            } else {
                Err(Error::ResponseCode(status.into()))
            }
        }
        _ => Err(Error::ResponseCode(status.into())),
    }
}

pub async fn force_pull(
    client: &mut RpcClient,
    summary: &Summary,
    event_log_file: &mut EventLogFile,
) -> Result<CommitProof> {
    // Need to recreate the event log file correctly before pulling
    // as pull_event_log() expects the file to exist
    *event_log_file = EventLogFile::new(event_log_file.path()).await?;
    event_log_file.load_tree().await?;

    // Pull the remote event log
    pull_event_log(client, summary, event_log_file).await?;

    let proof = event_log_file.tree().head()?;

    Ok(proof)
}
