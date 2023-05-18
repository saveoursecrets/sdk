use super::{Error, Result};
use crate::client::net::{MaybeRetry, RpcClient};

use http::StatusCode;

use sos_sdk::{
    commit::{CommitProof, SyncInfo, SyncKind},
    constants::WAL_IDENTITY,
    formats::FileIdentity,
    patch::PatchProvider,
    vault::Summary,
    wal::WalProvider,
};

use crate::{client::provider::assert_proofs_eq, retry};

use super::apply_patch_file;

/// Download changes from the remote server.
pub async fn pull<W, P>(
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
            let result_proof = force_pull(client, summary, wal_file).await?;
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

/// Fetch the remote WAL file.
pub async fn pull_wal<W>(
    client: &mut RpcClient,
    summary: &Summary,
    wal_file: &mut W,
) -> Result<CommitProof>
where
    W: WalProvider + Send + Sync + 'static,
{
    let client_proof = if wal_file.tree().root().is_some() {
        let proof = wal_file.tree().head()?;
        tracing::debug!(root = %proof.root_hex(), "pull_wal wants diff");
        Some(proof)
    } else {
        None
    };

    let (status, (server_proof, buffer)) = retry!(
        || client.load_wal(summary.id(), client_proof.clone()),
        client
    );

    tracing::debug!(status = %status, "pull_wal");

    match status {
        StatusCode::OK => {
            let buffer = buffer.unwrap();
            let server_proof = server_proof.ok_or(Error::ServerProof)?;
            tracing::debug!(
                server_root_hash = %server_proof.root_hex(), "pull_wal");

            let client_proof = match client_proof {
                // If we sent a proof to the server then we
                // are expecting a diff of records
                Some(_proof) => {
                    tracing::debug!(bytes = ?buffer.len(),
                        "pull_wal write diff WAL records");

                    // Check the identity looks good
                    FileIdentity::read_slice(&buffer, &WAL_IDENTITY)?;

                    // Append the diff bytes
                    wal_file.append_buffer(buffer)?;

                    wal_file.tree().head()?
                }
                // Otherwise the server should send us the entire
                // WAL file
                None => {
                    tracing::debug!(bytes = ?buffer.len(),
                        "pull_wal write entire WAL");

                    // Check the identity looks good
                    FileIdentity::read_slice(&buffer, &WAL_IDENTITY)?;
                    wal_file.write_buffer(buffer)?;
                    wal_file.tree().head()?
                }
            };

            assert_proofs_eq(&client_proof, &server_proof)?;

            Ok(client_proof)
        }
        StatusCode::NOT_MODIFIED => {
            /*
            // Verify that both proofs are equal
            let (wal, _) = self
                .cache
                .get(summary.id())
                .ok_or(Error::CacheNotAvailable(*summary.id()))?;
            */
            let server_proof = server_proof.ok_or(Error::ServerProof)?;
            let client_proof = wal_file.tree().head()?;
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

pub async fn force_pull<W>(
    client: &mut RpcClient,
    summary: &Summary,
    wal_file: &mut W,
) -> Result<CommitProof>
where
    W: WalProvider + Send + Sync + 'static,
{
    // Need to recreate the WAL file correctly before pulling
    // as pull_wal() expects the file to exist
    *wal_file = W::new(wal_file.path())?;
    wal_file.load_tree()?;

    // Pull the remote WAL
    pull_wal(client, summary, wal_file).await?;

    let proof = wal_file.tree().head()?;

    Ok(proof)
}
