use super::{Error, Result};
use crate::client::net::{MaybeRetry, RpcClient};

use http::StatusCode;

use sos_core::{
    commit_tree::CommitProof, constants::WAL_IDENTITY, vault::Summary,
    wal::WalProvider, FileIdentity, PatchProvider,
};

use crate::{
    client::provider::assert_proofs_eq,
    retry,
    sync::{SyncInfo, SyncKind},
};

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

    println!("got pull status {}", status);

    //.await?;
    status
        .is_success()
        .then_some(())
        .ok_or(Error::ResponseCode(status.into()))?;

    let equals = client_proof.root() == server_proof.root();

    println!("PROOFS ARE EQUAL {}", equals);

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
            println!("TRYING THE FORCE PULL!");

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
    let client_proof = if let Some(_) = wal_file.tree().root() {
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

    println!("PULL WAL STATUS {}", status);

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
                    local: client_proof.reduce(),
                    remote: server_proof.reduce(),
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
    /*
    // Noop on wasm32
    self.backup_vault_file(summary).await?;
    */

    //let (wal, _) = self
    //.cache
    //.get_mut(summary.id())
    //.ok_or(Error::CacheNotAvailable(*summary.id()))?;

    /*
    // Create a snapshot of the WAL before deleting it
    if let Some(snapshots) = &self.snapshots {
        let root_hash = wal.tree().root().ok_or(Error::NoRootCommit)?;
        let (snapshot, _) =
            snapshots.create(summary.id(), wal.path(), root_hash)?;
        tracing::debug!(
            path = ?snapshot.0, "force_pull snapshot");
    }
    */

    // Noop on wasm32
    //fs_adapter::remove_file(wal_file.path()).await?;

    // Need to recreate the WAL file correctly before pulling
    // as pull_wal() expects the file to exist
    *wal_file = W::new(wal_file.path())?;
    wal_file.load_tree()?;

    println!("PULLING WAL FROM REMOTE!!!!");

    // Pull the remote WAL
    pull_wal(client, summary, wal_file).await?;

    println!("AFTER pulling wal from remote!!!");

    /*
    let (wal, _) = self
        .cache
        .get(summary.id())
        .ok_or(Error::CacheNotAvailable(*summary.id()))?;
    */

    let proof = wal_file.tree().head()?;

    //self.refresh_vault(summary, None)?;

    Ok(proof)
}
