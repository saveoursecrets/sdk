use crate::{StorageEventLogs, SyncStatus};
use indexmap::IndexMap;
use sos_core::{commit::CommitTree, events::EventLog, VaultId};

/// Compute the sync status for event log storage.
pub async fn compute_sync_status<S, E>(logs: &S) -> Result<SyncStatus, E>
where
    S: StorageEventLogs<Error = E>,
    E: std::error::Error
        + std::fmt::Debug
        + From<sos_core::Error>
        + From<sos_backend::Error>
        + Send
        + Sync
        + 'static,
{
    // NOTE: the order for computing the cumulative
    // NOTE: root hash must be identical to the logic
    // NOTE: in the server implementation and the folders
    // NOTE: collection must be sorted so that the folders
    // NOTE: root hash is deterministic

    let summaries = logs.folder_details().await?;

    let identity = {
        let event_log = logs.identity_log().await?;
        let reader = event_log.read().await;
        reader.tree().commit_state()?
    };

    let account = {
        let event_log = logs.account_log().await?;
        let reader = event_log.read().await;
        reader.tree().commit_state()?
    };

    let device = {
        let event_log = logs.device_log().await?;
        let reader = event_log.read().await;
        reader.tree().commit_state()?
    };

    #[cfg(feature = "files")]
    let files = {
        let event_log = logs.file_log().await?;
        let reader = event_log.read().await;
        if reader.tree().is_empty() {
            None
        } else {
            Some(reader.tree().commit_state()?)
        }
    };

    let mut folders = IndexMap::new();
    let mut folder_roots: Vec<(&VaultId, [u8; 32])> = Vec::new();
    for summary in &summaries {
        let event_log = logs.folder_log(summary.id()).await?;
        let reader = event_log.read().await;

        let commit_state = reader.tree().commit_state()?;
        folder_roots.push((summary.id(), commit_state.1.root().into()));
        folders.insert(*summary.id(), commit_state);
    }

    // Compute a root hash of all the trees for an account
    let mut root_tree = CommitTree::new();
    let mut root_commits = vec![
        identity.1.root().into(),
        account.1.root().into(),
        device.1.root().into(),
    ];
    #[cfg(feature = "files")]
    if let Some(files) = &files {
        root_commits.push(files.1.root().into());
    }

    folder_roots.sort_by(|a, b| a.0.cmp(b.0));
    let mut folder_roots =
        folder_roots.into_iter().map(|f| f.1).collect::<Vec<_>>();
    root_commits.append(&mut folder_roots);
    root_tree.append(&mut root_commits);
    root_tree.commit();

    let root = root_tree.root().ok_or(sos_core::Error::NoRootCommit)?;

    Ok(SyncStatus {
        root,
        identity,
        account,
        device,
        #[cfg(feature = "files")]
        files,
        folders,
    })
}
