use anyhow::Result;
use sos_backend::FolderEventLog;
use sos_core::commit::{CommitHash, CommitTree};
use sos_sdk::prelude::*;
use std::path::Path;
use uuid::Uuid;

async fn mock_secret<'a>() -> Result<(SecretId, VaultCommit)> {
    let id = Uuid::new_v4();
    let entry = VaultEntry(Default::default(), Default::default());
    let buffer = encode(&entry).await?;
    let commit = CommitHash(CommitTree::hash(&buffer));
    let result = VaultCommit(commit, entry);
    Ok((id, result))
}

async fn mock_event_log_standalone(
    path: impl AsRef<Path>,
) -> Result<(FolderEventLog, SecretId)> {
    if vfs::try_exists(path.as_ref()).await? {
        vfs::remove_file(path.as_ref()).await?;
    }

    let mut vault: Vault = Default::default();
    vault.set_name(String::from("Standalone vault"));
    let vault_buffer = encode(&vault).await?;

    let (id, data) = mock_secret().await?;

    // Create a simple event log
    let mut event_log = FolderEventLog::new_fs_folder(path.as_ref()).await?;
    event_log
        .apply(vec![
            &WriteEvent::CreateVault(vault_buffer),
            &WriteEvent::CreateSecret(id, data),
        ])
        .await?;

    Ok((event_log, id))
}

#[tokio::test]
async fn event_log_rewind() -> Result<()> {
    let path = "target/event_log_rewind.events";

    if vfs::try_exists(path).await? {
        vfs::remove_file(path).await?;
    }

    let mut event_log = FolderEventLog::new_fs_folder(path).await?;

    let vault: Vault = Default::default();
    let vault_buffer = encode(&vault).await?;
    event_log
        .apply(vec![&WriteEvent::CreateVault(vault_buffer)])
        .await?;

    assert_eq!(1, event_log.tree().len());

    // Checkpoint we will rewind to
    let rewind_root = event_log.tree().root().unwrap();
    let rewind_commit = event_log.tree().last_commit().unwrap();

    // Append some more events
    let (id, data) = mock_secret().await?;
    event_log
        .apply(vec![&WriteEvent::CreateSecret(id, data)])
        .await?;

    assert_eq!(2, event_log.tree().len());
    let new_root = event_log.tree().root().unwrap();

    assert_ne!(rewind_root, new_root);

    // Try to rewind discarding the create secret event
    event_log.rewind(&rewind_commit).await?;

    assert_eq!(rewind_commit, event_log.tree().last_commit().unwrap());

    assert_eq!(1, event_log.tree().len());
    let updated_root = event_log.tree().root().unwrap();
    assert_eq!(rewind_root, updated_root);

    // Make sure the file truncation is correct
    {
        let mut new_event_log = FolderEventLog::new_fs_folder(path).await?;
        new_event_log.load_tree().await?;

        let reloaded_root = new_event_log.tree().root().unwrap();
        assert_eq!(rewind_root, reloaded_root);
    }

    Ok(())
}
