use super::mock;
use anyhow::Result;
use sos_backend::{BackendEventLog, BackendTarget, FolderEventLog};
use sos_core::Paths;
use sos_core::{
    commit::CommitHash,
    encode,
    events::{EventLog, WriteEvent},
};
use sos_test_utils::mock::memory_database;
use sos_vault::Vault;
use sos_vfs as vfs;

#[tokio::test]
async fn fs_event_log_rewind() -> Result<()> {
    let path = "target/event_log_rewind.events";
    if vfs::try_exists(path).await? {
        vfs::remove_file(path).await?;
    }

    let vault: Vault = Default::default();
    let event_log = BackendEventLog::FileSystem(
        sos_filesystem::FolderEventLog::new_folder(path).await?,
    );
    let rewind_root = assert_event_log_rewind(event_log, vault).await?;

    // Create new event log to load the commits and verify the root
    let event_log = BackendEventLog::FileSystem(
        sos_filesystem::FolderEventLog::new_folder(path).await?,
    );
    assert_event_log_rewound_root(event_log, rewind_root).await?;

    Ok(())
}

#[tokio::test]
async fn db_event_log_rewind() -> Result<()> {
    let vault: Vault = Default::default();
    let folder_id = *vault.id();
    let mut client = memory_database().await?;
    let (account_id, event_log, temp) =
        mock::db_folder_event_log(&mut client, &vault).await?;
    let rewind_root = assert_event_log_rewind(event_log, vault).await?;
    let paths = Paths::new_client(temp.path()).with_account_id(&account_id);
    let target = BackendTarget::Database(paths, client);

    // Create new event log to load the commits and verify the root
    let event_log =
        FolderEventLog::new_folder(target, &account_id, &folder_id).await?;
    assert_event_log_rewound_root(event_log, rewind_root).await?;
    temp.close()?;
    Ok(())
}

async fn assert_event_log_rewind(
    mut event_log: FolderEventLog,
    vault: Vault,
) -> Result<CommitHash> {
    let vault_buffer = encode(&vault).await?;
    event_log
        .apply(&[WriteEvent::CreateVault(vault_buffer)])
        .await?;

    assert_eq!(1, event_log.tree().len());

    // Checkpoint we will rewind to
    let rewind_root = event_log.tree().root().unwrap();
    let rewind_commit = event_log.tree().last_commit().unwrap();

    // Append some more events
    let (id, data) = mock::mock_secret().await?;
    event_log
        .apply(&[WriteEvent::CreateSecret(id, data)])
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

    Ok(rewind_root)
}

async fn assert_event_log_rewound_root(
    mut event_log: FolderEventLog,
    root: CommitHash,
) -> Result<()> {
    event_log.load_tree().await?;
    let reloaded_root = event_log.tree().root().unwrap();
    assert_eq!(root, reloaded_root);
    Ok(())
}
