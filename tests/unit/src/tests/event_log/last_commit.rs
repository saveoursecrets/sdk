use super::mock;
use anyhow::Result;
use sos_backend::FolderEventLog;
use sos_core::events::{EventLog, WriteEvent};
use sos_test_utils::mock::{memory_database, vault_file};

#[tokio::test]
async fn fs_event_log_last_commit() -> Result<()> {
    let (_, vault, _) = vault_file().await?;
    let event = vault.into_event().await?;
    let (temp, event_log) = mock::fs_folder_event_log().await?;
    assert_last_commit(event_log, event).await?;
    temp.close()?;
    Ok(())
}

#[tokio::test]
async fn db_event_log_last_commit() -> Result<()> {
    let (_, vault, _) = vault_file().await?;
    let event = vault.into_event().await?;
    let mut client = memory_database().await?;
    let (_, event_log) =
        mock::db_folder_event_log(&mut client, &vault).await?;
    assert_last_commit(event_log, event).await?;
    Ok(())
}

async fn assert_last_commit(
    mut event_log: FolderEventLog,
    event: WriteEvent,
) -> Result<()> {
    assert!(event_log.tree().last_commit().is_none());

    event_log.apply(&[event]).await?;

    assert!(event_log.tree().last_commit().is_some());

    // Patch with all events
    let patch = event_log.diff_records(None).await?;
    assert_eq!(1, patch.len());

    // Patch is empty as the target commit is the empty commit
    let last_commit = event_log.tree().last_commit();
    let patch = event_log.diff_records(last_commit.as_ref()).await?;
    assert_eq!(0, patch.len());

    Ok(())
}
