use super::mock;
use anyhow::Result;
use futures::{pin_mut, StreamExt};
use sos_backend::{BackendTarget, FolderEventLog};
use sos_core::{commit::CommitHash, events::EventLog, Paths};
use sos_test_utils::mock::file_database;

#[tokio::test]
async fn fs_event_log_load_tree() -> Result<()> {
    let path = "target/event_log_file_load.events";
    let (mock_event_log, _) = mock::fs_event_log_standalone(path).await?;
    let expected_root = mock_event_log.tree().root().unwrap();
    let event_log = FolderEventLog::new_fs_folder(path).await?;
    assert_load_tree(event_log, expected_root).await?;
    Ok(())
}

#[tokio::test]
async fn db_event_log_load_tree() -> Result<()> {
    let (temp, mut client) = file_database().await?;
    let (event_log, account_id, _, _, vault, _temp) =
        mock::db_event_log_standalone(&mut client).await?;
    let expected_root = event_log.tree().root().unwrap();
    let paths = Paths::new_client(temp.path()).with_account_id(&account_id);
    let target = BackendTarget::Database(paths, client.clone());
    let event_log =
        FolderEventLog::new_folder(target, &account_id, vault.id()).await?;
    assert_load_tree(event_log, expected_root).await?;
    // Must close the client before the temp file otherwise
    // we will get an error on windows
    client.close().await?;
    temp.close()?;
    Ok(())
}

async fn assert_load_tree(
    mut event_log: FolderEventLog,
    expected_root: CommitHash,
) -> Result<()> {
    // Load the commit hashes and build the merkle tree
    event_log.load_tree().await?;

    // Ensure the new root matches the original tree
    assert_eq!(Some(&expected_root), event_log.tree().root().as_ref());

    // Read events from the event log
    let mut events = Vec::new();
    let stream = event_log.event_stream(false).await;
    pin_mut!(stream);
    while let Some(result) = stream.next().await {
        let (_, event) = result?;
        events.push(event);
    }

    // Mock standalone events logs have two events
    assert_eq!(2, events.len());

    Ok(())
}
