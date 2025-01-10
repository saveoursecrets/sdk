use anyhow::Result;
use futures::{pin_mut, StreamExt};
use sos_backend::{AccountEventLog, FolderEventLog};
use sos_sdk::prelude::*;
use sos_test_utils::mock;
use tempfile::NamedTempFile;

async fn mock_account_event_log() -> Result<(NamedTempFile, AccountEventLog)>
{
    let temp = NamedTempFile::new()?;
    let event_log =
        AccountEventLog::new_fs_account(temp.path()).await?;
    Ok((temp, event_log))
}

async fn mock_folder_event_log() -> Result<(NamedTempFile, FolderEventLog)> {
    let temp = NamedTempFile::new()?;
    let event_log =
        FolderEventLog::new_fs_folder(temp.path()).await?;
    Ok((temp, event_log))
}

async fn mock_event_log_file() -> Result<(NamedTempFile, FolderEventLog)> {
    let (encryption_key, _, _) = mock::encryption_key()?;
    let (_, mut vault) = mock::vault_file().await?;

    let (temp, mut event_log) = mock_folder_event_log().await?;

    // Create the vault
    let event = vault.into_event().await?;
    event_log.apply(vec![&event]).await?;

    // Create a secret
    let (secret_id, _, _, _, event) = mock::vault_note(
        &mut vault,
        &encryption_key,
        "event log Note",
        "This a event log note secret.",
    )
    .await?;
    event_log.apply(vec![&event]).await?;

    // Update the secret
    let (_, _, _, event) = mock::vault_note_update(
        &mut vault,
        &encryption_key,
        &secret_id,
        "event log Note Edited",
        "This a event log note secret that was edited.",
    )
    .await?;
    if let Some(event) = event {
        event_log.apply(vec![&event]).await?;
    }

    Ok((temp, event_log))
}

#[tokio::test]
async fn folder_event_log_iter_forward() -> Result<()> {
    let (temp, event_log) = mock_event_log_file().await?;
    let stream = event_log.stream(false).await;
    pin_mut!(stream);
    assert!(stream.next().await.is_some());
    assert!(stream.next().await.is_some());
    assert!(stream.next().await.is_some());
    assert!(stream.next().await.is_none());
    temp.close()?;
    Ok(())
}

#[tokio::test]
async fn folder_event_log_iter_backward() -> Result<()> {
    let (temp, event_log) = mock_event_log_file().await?;
    let stream = event_log.stream(true).await;
    pin_mut!(stream);
    assert!(stream.next().await.is_some());
    assert!(stream.next().await.is_some());
    assert!(stream.next().await.is_some());
    assert!(stream.next().await.is_none());
    temp.close()?;
    Ok(())
}

#[tokio::test]
async fn event_log_last_commit() -> Result<()> {
    let (temp, mut event_log) = mock_folder_event_log().await?;
    let (_, vault) = mock::vault_file().await?;

    assert!(event_log.tree().last_commit().is_none());

    let event = vault.into_event().await?;
    event_log.apply(vec![&event]).await?;

    assert!(event_log.tree().last_commit().is_some());

    // Patch with all events
    let patch = event_log.diff_records(None).await?;
    assert_eq!(1, patch.len());

    // Patch is empty as the target commit is the empty commit
    let last_commit = event_log.tree().last_commit();
    let patch = event_log.diff_records(last_commit.as_ref()).await?;
    assert_eq!(0, patch.len());

    temp.close()?;
    Ok(())
}

#[tokio::test]
async fn account_event_log() -> Result<()> {
    let (temp, mut event_log) = mock_account_event_log().await?;

    let folder = VaultId::new_v4();
    event_log
        .apply(vec![
            &AccountEvent::CreateFolder(folder, vec![]),
            &AccountEvent::DeleteFolder(folder),
        ])
        .await?;

    assert!(event_log.tree().len() > 0);
    assert!(event_log.tree().root().is_some());
    assert!(event_log.tree().last_commit().is_some());

    let patch = event_log.diff_events(None).await?;
    assert_eq!(2, patch.len());

    temp.close()?;
    Ok(())
}
