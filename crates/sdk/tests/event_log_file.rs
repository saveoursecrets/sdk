use anyhow::Result;
use tempfile::NamedTempFile;

use sos_sdk::prelude::*;
use sos_test_utils::*;

async fn mock_account_event_log() -> Result<(NamedTempFile, AccountEventLog)>
{
    let temp = NamedTempFile::new()?;
    let event_log = AccountEventLog::new_account(temp.path()).await?;
    Ok((temp, event_log))
}

async fn mock_folder_event_log() -> Result<(NamedTempFile, FolderEventLog)> {
    let temp = NamedTempFile::new()?;
    let event_log = FolderEventLog::new(temp.path()).await?;
    Ok((temp, event_log))
}

async fn mock_event_log_file(
) -> Result<(NamedTempFile, FolderEventLog)> {
    let (encryption_key, _, _) = mock_encryption_key()?;
    let (_, mut vault) = mock_vault_file().await?;

    let (temp, mut event_log) = mock_folder_event_log().await?;

    // Create the vault
    let event = vault.into_event().await?;
    event_log.apply(vec![&event]).await?;

    // Create a secret
    let (secret_id, _, _, _, event) = mock_vault_note(
        &mut vault,
        &encryption_key,
        "event log Note",
        "This a event log note secret.",
    )
    .await?;
    event_log.apply(vec![&event]).await?;

    // Update the secret
    let (_, _, _, event) = mock_vault_note_update(
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
    let mut it = event_log.iter(false).await?;
    assert!(it.next().await?.is_some());
    assert!(it.next().await?.is_some());
    assert!(it.next().await?.is_some());
    assert!(it.next().await?.is_none());
    temp.close()?;
    Ok(())
}

#[tokio::test]
async fn folder_event_log_iter_backward() -> Result<()> {
    let (temp, event_log) = mock_event_log_file().await?;
    let mut it = event_log.iter(true).await?;
    assert!(it.next().await?.is_some());
    assert!(it.next().await?.is_some());
    assert!(it.next().await?.is_some());
    assert!(it.next().await?.is_none());
    temp.close()?;
    Ok(())
}

#[tokio::test]
async fn event_log_last_commit() -> Result<()> {
    let (temp, mut event_log) = mock_folder_event_log().await?;
    let (_, vault) = mock_vault_file().await?;

    assert!(event_log.tree().last_commit().is_none());

    let event = vault.into_event().await?;
    event_log.apply(vec![&event]).await?;

    assert!(event_log.tree().last_commit().is_some());

    // Patch with all events
    let patch = event_log.patch_records(None).await?;
    assert_eq!(1, patch.len());

    // Patch is empty as the target commit is the empty commit
    let last_commit = event_log.tree().last_commit();
    let patch = event_log.patch_records(last_commit.as_ref()).await?;
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

    #[cfg(feature = "sync")]
    {
        let patch = event_log.diff(None).await?;
        assert_eq!(2, patch.len());
    }

    temp.close()?;
    Ok(())
}

#[tokio::test]
async fn memory_folder_log() -> Result<()> {
    let mut event_log = MemoryFolderLog::new();

    event_log
        .apply(vec![&WriteEvent::CreateVault(vec![])])
        .await?;

    assert!(event_log.tree().len() > 0);
    assert!(event_log.tree().root().is_some());
    assert!(event_log.tree().last_commit().is_some());

    #[cfg(feature = "sync")]
    let previous_commit = event_log.tree().last_commit();

    event_log
        .apply(vec![&WriteEvent::SetVaultName("name".to_owned())])
        .await?;

    #[cfg(feature = "sync")]
    {
        let patch = event_log.diff(previous_commit.as_ref()).await?;
        assert_eq!(1, patch.len());
    }

    Ok(())
}
