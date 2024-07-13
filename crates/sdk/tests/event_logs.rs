use anyhow::Result;
use sos_sdk::prelude::*;
use std::path::Path;
use uuid::Uuid;

// const PATH: &str = "target/event_log_standalone.events";

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
    let mut event_log = FolderEventLog::new(path.as_ref()).await?;
    event_log
        .apply(vec![
            &WriteEvent::CreateVault(vault_buffer),
            &WriteEvent::CreateSecret(id, data),
        ])
        .await?;

    Ok((event_log, id))
}

async fn mock_event_log_server_client(
) -> Result<(FolderEventLog, FolderEventLog, SecretId)> {
    // Required for CI which is setting the current
    // working directory to the workspace member rather
    // than using the top-level working directory
    vfs::create_dir_all("target/mock-event-log").await?;

    let server_file = "target/mock-event-log/server.events";
    let client_file = "target/mock-event-log/client.events";
    if vfs::try_exists(server_file).await? {
        let _ = vfs::remove_file(server_file).await;
    }
    if vfs::try_exists(&client_file).await? {
        let _ = vfs::remove_file(client_file).await;
    }

    let vault: Vault = Default::default();
    let vault_buffer = encode(&vault).await?;

    let (id, data) = mock_secret().await?;

    // Create a simple event log
    let mut server = FolderEventLog::new(server_file).await?;
    server
        .apply(vec![
            &WriteEvent::CreateVault(vault_buffer),
            &WriteEvent::CreateSecret(id, data),
        ])
        .await?;

    // Duplicate the server events on the client
    let mut client = FolderEventLog::new(client_file).await?;
    let mut it = server.iter(false).await?;
    while let Some(record) = it.next().await? {
        let event = server.decode_event(&record).await?;
        client.apply(vec![&event]).await?;
    }

    let proof = client.tree().head()?;
    let comparison = server.tree().compare(&proof)?;
    assert_eq!(Comparison::Equal, comparison);

    assert_eq!(server.tree().len(), client.tree().len());
    Ok((server, client, id))
}

#[tokio::test]
async fn event_log_compare() -> Result<()> {
    let (mut server, client, id) = mock_event_log_server_client().await?;

    // Add another event to the server from another client.
    server.apply(vec![&WriteEvent::DeleteSecret(id)]).await?;

    // Check that the server contains the client proof
    let proof = client.tree().head()?;
    let comparison = server.tree().compare(&proof)?;

    let matched = if let Comparison::Contains(indices) = comparison {
        indices == vec![1]
    } else {
        false
    };
    assert!(matched);

    // Verify that the server root is not contained by the client.
    let proof = server.tree().head()?;
    let comparison = client.tree().compare(&proof)?;
    assert_eq!(Comparison::Unknown, comparison);

    // A completely different tree should also be unknown to the server.
    //
    // This can happen if a client compacts its event log which would create
    // a new commit tree.
    let (standalone, _) =
        mock_event_log_standalone("target/event_log_compare.events").await?;
    let proof = standalone.tree().head()?;
    let comparison = server.tree().compare(&proof)?;
    assert_eq!(Comparison::Unknown, comparison);

    Ok(())
}

#[tokio::test]
async fn event_log_file_load() -> Result<()> {
    mock_event_log_standalone("target/event_log_file_load.events").await?;

    let event_log = FolderEventLog::new(PATH).await?;
    let mut it = event_log.iter(false).await?;
    while let Some(record) = it.next().await? {
        let _event = event_log.decode_event(&record).await?;
    }

    Ok(())
}

#[tokio::test]
async fn event_log_rewind() -> Result<()> {
    let path = "target/event_log_rewind.events";

    if vfs::try_exists(path).await? {
        vfs::remove_file(path).await?;
    }

    let mut event_log = FolderEventLog::new(path).await?;

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
        let mut new_event_log = FolderEventLog::new(path).await?;
        new_event_log.load_tree().await?;

        let reloaded_root = new_event_log.tree().root().unwrap();
        assert_eq!(rewind_root, reloaded_root);
    }

    Ok(())
}
