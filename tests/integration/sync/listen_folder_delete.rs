use anyhow::Result;
use copy_dir::copy_dir;
use serial_test::serial;
use std::{path::PathBuf, sync::Arc, time::Duration};

use sos_net::{
    client::{ListenOptions, RemoteBridge, RemoteSync, UserStorage},
    sdk::{
        constants::{EVENT_LOG_EXT, VAULT_EXT},
        vault::Summary,
        vfs,
    },
};

use crate::test_utils::{create_local_account, origin, setup, spawn};

use super::num_events;

/// Tests syncing delete folder events between two clients
/// where the second client listens for changes emitted
/// by the first client via the remote.
#[tokio::test]
#[serial]
async fn integration_listen_delete_folder() -> Result<()> {
    //crate::test_utils::init_tracing();

    // Prepare distinct data directories for the two clients
    let dirs = setup(2).await?;

    // Set up the paths for the first client
    let test_data_dir = dirs.clients.get(0).unwrap();

    // Need to remove the other data dir as we will
    // copy the first data dir in later
    let other_data_dir = dirs.clients.get(1).unwrap();
    std::fs::remove_dir(&other_data_dir)?;

    // Spawn a backend server and wait for it to be listening
    let (rx, _handle) = spawn()?;
    let _ = rx.await?;

    let (mut owner, _, default_folder, passphrase) = create_local_account(
        "sync_listen_delete_folder",
        Some(test_data_dir.clone()),
    )
    .await?;

    // Folders on the local account
    let expected_summaries: Vec<Summary> = {
        let storage = owner.storage();
        let mut writer = storage.write().await;
        writer
            .load_vaults()
            .await?
            .into_iter()
            .map(|s| s.clone())
            .collect()
    };

    // Path that we expect the remote server to write to
    let server_path = PathBuf::from(format!(
        "target/integration-test/server/{}",
        owner.address()
    ));
    let address = owner.address().to_string();

    // Create the remote provider
    let origin = origin();
    let remote_origin = origin.clone();
    let provider = owner.remote_bridge(&origin).await?;

    // Copy the owner's account directory and sign in
    // using the alternative owner
    copy_dir(&test_data_dir, &other_data_dir)?;
    let mut other_owner = UserStorage::sign_in(
        owner.address(),
        passphrase,
        None,
        Some(other_data_dir.clone()),
    )
    .await?;

    // Mimic account owner on another device connected to
    // the same remotes
    let other_provider = other_owner.remote_bridge(&origin).await?;

    // Insert the remote for the other owner
    other_owner.insert_remote(origin.clone(), Box::new(other_provider));

    // Must list folders to load cache into memory after sign in
    other_owner.list_folders().await?;

    // Insert the remote for the primary owner
    owner.insert_remote(origin.clone(), Box::new(provider));

    // Start listening for change notifications (first client)
    owner.listen(
        &origin,
        ListenOptions::new("device_1".to_string())?,
    )?;

    // Start listening for change notifications (second client)
    other_owner.listen(
        &origin,
        ListenOptions::new("device_2".to_string())?,
    )?;

    let default_folder_id = *default_folder.id();
    owner.open_folder(&default_folder).await?;
    other_owner.open_folder(&default_folder).await?;

    //println!("default folder {}", default_folder_id);

    // Before we begin both clients should have a single event
    assert_eq!(1, num_events(&mut owner, &default_folder_id).await);
    assert_eq!(1, num_events(&mut other_owner, &default_folder_id).await);

    // Sync a local account that does not exist on
    // the remote which should create the account on the remote
    owner.sync().await?;

    let (new_folder, sync_error) =
        owner.create_folder("sync_folder".to_string()).await?;
    assert!(sync_error.is_none());

    let sync_error = owner.delete_folder(&new_folder).await?;
    assert!(sync_error.is_none());

    // Pause a while to give the listener some time to process
    // the change notification
    tokio::time::sleep(Duration::from_millis(250)).await;

    let updated_summaries: Vec<Summary> = {
        let storage = owner.storage();
        let reader = storage.read().await;
        reader.state().summaries().to_vec()
    };
    assert_eq!(expected_summaries.len(), updated_summaries.len());

    // Check the server removed the files
    let expected_vault_file = server_path.join(&address).join(format!(
        "{}.{}",
        new_folder.id(),
        VAULT_EXT
    ));
    let expected_event_file = server_path.join(&address).join(format!(
        "{}.{}",
        new_folder.id(),
        EVENT_LOG_EXT
    ));
    assert!(!vfs::try_exists(expected_vault_file).await?);
    assert!(!vfs::try_exists(expected_event_file).await?);

    // Check the first client removed the files
    let expected_vault_file =
        owner.paths().vault_path(new_folder.id().to_string());
    let expected_event_file =
        owner.paths().vault_path(new_folder.id().to_string());
    assert!(!vfs::try_exists(expected_vault_file).await?);
    assert!(!vfs::try_exists(expected_event_file).await?);

    // Check the listening client removed the files
    let expected_vault_file =
        other_owner.paths().vault_path(new_folder.id().to_string());
    let expected_event_file =
        other_owner.paths().vault_path(new_folder.id().to_string());
    assert!(!vfs::try_exists(expected_vault_file).await?);
    assert!(!vfs::try_exists(expected_event_file).await?);

    Ok(())
}
