use anyhow::Result;
use copy_dir::copy_dir;
use serial_test::serial;
use std::{path::PathBuf, sync::Arc, time::Duration};

use sos_net::{
    client::{ListenOptions, RemoteBridge, RemoteSync, UserStorage},
    sdk::{account::DelegatedPassphrase, encode, vault::Summary},
};

use crate::test_utils::{create_local_account, origin, setup, spawn};

use super::{
    assert_local_remote_events_eq, assert_local_remote_vaults_eq, num_events,
};

/// Tests syncing update folder events between two clients
/// where the second client listens for changes emitted
/// by the first client via the remote.
#[tokio::test]
#[serial]
async fn integration_listen_import_folder() -> Result<()> {
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
        "sync_listen_import_folder",
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

    // Before we begin both clients should have a single event
    assert_eq!(1, num_events(&mut owner, &default_folder_id).await);
    assert_eq!(1, num_events(&mut other_owner, &default_folder_id).await);

    // Sync a local account that does not exist on
    // the remote which should create the account on the remote
    owner.sync().await?;

    let (new_folder, sync_error) =
        owner.create_folder("sync_folder".to_string()).await?;
    assert!(sync_error.is_none());

    // Open the new folder so we can get a copy of the data,
    // using the same vault data ensures the same identifier
    // which means we will trigger the WriteEvent::UpdateVault
    // path when sync happens
    owner.open_folder(&new_folder).await?;
    let mut vault = {
        let storage = owner.storage();
        let reader = storage.read().await;
        reader.current().unwrap().vault().clone()
    };

    // Need the vault passphrase to import a buffer
    let vault_passphrase = DelegatedPassphrase::find_vault_passphrase(
        owner.user().identity().keeper(),
        new_folder.id(),
    )
    .await?;

    // Make a change so we can assert on the new value
    vault.set_name("sync_folder_imported".to_string());

    // Encode for the import
    let buffer = encode(&vault).await?;

    owner
        .import_folder_buffer(buffer, vault_passphrase, true)
        .await?;

    // Pause a while to give the listener some time to process
    // the change notification
    tokio::time::sleep(Duration::from_millis(250)).await;

    // Expected folders on the local account must be computed
    // again after creating the new folder for the assertions
    let expected_summaries: Vec<Summary> = {
        let storage = owner.storage();
        let reader = storage.read().await;
        reader.state().summaries().to_vec()
    };

    // Get the remote out of the owner so we can
    // assert on equality between local and remote
    let mut provider = owner.delete_remote(&remote_origin).unwrap();
    let remote_provider = provider
        .as_any_mut()
        .downcast_mut::<RemoteBridge>()
        .expect("to be a remote provider");

    let mut provider = other_owner.delete_remote(&remote_origin).unwrap();
    let other_remote_provider = provider
        .as_any_mut()
        .downcast_mut::<RemoteBridge>()
        .expect("to be a remote provider");

    // Primary client
    assert_local_remote_vaults_eq(
        expected_summaries.clone(),
        &server_path,
        &mut owner,
        remote_provider,
    )
    .await?;

    assert_local_remote_events_eq(
        expected_summaries.clone(),
        &server_path,
        &mut owner,
        remote_provider,
    )
    .await?;

    // Secondary client
    assert_local_remote_vaults_eq(
        expected_summaries.clone(),
        &server_path,
        &mut owner,
        other_remote_provider,
    )
    .await?;

    assert_local_remote_events_eq(
        expected_summaries,
        &server_path,
        &mut other_owner,
        other_remote_provider,
    )
    .await?;

    Ok(())
}
