use anyhow::Result;
use copy_dir::copy_dir;
use serial_test::serial;
use std::{path::PathBuf, sync::Arc};

use sos_net::{
    client::{ListenOptions, RemoteBridge, RemoteSync, UserStorage},
    sdk::{account::DelegatedPassphrase, encode, vault::Summary},
};

use crate::test_utils::{
    create_local_account, setup, spawn, sync_pause,
};

use super::{
    assert_local_remote_events_eq, assert_local_remote_vaults_eq, num_events,
};

const TEST_ID: &str = "sync_listen_rename_folder";

/// Tests syncing folder rename events between two clients
/// where the second client listens for changes emitted
/// by the first client via the remote.
#[tokio::test]
#[serial]
async fn integration_listen_rename_folder() -> Result<()> {
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
    let server = spawn(None).await?;

    let (mut owner, _, default_folder, passphrase) = create_local_account(
        "sync_listen_rename_folder",
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
    let origin = server.origin.clone();
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
    owner.listen(&origin, ListenOptions::new("device_1".to_string())?)?;

    // Start listening for change notifications (second client)
    other_owner
        .listen(&origin, ListenOptions::new("device_2".to_string())?)?;

    let default_folder_id = *default_folder.id();
    owner.open_folder(&default_folder).await?;
    other_owner.open_folder(&default_folder).await?;

    // Before we begin both clients should have a single event
    assert_eq!(1, num_events(&mut owner, &default_folder_id).await);
    assert_eq!(1, num_events(&mut other_owner, &default_folder_id).await);

    // Sync a local account that does not exist on
    // the remote which should create the account on the remote
    owner.sync().await?;

    let sync_error = owner
        .rename_folder(&default_folder, "new_name".to_string())
        .await?;
    assert!(sync_error.is_none());

    // Pause a while to give the listener some time to process
    // the change notification
    sync_pause().await;

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
