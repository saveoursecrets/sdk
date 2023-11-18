use anyhow::Result;
use serial_test::serial;
use std::{path::PathBuf, collections::HashMap};
use copy_dir::copy_dir;

use sos_net::{
    client::{
        user::{UserStorage, Origin, Remote},
        provider::RemoteProvider,
        RemoteSync,
    },
    sdk::{storage::AppPaths, vault::Summary},
};

use crate::test_utils::{
    create_local_account, mock_note, origin, setup, spawn,
};

use super::assert_local_remote_events_eq;

/// Tests sending events from changes to the local storage
/// to a connected remote.
#[tokio::test]
#[serial]
async fn integration_sync_send_events() -> Result<()> {
    // Prepare distinct data directories for the two clients
    let dirs = setup(2).await?;

    // Set up the paths for the first client
    let test_data_dir = dirs.clients.get(0).unwrap();
    AppPaths::set_data_dir(test_data_dir.clone());
    AppPaths::scaffold().await?;

    AppPaths::clear_data_dir();
    
    // Need to remove the other data dir as we will
    // copy the first data dir in later
    let other_data_dir = dirs.clients.get(1).unwrap();
    std::fs::remove_dir(&other_data_dir)?;
    
    // Spawn a backend server and wait for it to be listening
    let (rx, _handle) = spawn()?;
    let _ = rx.await?;

    let (mut owner, _, default_folder, passphrase) =
        create_local_account(
            "sync_basic_1",
            Some(test_data_dir.join("debug"))).await?;

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
    let provider = owner.create_remote_provider(&origin, None).await?;

    // Mimic account owner on another device connected to 
    // the same remotes
    let mut other_remotes: HashMap<Origin, Remote> = HashMap::new();
    other_remotes.insert(origin.clone(), Box::new(provider.clone()));
    
    // Copy the owner's account directory and sign in
    // using the alternative owner
    copy_dir(test_data_dir, other_data_dir)?;
    let mut other_owner = UserStorage::sign_in(
        owner.address(),
        passphrase,
        Some(other_remotes),
        Some(other_data_dir.join("debug")),
    ).await?;

    // Must list folders to load cache into memory after sign in
    other_owner.list_folders().await?;

    // Insert the remote for the other owner
    other_owner.insert_remote(origin.clone(), Box::new(provider.clone()));
    
    // Insert the remote for the primary owner
    owner.insert_remote(origin, Box::new(provider));

    // Sync a local account that does not exist on
    // the remote which should create the account on the remote
    owner.sync().await?;

    println!("Default folder {}", default_folder.id());

    owner.open_folder(&default_folder).await?;
    other_owner.open_folder(&default_folder).await?;
    
    /*
    let owner_paths = owner.paths().await;
    let other_owner_paths = other_owner.paths().await;

    println!("owner_paths {:#?}", owner_paths);
    println!("other_owner_paths {:#?}", other_owner_paths);
    */
    
    // Create a secret in the primary owner which won't exist
    // in the second device
    let (meta, secret) = mock_note("note_first_owner", "send_events_secret");
    owner
        .create_secret(meta, secret, Default::default())
        .await?;
    
    // The other owner creates a secret which should trigger a pull
    // of the remote patch before applying changes
    let (meta, secret) = mock_note("note_second_owner", "send_events_secret");
    other_owner
        .create_secret(meta, secret, Default::default())
        .await?;
    
    // Get the remote out of the owner so we can
    // assert on equality between local and remote
    let mut provider = owner.delete_remote(&remote_origin).unwrap();
    let remote_provider = provider
        .as_any_mut()
        .downcast_mut::<RemoteProvider>()
        .expect("to be a remote provider");

    assert_local_remote_events_eq(
        expected_summaries,
        &server_path,
        &mut owner,
        remote_provider,
    )
    .await?;

    Ok(())
}
