use anyhow::Result;
use copy_dir::copy_dir;

use sos_net::{
    client::{RemoteBridge, RemoteSync, UserStorage},
    sdk::vault::Summary,
};

use crate::test_utils::{
    create_local_account, mock_note, setup, spawn, sync_pause, teardown,
};

use super::{assert_local_remote_events_eq, num_events};

const TEST_ID: &str = "sync_offline_manual";

/// Tests syncing events between two clients after
/// a server goes offline and a client commits changes
/// to local storage whilst disconnected.
#[tokio::test]
async fn integration_sync_offline_manual() -> Result<()> {
    //crate::test_utils::init_tracing();

    // Prepare distinct data directories for the two clients
    let dirs = setup(TEST_ID, 2).await?;

    // Set up the paths for the first client
    let test_data_dir = dirs.clients.get(0).unwrap();

    // Need to remove the other data dir as we will
    // copy the first data dir in later
    let other_data_dir = dirs.clients.get(1).unwrap();
    std::fs::remove_dir(&other_data_dir)?;

    // Spawn a backend server and wait for it to be listening
    let server = spawn(TEST_ID, None, None).await?;
    let addr = server.addr.clone();

    let (mut owner, _, default_folder, passphrase) =
        create_local_account(TEST_ID, Some(test_data_dir.clone())).await?;

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
    let _server_path = server.account_path(owner.address());

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
    owner.insert_remote(origin, Box::new(provider));

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

    // Oh no, the server has gone offline!
    drop(server);
    // Wait a while to make sure the server has gone
    sync_pause().await;

    // Perform all the basic CRUD operations to make sure
    // we are not affected by the remote being offline
    let (meta, secret) = mock_note("note", "offline_secret");
    let (id, sync_error) = owner
        .create_secret(meta, secret, Default::default())
        .await?;
    assert!(sync_error.is_some());
    let (_, _) = owner.read_secret(&id, Default::default()).await?;
    let (meta, secret) = mock_note("note_edited", "offline_secret_edit");
    let (_, sync_error) = owner
        .update_secret(&id, meta, Some(secret), Default::default(), None)
        .await?;
    assert!(sync_error.is_some());
    let sync_error = owner.delete_secret(&id, Default::default()).await?;
    assert!(sync_error.is_some());

    // The first client is now very much ahead of the second client
    assert_eq!(4, num_events(&mut owner, &default_folder_id).await);
    assert_eq!(1, num_events(&mut other_owner, &default_folder_id).await);

    // Let's bring the server back online using
    // the same bind address so we don't need to
    // update the remote origin
    let _server = spawn(TEST_ID, Some(addr), None).await?;

    // Client explicitly syncs with the remote, either
    // they detected the server was back online of maybe
    // they signed in again (which is a natural event to sync).
    //
    // This should push the local changes to the remote.
    owner.sync().await?;

    // The client explicitly sync from the other device too.
    other_owner.sync().await?;

    // Now both devices should be up to date
    assert_eq!(4, num_events(&mut owner, &default_folder_id).await);
    assert_eq!(4, num_events(&mut other_owner, &default_folder_id).await);

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

    assert_local_remote_events_eq(
        expected_summaries.clone(),
        &mut owner,
        remote_provider,
    )
    .await?;

    assert_local_remote_events_eq(
        expected_summaries,
        &mut other_owner,
        other_remote_provider,
    )
    .await?;

    teardown(TEST_ID).await;

    Ok(())
}
