use anyhow::Result;
use serial_test::serial;
use std::path::PathBuf;

use sos_net::{
    client::{RemoteBridge, RemoteSync},
    sdk::vault::Summary,
};

use crate::test_utils::{
    create_local_account, origin, setup, spawn, mock_note,
};

use super::{assert_local_remote_events_eq, num_events};

/// Tests sending delete secret events to a remote.
#[tokio::test]
#[serial]
async fn integration_sync_delete_secret() -> Result<()> {
    //crate::test_utils::init_tracing();

    let dirs = setup(1).await?;
    let test_data_dir = dirs.clients.get(0).unwrap();

    // Spawn a backend server and wait for it to be listening
    let (rx, _handle) = spawn()?;
    let _ = rx.await?;

    let (mut owner, _, default_folder, _) = create_local_account(
        "sync_delete_secret",
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

    // Insert the remote for the primary owner
    owner.insert_remote(origin, Box::new(provider));

    let default_folder_id = *default_folder.id();
    owner.open_folder(&default_folder).await?;

    //println!("default folder {}", default_folder_id);

    // Before we begin the clients should have a single event
    assert_eq!(1, num_events(&mut owner, &default_folder_id).await);

    // Sync the local account to create the account on remote
    owner.sync().await?;

    // Create a secret
    let (meta, secret) = mock_note("note", "secret1");
    let (id, sync_error) = owner
        .create_secret(meta, secret, Default::default())
        .await?;
    assert!(sync_error.is_none());

    // Should have two events
    assert_eq!(2, num_events(&mut owner, &default_folder_id).await);

    let sync_error = owner.delete_secret(&id, Default::default()).await?;
    assert!(sync_error.is_none());

    // Should have three events
    assert_eq!(3, num_events(&mut owner, &default_folder_id).await);

    // Get the remote out of the owner so we can
    // assert on equality between local and remote
    let mut provider = owner.delete_remote(&remote_origin).unwrap();
    let remote_provider = provider
        .as_any_mut()
        .downcast_mut::<RemoteBridge>()
        .expect("to be a remote provider");

    assert_local_remote_events_eq(
        expected_summaries.clone(),
        &server_path,
        &mut owner,
        remote_provider,
    )
    .await?;

    Ok(())
}
