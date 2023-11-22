use anyhow::Result;
use serial_test::serial;
use std::path::PathBuf;

use sos_net::{
    client::{RemoteBridge, RemoteSync},
    sdk::{account::DelegatedPassphrase, encode, vault::Summary},
};

use crate::test_utils::{
    create_local_account, mock_note, origin, setup, spawn,
};

use super::{
    assert_local_remote_events_eq, assert_local_remote_vaults_eq, num_events,
};

/// Tests sending import folder events to a remote.
#[tokio::test]
#[serial]
async fn integration_sync_import_folder() -> Result<()> {
    //crate::test_utils::init_tracing();

    let dirs = setup(1).await?;
    let test_data_dir = dirs.clients.get(0).unwrap();

    // Spawn a backend server and wait for it to be listening
    let (rx, _handle) = spawn()?;
    let _ = rx.await?;

    let (mut owner, _, default_folder, _) = create_local_account(
        "sync_import_folder",
        Some(test_data_dir.clone()),
    )
    .await?;

    // Folders on the local account must be loaded into memory
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

    // Before we begin the client should have a single event
    assert_eq!(1, num_events(&mut owner, &default_folder_id).await);

    // Sync the local account to create the account on remote
    owner.sync().await?;

    // Create a folder as we don't want an import to collide
    // with the default folder
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

    Ok(())
}
