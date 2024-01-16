use crate::test_utils::{
    assert_local_remote_events_eq, assert_local_remote_vaults_eq,
    simulate_device, spawn, teardown,
};
use anyhow::Result;
use sos_net::{client::RemoteBridge, sdk::prelude::*};

const TEST_ID: &str = "sync_import_folder";

/// Tests sending import folder events to a remote.
#[tokio::test]
async fn integration_sync_import_folder() -> Result<()> {
    //crate::test_utils::init_tracing();

    // Spawn a backend server and wait for it to be listening
    let server = spawn(TEST_ID, None, None).await?;

    // Prepare a mock device
    let mut device = simulate_device(TEST_ID, 1, Some(&server)).await?;
    let origin = device.origin.clone();
    let server_path = device.server_path.clone();

    // Create a folder as we don't want an import to collide
    // with the default folder
    let FolderCreate{ folder: new_folder, sync_error, .. } = device
        .owner
        .create_folder("sync_folder".to_string())
        .await?;
    assert!(sync_error.is_none());

    // Open the new folder so we can get a copy of the data,
    // using the same vault data ensures the same identifier
    // which means we will trigger the WriteEvent::UpdateVault
    // path when sync happens
    device.owner.open_folder(&new_folder).await?;
    let mut vault = {
        let storage = device.owner.storage().await?;
        let reader = storage.read().await;
        let folder = reader.cache().get(new_folder.id()).unwrap();
        folder.keeper().vault().clone()
    };

    // Need the vault passphrase to import a buffer
    let vault_passphrase =
        device.owner.find_folder_password(new_folder.id()).await?;

    // Make a change so we can assert on the new value
    vault.set_name("sync_folder_imported".to_string());

    // Encode for the import
    let buffer = encode(&vault).await?;

    device
        .owner
        .import_folder_buffer(buffer, vault_passphrase, true)
        .await?;

    // Expected folders on the local account must be computed
    // again after creating the new folder for the assertions
    let folders: Vec<Summary> = {
        let storage = device.owner.storage().await?;
        let reader = storage.read().await;
        reader.list_folders().to_vec()
    };

    // Get the remote out of the owner so we can
    // assert on equality between local and remote
    let mut provider = device.owner.delete_remote(&origin).await?.unwrap();
    let remote_provider = provider
        .as_any_mut()
        .downcast_mut::<RemoteBridge>()
        .expect("to be a remote provider");

    assert_local_remote_vaults_eq(
        folders.clone(),
        &server_path,
        &mut device.owner,
        remote_provider,
    )
    .await?;

    assert_local_remote_events_eq(
        folders.clone(),
        &mut device.owner,
        remote_provider,
    )
    .await?;

    teardown(TEST_ID).await;

    Ok(())
}
