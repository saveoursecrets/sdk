use crate::test_utils::{
    assert_local_remote_events_eq, mock, simulate_device, spawn, sync_pause,
    teardown,
};
use anyhow::Result;
use sos_net::sdk::prelude::*;

/// Tests syncing update folder events between two clients
/// where the second client listens for changes emitted
/// by the first client via the remote.
#[tokio::test]
async fn network_sync_listen_folder_import() -> Result<()> {
    const TEST_ID: &str = "sync_listen_folder_import";
    //crate::test_utils::init_tracing();

    // Spawn a backend server and wait for it to be listening
    let server = spawn(TEST_ID, None, None).await?;

    // Prepare mock devices
    let mut device1 = simulate_device(TEST_ID, 2, Some(&server)).await?;
    let origin = device1.origin.clone();
    let mut device2 = device1.connect(1, None).await?;

    // Start listening for change notifications
    device1.listen().await?;
    device2.listen().await?;

    let FolderCreate {
        folder: new_folder,
        sync_result,
        ..
    } = device1
        .owner
        .create_folder("sync_folder".to_string(), Default::default())
        .await?;
    assert!(sync_result.first_error().is_none());

    // Open the new folder so we can get a copy of the data,
    // using the same vault data ensures the same identifier
    // which means we will trigger the WriteEvent::UpdateVault
    // path when sync happens
    device1.owner.open_folder(&new_folder).await?;
    let mut vault = {
        let storage = device1.owner.storage().await.unwrap();
        let reader = storage.read().await;
        let folder = reader.cache().get(new_folder.id()).unwrap();
        folder.keeper().vault().clone()
    };

    // Need the vault passphrase to import a buffer
    let vault_passphrase = device1
        .owner
        .find_folder_password(new_folder.id())
        .await?
        .unwrap();

    // Make a change so we can assert on the new value
    vault.set_name("sync_folder_imported".to_string());

    // Encode for the import
    let buffer = encode(&vault).await?;
    device1
        .owner
        .import_folder_buffer(buffer, vault_passphrase, true)
        .await?;

    // Pause a while to give the listener some time to process
    // the change notification
    sync_pause(Some(1500)).await;

    // Ensure we can open and write to the synced folder
    device2.owner.open_folder(&new_folder).await?;
    let (meta, secret) =
        mock::note("note_second_owner", "listen_import_folder");
    let result = device2
        .owner
        .create_secret(meta, secret, Default::default())
        .await?;
    assert!(result.sync_result.first_error().is_none());

    // Pause a while to allow the first owner to sync
    // with the new change
    sync_pause(None).await;

    // Expected folders on the local account must be computed
    // again after creating the new folder for the assertions
    let expected_summaries: Vec<Summary> = {
        let storage = device1.owner.storage().await.unwrap();
        let reader = storage.read().await;
        reader.list_folders().to_vec()
    };

    // Assert first device
    let mut bridge = device1.owner.remove_server(&origin).await?.unwrap();
    assert_local_remote_events_eq(
        expected_summaries.clone(),
        &mut device1.owner,
        &mut bridge,
    )
    .await?;

    // Assert second device
    let mut bridge = device2.owner.remove_server(&origin).await?.unwrap();
    assert_local_remote_events_eq(
        expected_summaries,
        &mut device2.owner,
        &mut bridge,
    )
    .await?;

    device1.owner.sign_out().await?;
    device2.owner.sign_out().await?;

    teardown(TEST_ID).await;

    Ok(())
}
