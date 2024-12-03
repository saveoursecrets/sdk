use crate::test_utils::{
    assert_local_remote_events_eq, mock::files::create_file_secret,
    num_events, simulate_device, spawn, teardown,
};
use anyhow::Result;
use sos_net::sdk::prelude::*;

/// Tests sending delete folder events to a remote.
#[tokio::test]
async fn network_sync_folder_delete() -> Result<()> {
    const TEST_ID: &str = "sync_folder_delete";
    //crate::test_utils::init_tracing();

    // Spawn a backend server and wait for it to be listening
    let server = spawn(TEST_ID, None, None).await?;

    // Prepare a mock device
    let mut device = simulate_device(TEST_ID, 1, Some(&server)).await?;
    let origin = device.origin.clone();
    let folders = device.folders.clone();

    let _original_summaries_len = folders.len();

    // Path that we expect the remote server to write to
    let server_path = server.account_path(device.owner.address());
    let address = device.owner.address().clone();

    let FolderCreate {
        folder: new_folder,
        sync_result,
        ..
    } = device
        .owner
        .create_folder("sync_delete_folder".to_string(), Default::default())
        .await?;
    assert!(sync_result.first_error().is_none());

    let (secret_id, _, _, file_name) =
        create_file_secret(&mut device.owner, &new_folder, None).await?;
    let file =
        ExternalFile::new(SecretPath(*new_folder.id(), secret_id), file_name);

    assert_eq!(3, num_events(&mut device.owner, new_folder.id()).await);

    let FolderDelete { sync_result, .. } =
        device.owner.delete_folder(&new_folder).await?;
    assert!(sync_result.first_error().is_none());

    let updated_summaries: Vec<Summary> = {
        let storage = device.owner.storage().await.unwrap();
        let reader = storage.read().await;
        reader.list_folders().to_vec()
    };

    assert_eq!(folders.len(), updated_summaries.len());

    let expected_vault_file = server_path
        .join(address.to_string())
        .join(format!("{}.{}", new_folder.id(), VAULT_EXT));

    let expected_event_file = server_path
        .join(address.to_string())
        .join(format!("{}.{}", new_folder.id(), EVENT_LOG_EXT));

    assert!(!vfs::try_exists(expected_vault_file).await?);
    assert!(!vfs::try_exists(expected_event_file).await?);

    // Check the file secret was deleted from the server
    let server_paths = server.paths(&address);
    let server_file_path = server_paths.file_location(
        file.vault_id(),
        file.secret_id(),
        file.file_name().to_string(),
    );
    assert!(!vfs::try_exists(server_file_path).await?);

    // Get the remote out of the owner so we can
    // assert on equality between local and remote
    let mut bridge = device.owner.remove_server(&origin).await?.unwrap();
    assert_local_remote_events_eq(
        folders.clone(),
        &mut device.owner,
        &mut bridge,
    )
    .await?;

    device.owner.sign_out().await?;
    teardown(TEST_ID).await;

    Ok(())
}
