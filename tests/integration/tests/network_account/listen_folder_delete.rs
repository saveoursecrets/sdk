use crate::test_utils::{simulate_device, spawn, teardown, wait_for_cond};
use anyhow::Result;
use sos_account::{Account, FolderCreate, FolderDelete};
use sos_client_storage::NewFolderOptions;
use sos_sdk::prelude::*;
use sos_vfs as vfs;

/// Tests syncing delete folder events between two clients
/// where the second client listens for changes emitted
/// by the first client via the remote.
#[tokio::test]
async fn network_sync_listen_folder_delete() -> Result<()> {
    const TEST_ID: &str = "sync_listen_folder_delete";
    //crate::test_utils::init_tracing();

    // Spawn a backend server and wait for it to be listening
    let server = spawn(TEST_ID, None, None).await?;

    // Prepare mock devices
    let mut device1 = simulate_device(TEST_ID, 2, Some(&server)).await?;
    let _default_folder_id = device1.default_folder_id.clone();
    let folders = device1.folders.clone();
    let mut device2 = device1.connect(1, None).await?;

    let server_paths = server.paths(device1.owner.account_id());

    // Start listening for change notifications
    device1.listen().await?;
    device2.listen().await?;

    let FolderCreate {
        folder: new_folder,
        sync_result,
        ..
    } = device1
        .owner
        .create_folder(NewFolderOptions::new("sync_folder".to_string()))
        .await?;
    assert!(sync_result.first_error().is_none());

    let FolderDelete { sync_result, .. } =
        device1.owner.delete_folder(new_folder.id()).await?;
    assert!(sync_result.first_error().is_none());

    let mut server_files = vec![
        server_paths.vault_path(new_folder.id()),
        server_paths.event_log_path(new_folder.id()),
    ];

    let mut device1_files = vec![
        device1.owner.paths().vault_path(new_folder.id()),
        device1.owner.paths().event_log_path(new_folder.id()),
    ];

    let mut device2_files = vec![
        device2.owner.paths().vault_path(new_folder.id()),
        device2.owner.paths().event_log_path(new_folder.id()),
    ];

    let mut wait_files = Vec::new();
    wait_files.extend_from_slice(&server_files);
    wait_files.extend_from_slice(&device1_files);
    wait_files.extend_from_slice(&device2_files);

    wait_for_cond(move || wait_files.iter().all(|p| !p.exists())).await;

    let updated_summaries: Vec<Summary> =
        device1.owner.list_folders().await?;
    assert_eq!(folders.len(), updated_summaries.len());

    assert!(!vfs::try_exists(server_files.remove(0)).await?);
    assert!(!vfs::try_exists(server_files.remove(0)).await?);

    assert!(!vfs::try_exists(device1_files.remove(0)).await?);
    assert!(!vfs::try_exists(device1_files.remove(0)).await?);

    assert!(!vfs::try_exists(device2_files.remove(0)).await?);
    assert!(!vfs::try_exists(device2_files.remove(0)).await?);

    device1.owner.sign_out().await?;
    device2.owner.sign_out().await?;

    teardown(TEST_ID).await;

    Ok(())
}
