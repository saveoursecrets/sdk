//! Tests for file transfer normalization.
use crate::test_utils::{
    assert_local_remote_file_eq, assert_local_remote_file_not_exist,
    mock::files::create_file_secret, simulate_device, spawn, teardown,
    wait_for_transfers,
};
use anyhow::Result;
use sos_net::{client::RemoteSync, sdk::prelude::*};
use std::sync::Arc;

/// Tests creating then deleting an external file whilst
/// not connected to any servers and that the corresponding
/// transfer list is normalized just to a delete operation.
#[tokio::test]
async fn file_transfers_normalize_upload_delete() -> Result<()> {
    const TEST_ID: &str = "file_transfers_normalize_upload_delete";

    //crate::test_utils::init_tracing();

    // Prepare mock device
    let mut device = simulate_device(TEST_ID, 1, None).await?;
    let address = device.owner.address().clone();
    let default_folder = device.owner.default_folder().await.unwrap();

    // Create an external file secret
    let (secret_id, _, _, file_name) =
        create_file_secret(&mut device.owner, &default_folder, None).await?;
    let file = ExternalFile::new(*default_folder.id(), secret_id, file_name);

    // Delete the secret
    device
        .owner
        .delete_secret(&secret_id, Default::default())
        .await?;

    {
        // Before the transfer list is normalized we have
        // upload and delete operations
        let transfers = device.owner.transfers().await?;
        let mut transfers = transfers.write().await;
        let ops = transfers.queue().get(&file).unwrap().clone();
        let ops = ops.into_iter().collect::<Vec<_>>();
        assert!(matches!(ops.get(0), Some(&TransferOperation::Upload)));
        assert!(matches!(ops.get(1), Some(&TransferOperation::Delete)));

        // Normalize the transfers queue
        transfers
            .normalize(Arc::new(device.owner.paths().clone()))
            .await?;

        // Should now just have the delete operation
        let ops = transfers.queue().get(&file).unwrap().clone();
        let ops = ops.into_iter().collect::<Vec<_>>();
        assert!(matches!(ops.get(0), Some(&TransferOperation::Delete)));
    }

    // Spawn a backend server and wait for it to be listening
    let server = spawn(TEST_ID, None, None).await?;
    let server_paths = server.account_path(&address);

    // Connect to the server
    device.owner.add_server(server.origin.clone()).await?;

    // Wait until the transfers are completed
    wait_for_transfers(&device.owner).await?;

    // Assert the files do not exist on local and remote
    let local_paths = device.owner.paths();
    assert_local_remote_file_not_exist(local_paths, &server_paths, &file)
        .await?;

    device.owner.sign_out().await?;

    teardown(TEST_ID).await;

    Ok(())
}

/// Tests creating then moving an external file whilst
/// not connected to any servers and that the corresponding
/// transfer list is normalized.
#[tokio::test]
async fn file_transfers_normalize_move() -> Result<()> {
    const TEST_ID: &str = "file_transfers_normalize_move";

    //crate::test_utils::init_tracing();

    // Prepare mock device
    let mut device = simulate_device(TEST_ID, 1, None).await?;
    let address = device.owner.address().clone();
    let default_folder = device.owner.default_folder().await.unwrap();

    let mut not_exists = Vec::new();
    let mut exists = Vec::new();

    // Create an external file secret
    let (secret_id, _, _, file_name) =
        create_file_secret(&mut device.owner, &default_folder, None).await?;

    let old_file =
        ExternalFile::new(*default_folder.id(), secret_id, file_name);
    not_exists.push(old_file.clone());

    // Create a folder
    let FolderCreate {
        folder: destination,
        ..
    } = device.owner.create_folder("new_folder".to_owned()).await?;

    // Moving the secret also moves the files
    let SecretMove { id: secret_id, .. } = device
        .owner
        .move_secret(
            &secret_id,
            &default_folder,
            &destination,
            Default::default(),
        )
        .await?;

    let new_file = ExternalFile::new(*destination.id(), secret_id, file_name);
    exists.push(new_file.clone());

    {
        // Before the transfer list is normalized we have
        // upload and delete operations
        let transfers = device.owner.transfers().await?;
        let mut transfers = transfers.write().await;

        let ops = transfers.queue().get(&old_file).unwrap().clone();
        let ops = ops.into_iter().collect::<Vec<_>>();

        assert!(matches!(ops.get(0), Some(&TransferOperation::Upload)));
        assert!(matches!(ops.get(1), Some(&TransferOperation::Move(_))));

        // Normalize the transfers queue
        transfers
            .normalize(Arc::new(device.owner.paths().clone()))
            .await?;

        // Delete operation for the old file
        let ops = transfers.queue().get(&old_file).unwrap().clone();
        let ops = ops.into_iter().collect::<Vec<_>>();
        assert!(matches!(ops.get(0), Some(&TransferOperation::Delete)));

        // Upload operation for the new file
        let ops = transfers.queue().get(&new_file).unwrap().clone();
        let ops = ops.into_iter().collect::<Vec<_>>();
        assert!(matches!(ops.get(0), Some(&TransferOperation::Upload)));
    }

    // Spawn a backend server and wait for it to be listening
    let server = spawn(TEST_ID, None, None).await?;
    let server_paths = server.account_path(&address);

    // Connect to the server
    device.owner.add_server(server.origin.clone()).await?;

    // Must sync so the account is created on the server
    assert!(device.owner.sync().await.is_none());

    // Wait until the transfers are completed
    wait_for_transfers(&device.owner).await?;

    // Assert the old file do not exist on local and remote
    for file in &not_exists {
        assert_local_remote_file_not_exist(
            device.owner.paths(),
            &server_paths,
            file,
        )
        .await?;
    }

    // Assert the files on disc are equal
    for file in &exists {
        assert_local_remote_file_eq(
            device.owner.paths(),
            &server_paths,
            file,
        )
        .await?;
    }

    device.owner.sign_out().await?;

    teardown(TEST_ID).await;

    Ok(())
}
