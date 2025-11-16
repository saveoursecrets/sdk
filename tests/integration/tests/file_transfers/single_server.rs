//! Test for single server file transfers whilst
//! the server is online.
use anyhow::Result;
use sos_client_storage::NewFolderOptions;

use sos_account::{Account, FolderCreate, SecretMove};
use sos_core::ExternalFile;
use sos_protocol::AccountSync;
use sos_sdk::prelude::*;
use sos_test_utils::{
    assert_local_remote_file_eq, assert_local_remote_file_not_exist,
    mock::files::{create_file_secret, update_file_secret},
    simulate_device, spawn, teardown, wait_for_num_transfers,
};

/// Tests uploading an external file.
#[tokio::test]
async fn file_transfers_single_upload() -> Result<()> {
    const TEST_ID: &str = "file_transfers_single_upload";

    //sos_test_utils::init_tracing();

    // Spawn a backend server and wait for it to be listening
    let server = spawn(TEST_ID, None, None).await?;

    // Prepare mock device
    let mut device = simulate_device(TEST_ID, 1, Some(&server)).await?;
    let default_folder = device.owner.default_folder().await.unwrap();

    // Create an external file secret
    let (secret_id, _, _, file_name) =
        create_file_secret(&mut device.owner, &default_folder, None).await?;
    let file = ExternalFile::new(
        SecretPath(*default_folder.id(), secret_id),
        file_name,
    );

    // Wait until the transfers are completed
    wait_for_num_transfers(&device.owner, 1).await?;

    let server_paths = server.paths(device.owner.account_id());

    // Assert the files on disc are equal
    assert_local_remote_file_eq(device.owner.paths(), &*server_paths, &file)
        .await?;

    device.owner.sign_out().await?;

    teardown(TEST_ID).await;

    Ok(())
}

/// Tests uploading an external file after updating
/// the file content.
#[tokio::test]
async fn file_transfers_single_update() -> Result<()> {
    const TEST_ID: &str = "file_transfers_single_update";

    //sos_test_utils::init_tracing();

    // Spawn a backend server and wait for it to be listening
    let server = spawn(TEST_ID, None, None).await?;

    // Prepare mock device
    let mut device = simulate_device(TEST_ID, 1, Some(&server)).await?;
    let default_folder = device.owner.default_folder().await.unwrap();

    // Create an external file secret
    let (secret_id, data, _, _) =
        create_file_secret(&mut device.owner, &default_folder, None).await?;

    // Wait for the upload event
    wait_for_num_transfers(&device.owner, 1).await?;

    // Update the file secret with new file content
    let (_, file_name) = update_file_secret(
        &mut device.owner,
        &default_folder,
        &data,
        None,
        None,
    )
    .await?;
    let file = ExternalFile::new(
        SecretPath(*default_folder.id(), secret_id),
        file_name,
    );

    // Wait until the transfers are completed
    wait_for_num_transfers(&device.owner, 2).await?;

    let server_paths = server.paths(device.owner.account_id());

    // Assert the files on disc are equal
    assert_local_remote_file_eq(device.owner.paths(), &*server_paths, &file)
        .await?;

    device.owner.sign_out().await?;

    teardown(TEST_ID).await;

    Ok(())
}

/// Tests uploading an external file after moving
/// the secret to a different folder.
#[tokio::test]
async fn file_transfers_single_move() -> Result<()> {
    const TEST_ID: &str = "file_transfers_single_move";

    //sos_test_utils::init_tracing();

    // Spawn a backend server and wait for it to be listening
    let server = spawn(TEST_ID, None, None).await?;

    // Prepare mock device
    let mut device = simulate_device(TEST_ID, 1, Some(&server)).await?;
    let default_folder = device.owner.default_folder().await.unwrap();

    // Create an external file secret
    let (secret_id, _, _, file_name) =
        create_file_secret(&mut device.owner, &default_folder, None).await?;

    // Wait until the upload is completed
    wait_for_num_transfers(&device.owner, 1).await?;

    // Create a folder
    let FolderCreate {
        folder: destination,
        ..
    } = device
        .owner
        .create_folder(NewFolderOptions::new("new_folder".to_owned()))
        .await?;

    // Moving the secret also needs to move the file
    let SecretMove { id: secret_id, .. } = device
        .owner
        .move_secret(
            &secret_id,
            default_folder.id(),
            destination.id(),
            Default::default(),
        )
        .await?;
    let file = ExternalFile::new(
        SecretPath(*destination.id(), secret_id),
        file_name,
    );

    // Wait until the move is completed
    wait_for_num_transfers(&device.owner, 1).await?;

    let server_paths = server.paths(device.owner.account_id());

    // Assert the files on disc are equal
    assert_local_remote_file_eq(device.owner.paths(), &*server_paths, &file)
        .await?;

    device.owner.sign_out().await?;

    teardown(TEST_ID).await;

    Ok(())
}

/// Tests uploading then deleting an external file.
#[tokio::test]
async fn file_transfers_single_delete() -> Result<()> {
    const TEST_ID: &str = "file_transfers_single_delete";

    //sos_test_utils::init_tracing();

    // Spawn a backend server and wait for it to be listening
    let server = spawn(TEST_ID, None, None).await?;

    // Prepare mock device
    let mut device = simulate_device(TEST_ID, 1, Some(&server)).await?;
    let default_folder = device.owner.default_folder().await.unwrap();

    // Create an external file secret
    let (secret_id, _, _, file_name) =
        create_file_secret(&mut device.owner, &default_folder, None).await?;
    let file = ExternalFile::new(
        SecretPath(*default_folder.id(), secret_id),
        file_name,
    );

    // Wait until the transfers are completed
    wait_for_num_transfers(&device.owner, 1).await?;

    let server_paths = server.paths(device.owner.account_id());

    // Assert the files on disc are equal
    assert_local_remote_file_eq(device.owner.paths(), &*server_paths, &file)
        .await?;

    device
        .owner
        .delete_secret(&secret_id, Default::default())
        .await?;

    // Wait until the transfers are completed
    wait_for_num_transfers(&device.owner, 1).await?;

    let local_paths = device.owner.paths();

    assert_local_remote_file_not_exist(local_paths, &*server_paths, &file)
        .await?;

    device.owner.sign_out().await?;

    teardown(TEST_ID).await;

    Ok(())
}

/// Tests downloading an uploaded file on a different device.
#[tokio::test]
async fn file_transfers_single_download() -> Result<()> {
    const TEST_ID: &str = "file_transfers_single_download";

    // sos_test_utils::init_tracing();

    // Spawn a backend server and wait for it to be listening
    let server = spawn(TEST_ID, None, None).await?;

    // Prepare mock devices
    let mut uploader = simulate_device(TEST_ID, 2, Some(&server)).await?;

    let default_folder = uploader.owner.default_folder().await.unwrap();
    let mut downloader = uploader.connect(1, None).await?;

    let uploader_server_paths = server.paths(uploader.owner.account_id());
    let downloader_server_paths = server.paths(downloader.owner.account_id());

    // Create file secret then wait and assert on the upload
    let file = {
        // Create an external file secret
        let (secret_id, _, _, file_name) =
            create_file_secret(&mut uploader.owner, &default_folder, None)
                .await?;
        let file = ExternalFile::new(
            SecretPath(*default_folder.id(), secret_id),
            file_name,
        );

        wait_for_num_transfers(&uploader.owner, 1).await?;

        assert_local_remote_file_eq(
            uploader.owner.paths(),
            &*uploader_server_paths,
            &file,
        )
        .await?;

        file
    };

    {
        // Sync pulls down the file event logs and
        // creates the pending download transfer operation
        assert!(downloader.owner.sync().await.first_error().is_none());

        wait_for_num_transfers(&downloader.owner, 1).await?;

        assert_local_remote_file_eq(
            downloader.owner.paths(),
            &*downloader_server_paths,
            &file,
        )
        .await?;
    }

    downloader.owner.sign_out().await?;
    uploader.owner.sign_out().await?;

    teardown(TEST_ID).await;

    Ok(())
}
