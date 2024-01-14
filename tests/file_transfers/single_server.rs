//! Test for single server file transfers whilst
//! the server is online.
use anyhow::Result;

use crate::test_utils::{
    assert_local_remote_file_eq, assert_local_remote_file_not_exist,
    mock::files::net::{create_file_secret, update_file_secret},
    simulate_device, spawn, teardown, wait_for_transfers,
};
use sos_net::{client::RemoteSync, sdk::prelude::*};

/// Tests uploading an external file.
#[tokio::test]
async fn file_transfers_upload() -> Result<()> {
    const TEST_ID: &str = "file_transfers_upload";

    //crate::test_utils::init_tracing();

    // Spawn a backend server and wait for it to be listening
    let server = spawn(TEST_ID, None, None).await?;

    // Prepare mock device
    let mut device = simulate_device(TEST_ID, &server, 1).await?;
    let default_folder = device.owner.default_folder().await.unwrap();

    // Create an external file secret
    let (secret_id, _, _, file_name) =
        create_file_secret(&mut device.owner, &default_folder, None).await?;
    let file = ExternalFile::new(*default_folder.id(), secret_id, file_name);

    // Wait until the transfers are completed
    wait_for_transfers(&device.owner).await?;

    // Assert the files on disc are equal
    assert_local_remote_file_eq(
        device.owner.paths(),
        &device.server_path,
        &file,
    )
    .await?;

    teardown(TEST_ID).await;

    Ok(())
}

/// Tests uploading an external file after updating
/// the file content.
#[tokio::test]
async fn file_transfers_update() -> Result<()> {
    const TEST_ID: &str = "file_transfers_update";

    //crate::test_utils::init_tracing();

    // Spawn a backend server and wait for it to be listening
    let server = spawn(TEST_ID, None, None).await?;

    // Prepare mock device
    let mut device = simulate_device(TEST_ID, &server, 1).await?;
    let default_folder = device.owner.default_folder().await.unwrap();

    // Create an external file secret
    let (secret_id, _, _, _) =
        create_file_secret(&mut device.owner, &default_folder, None).await?;

    // Wait for the upload event
    wait_for_transfers(&device.owner).await?;

    let (data, _) = device.owner.read_secret(&secret_id, None).await?;

    // Update the file secret with new file content
    let (_, file_name) = update_file_secret(
        &mut device.owner,
        &default_folder,
        &data,
        None,
        None,
    )
    .await?;
    let file = ExternalFile::new(*default_folder.id(), secret_id, file_name);

    // Wait until the transfers are completed
    wait_for_transfers(&device.owner).await?;

    // Assert the files on disc are equal
    assert_local_remote_file_eq(
        device.owner.paths(),
        &device.server_path,
        &file,
    )
    .await?;

    teardown(TEST_ID).await;

    Ok(())
}

/// Tests uploading an external file after moving
/// the secret to a different folder.
#[tokio::test]
async fn file_transfers_move() -> Result<()> {
    const TEST_ID: &str = "file_transfers_move";

    //crate::test_utils::init_tracing();

    // Spawn a backend server and wait for it to be listening
    let server = spawn(TEST_ID, None, None).await?;

    // Prepare mock device
    let mut device = simulate_device(TEST_ID, &server, 1).await?;
    let default_folder = device.owner.default_folder().await.unwrap();

    // Create an external file secret
    let (secret_id, _, _, file_name) =
        create_file_secret(&mut device.owner, &default_folder, None).await?;

    // Wait until the upload is completed
    wait_for_transfers(&device.owner).await?;

    // Create a folder
    let (destination, _) =
        device.owner.create_folder("new_folder".to_owned()).await?;

    // Moving the secret also needs to move the file
    let ((secret_id, _), _) = device
        .owner
        .move_secret(
            &secret_id,
            &default_folder,
            &destination,
            Default::default(),
        )
        .await?;
    let file = ExternalFile::new(*destination.id(), secret_id, file_name);

    // Wait until the move is completed
    wait_for_transfers(&device.owner).await?;

    // Assert the files on disc are equal
    assert_local_remote_file_eq(
        device.owner.paths(),
        &device.server_path,
        &file,
    )
    .await?;

    teardown(TEST_ID).await;

    Ok(())
}

/// Tests uploading then deleting an external file.
#[tokio::test]
async fn file_transfers_delete() -> Result<()> {
    const TEST_ID: &str = "file_transfers_delete";

    //crate::test_utils::init_tracing();

    // Spawn a backend server and wait for it to be listening
    let server = spawn(TEST_ID, None, None).await?;

    // Prepare mock device
    let mut device = simulate_device(TEST_ID, &server, 1).await?;
    let default_folder = device.owner.default_folder().await.unwrap();

    // Create an external file secret
    let (secret_id, _, _, file_name) =
        create_file_secret(&mut device.owner, &default_folder, None).await?;
    let file = ExternalFile::new(*default_folder.id(), secret_id, file_name);

    // Wait until the transfers are completed
    wait_for_transfers(&device.owner).await?;

    // Assert the files on disc are equal
    assert_local_remote_file_eq(
        device.owner.paths(),
        &device.server_path,
        &file,
    )
    .await?;

    device
        .owner
        .delete_secret(&secret_id, Default::default())
        .await?;

    // Wait until the transfers are completed
    wait_for_transfers(&device.owner).await?;

    let local_paths = device.owner.paths();

    assert_local_remote_file_not_exist(
        local_paths,
        &device.server_path,
        &file,
    )
    .await?;

    teardown(TEST_ID).await;

    Ok(())
}

/// Tests downloading an uploaded file on a different device.
#[tokio::test]
async fn file_transfers_download() -> Result<()> {
    const TEST_ID: &str = "file_transfers_download";

    //crate::test_utils::init_tracing();

    // Spawn a backend server and wait for it to be listening
    let server = spawn(TEST_ID, None, None).await?;

    // Prepare mock devices
    let mut uploader = simulate_device(TEST_ID, &server, 2).await?;
    let default_folder = uploader.owner.default_folder().await.unwrap();

    let downloader = uploader.connect(1, None).await?;

    // Create file secret then wait and assert on the upload
    let file = {
        // Create an external file secret
        let (secret_id, _, _, file_name) =
            create_file_secret(&mut uploader.owner, &default_folder, None)
                .await?;
        let file =
            ExternalFile::new(*default_folder.id(), secret_id, file_name);
        wait_for_transfers(&uploader.owner).await?;
        assert_local_remote_file_eq(
            uploader.owner.paths(),
            &uploader.server_path,
            &file,
        )
        .await?;

        file
    };

    {
        // Sync pulls down the file event logs and
        // creates the pending download transfer operation
        assert!(downloader.owner.sync().await.is_none());

        wait_for_transfers(&downloader.owner).await?;

        assert_local_remote_file_eq(
            downloader.owner.paths(),
            &downloader.server_path,
            &file,
        )
        .await?;
    }

    teardown(TEST_ID).await;

    Ok(())
}
