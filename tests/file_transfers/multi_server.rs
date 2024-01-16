//! Test for multiple server file transfers whilst
//! the servers are online.
use anyhow::Result;

use crate::test_utils::{
    assert_local_remote_file_eq, assert_local_remote_file_not_exist,
    mock::files::{create_file_secret, update_file_secret},
    simulate_device, spawn, teardown, wait_for_transfers,
};
use sos_net::{client::RemoteSync, sdk::prelude::*};

/// Tests uploading an external file to multiple servers.
#[tokio::test]
async fn file_transfers_multi_upload() -> Result<()> {
    const TEST_ID: &str = "file_transfers_multi_upload";

    //crate::test_utils::init_tracing();

    // Spawn some backend servers
    let server1 = spawn(TEST_ID, None, Some("server1")).await?;
    let server2 = spawn(TEST_ID, None, Some("server2")).await?;
    let origin = server2.origin.clone();

    // Prepare mock device
    let mut device = simulate_device(TEST_ID, 1, Some(&server1)).await?;
    let address = device.owner.address().clone();
    let default_folder = device.owner.default_folder().await.unwrap();
    device.owner.add_server(origin).await?;

    // Create an external file secret
    let (secret_id, _, _, file_name) =
        create_file_secret(&mut device.owner, &default_folder, None).await?;
    let file = ExternalFile::new(*default_folder.id(), secret_id, file_name);

    // Wait until the transfers are completed
    wait_for_transfers(&device.owner).await?;

    let server1_path = device.server_path;
    let server2_path =
        server2.path.join(REMOTE_DIR).join(address.to_string());

    // Assert the files on server1 are equal
    assert_local_remote_file_eq(device.owner.paths(), &server1_path, &file)
        .await?;

    // Assert the files on server2 are equal
    assert_local_remote_file_eq(device.owner.paths(), &server2_path, &file)
        .await?;

    device.owner.sign_out().await?;

    teardown(TEST_ID).await;

    Ok(())
}

/// Tests uploading an external file after updating
/// the file content on multiple servers.
#[tokio::test]
async fn file_transfers_multi_update() -> Result<()> {
    const TEST_ID: &str = "file_transfers_multi_update";

    //crate::test_utils::init_tracing();

    // Spawn some backend servers
    let server1 = spawn(TEST_ID, None, Some("server1")).await?;
    let server2 = spawn(TEST_ID, None, Some("server2")).await?;
    let origin = server2.origin.clone();

    // Prepare mock device
    let mut device = simulate_device(TEST_ID, 1, Some(&server1)).await?;
    let address = device.owner.address().clone();
    let default_folder = device.owner.default_folder().await.unwrap();
    device.owner.add_server(origin).await?;

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

    let server1_path = device.server_path;
    let server2_path =
        server2.path.join(REMOTE_DIR).join(address.to_string());

    // Assert the files on server1 are equal
    assert_local_remote_file_eq(device.owner.paths(), &server1_path, &file)
        .await?;

    // Assert the files on server2 are equal
    assert_local_remote_file_eq(device.owner.paths(), &server2_path, &file)
        .await?;

    device.owner.sign_out().await?;

    teardown(TEST_ID).await;

    Ok(())
}

/// Tests uploading an external file after moving
/// the secret to a different folder on multiple servers.
#[tokio::test]
async fn file_transfers_multi_move() -> Result<()> {
    const TEST_ID: &str = "file_transfers_multi_move";

    //crate::test_utils::init_tracing();

    // Spawn some backend servers
    let server1 = spawn(TEST_ID, None, Some("server1")).await?;
    let server2 = spawn(TEST_ID, None, Some("server2")).await?;
    let origin = server2.origin.clone();

    // Prepare mock device
    let mut device = simulate_device(TEST_ID, 1, Some(&server1)).await?;
    let address = device.owner.address().clone();
    let default_folder = device.owner.default_folder().await.unwrap();
    device.owner.add_server(origin).await?;

    // Create an external file secret
    let (secret_id, _, _, file_name) =
        create_file_secret(&mut device.owner, &default_folder, None).await?;

    // Wait until the upload is completed
    wait_for_transfers(&device.owner).await?;

    // Create a folder
    let FolderCreate {
        folder: destination,
        ..
    } = device.owner.create_folder("new_folder".to_owned()).await?;

    // Moving the secret also needs to move the file
    let SecretMove { id: secret_id, .. } = device
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

    let server1_path = device.server_path;
    let server2_path =
        server2.path.join(REMOTE_DIR).join(address.to_string());

    // Assert the files on server1 are equal
    assert_local_remote_file_eq(device.owner.paths(), &server1_path, &file)
        .await?;

    // Assert the files on server2 are equal
    assert_local_remote_file_eq(device.owner.paths(), &server2_path, &file)
        .await?;

    device.owner.sign_out().await?;

    teardown(TEST_ID).await;

    Ok(())
}

/// Tests uploading then deleting an external file on multiple servers.
#[tokio::test]
async fn file_transfers_multi_delete() -> Result<()> {
    const TEST_ID: &str = "file_transfers_multi_delete";

    //crate::test_utils::init_tracing();

    // Spawn some backend servers
    let server1 = spawn(TEST_ID, None, Some("server1")).await?;
    let server2 = spawn(TEST_ID, None, Some("server2")).await?;
    let origin = server2.origin.clone();

    // Prepare mock device
    let mut device = simulate_device(TEST_ID, 1, Some(&server1)).await?;
    let address = device.owner.address().clone();
    let default_folder = device.owner.default_folder().await.unwrap();
    device.owner.add_server(origin).await?;

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

    let server1_path = device.server_path;
    let server2_path =
        server2.path.join(REMOTE_DIR).join(address.to_string());

    // Assert the files on server1 do not exist
    assert_local_remote_file_not_exist(local_paths, &server1_path, &file)
        .await?;

    // Assert the files on server2 do not exist
    assert_local_remote_file_not_exist(local_paths, &server2_path, &file)
        .await?;

    device.owner.sign_out().await?;

    teardown(TEST_ID).await;

    Ok(())
}

/// Tests uploaded a file to multiple servers then downloading
/// on a different device.
#[tokio::test]
async fn file_transfers_multi_download() -> Result<()> {
    const TEST_ID: &str = "file_transfers_multi_download";

    //crate::test_utils::init_tracing();

    // Spawn some backend servers
    let server1 = spawn(TEST_ID, None, Some("server1")).await?;
    let server2 = spawn(TEST_ID, None, Some("server2")).await?;
    let origin = server2.origin.clone();

    // Prepare mock device
    let mut uploader = simulate_device(TEST_ID, 2, Some(&server1)).await?;
    let address = uploader.owner.address().clone();
    let default_folder = uploader.owner.default_folder().await.unwrap();
    uploader.owner.add_server(origin).await?;
    let mut downloader = uploader.connect(1, None).await?;

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

        let server1_path = downloader.server_path;
        let server2_path =
            server2.path.join(REMOTE_DIR).join(address.to_string());

        assert_local_remote_file_eq(
            downloader.owner.paths(),
            &server1_path,
            &file,
        )
        .await?;

        assert_local_remote_file_eq(
            downloader.owner.paths(),
            &server2_path,
            &file,
        )
        .await?;
    }

    uploader.owner.sign_out().await?;
    downloader.owner.sign_out().await?;

    teardown(TEST_ID).await;

    Ok(())
}
