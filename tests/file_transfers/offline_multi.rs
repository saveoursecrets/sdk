//! Test for multiple server file transfers whilst
//! the first server is offline and the second server
//! is online.
use anyhow::Result;

use crate::test_utils::{
    assert_local_remote_file_eq, assert_local_remote_file_not_exist,
    mock::files::{create_file_secret, update_file_secret},
    simulate_device, spawn, teardown, wait_for_file, wait_for_file_not_exist,
};
use sos_net::{client::RemoteSync, sdk::prelude::*};

/// Tests uploading an external file to multiple servers
/// when the first server is offline.
#[tokio::test]
async fn file_transfers_offline_multi_upload() -> Result<()> {
    const TEST_ID: &str = "file_transfers_offline_multi_upload";

    //crate::test_utils::init_tracing();

    // Spawn some backend servers
    let server1 = spawn(TEST_ID, None, Some("server1")).await?;
    let addr = server1.addr.clone();
    let server2 = spawn(TEST_ID, None, Some("server2")).await?;
    let origin = server2.origin.clone();

    // Prepare mock device
    let mut device = simulate_device(TEST_ID, 1, Some(&server1)).await?;
    let address = device.owner.address().clone();
    let default_folder = device.owner.default_folder().await.unwrap();
    device.owner.add_server(origin).await?;

    let server1_paths = server1.paths(&address);
    let server2_paths = server2.paths(&address);

    // Shutdown the first server
    drop(server1);

    // Create an external file secret
    let (secret_id, _, _, file_name) =
        create_file_secret(&mut device.owner, &default_folder, None).await?;
    let file = ExternalFile::new(*default_folder.id(), secret_id, file_name);

    // Wait for the file to exist
    wait_for_file(&server2_paths, &file).await?;

    let server1_path = device.server_path;
    let server2_path =
        server2.path.join(REMOTE_DIR).join(address.to_string());

    // Assert the files on server2 are equal
    assert_local_remote_file_eq(device.owner.paths(), &server2_path, &file)
        .await?;

    // Bring the server back online
    let _server1 = spawn(TEST_ID, Some(addr), Some("server1")).await?;

    // Wait for the file to exist
    wait_for_file(&server1_paths, &file).await?;

    // Assert the files on server1 are equal
    assert_local_remote_file_eq(device.owner.paths(), &server1_path, &file)
        .await?;

    device.owner.sign_out().await?;

    teardown(TEST_ID).await;

    Ok(())
}

/// Tests uploading an external file after updating
/// the file content on multiple servers.
#[tokio::test]
async fn file_transfers_offline_multi_update() -> Result<()> {
    const TEST_ID: &str = "file_transfers_offline_multi_update";

    //crate::test_utils::init_tracing();

    // Spawn some backend servers
    let server1 = spawn(TEST_ID, None, Some("server1")).await?;
    let addr = server1.addr.clone();
    let server2 = spawn(TEST_ID, None, Some("server2")).await?;
    let origin = server2.origin.clone();

    // Prepare mock device
    let mut device = simulate_device(TEST_ID, 1, Some(&server1)).await?;
    let address = device.owner.address().clone();
    let default_folder = device.owner.default_folder().await.unwrap();
    device.owner.add_server(origin).await?;

    let server1_paths = server1.paths(&address);
    let server2_paths = server2.paths(&address);

    // Shutdown the first server
    drop(server1);

    // Create an external file secret
    let (secret_id, data, _, file_name) =
        create_file_secret(&mut device.owner, &default_folder, None).await?;
    let file = ExternalFile::new(*default_folder.id(), secret_id, file_name);

    // Wait for the file to exist
    wait_for_file(&server2_paths, &file).await?;

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

    // Wait for the file to exist
    wait_for_file(&server2_paths, &file).await?;

    let server1_path = device.server_path;
    let server2_path =
        server2.path.join(REMOTE_DIR).join(address.to_string());

    // Assert the files on server2 are equal
    assert_local_remote_file_eq(device.owner.paths(), &server2_path, &file)
        .await?;

    // Bring the server back online
    let _server1 = spawn(TEST_ID, Some(addr), Some("server1")).await?;

    // Wait for the file to exist
    wait_for_file(&server1_paths, &file).await?;

    // Assert the files on server1 are equal
    assert_local_remote_file_eq(device.owner.paths(), &server1_path, &file)
        .await?;

    device.owner.sign_out().await?;

    teardown(TEST_ID).await;

    Ok(())
}

/// Tests uploading an external file after moving
/// the secret to a different folder on multiple servers.
#[tokio::test]
async fn file_transfers_offline_multi_move() -> Result<()> {
    const TEST_ID: &str = "file_transfers_offline_multi_move";

    //crate::test_utils::init_tracing();

    // Spawn some backend servers
    let server1 = spawn(TEST_ID, None, Some("server1")).await?;
    let addr = server1.addr.clone();
    let server2 = spawn(TEST_ID, None, Some("server2")).await?;
    let origin = server2.origin.clone();

    // Prepare mock device
    let mut device = simulate_device(TEST_ID, 1, Some(&server1)).await?;
    let address = device.owner.address().clone();
    let default_folder = device.owner.default_folder().await.unwrap();
    device.owner.add_server(origin).await?;

    let server1_paths = server1.paths(&address);
    let server2_paths = server2.paths(&address);

    // Shutdown the first server
    drop(server1);

    // Create an external file secret
    let (secret_id, _, _, file_name) =
        create_file_secret(&mut device.owner, &default_folder, None).await?;
    let file = ExternalFile::new(*default_folder.id(), secret_id, file_name);

    // Wait for the file to exist
    wait_for_file(&server2_paths, &file).await?;

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

    // Wait for the file to exist
    wait_for_file(&server2_paths, &file).await?;

    let server1_path = device.server_path;
    let server2_path =
        server2.path.join(REMOTE_DIR).join(address.to_string());

    // Assert the files on server2 are equal
    assert_local_remote_file_eq(device.owner.paths(), &server2_path, &file)
        .await?;

    // Bring the server back online
    let _server1 = spawn(TEST_ID, Some(addr), Some("server1")).await?;

    // Wait for the file to exist
    wait_for_file(&server1_paths, &file).await?;

    //println!("Move completed waiting for file on server1");

    // Assert the files on server1 are equal
    assert_local_remote_file_eq(device.owner.paths(), &server1_path, &file)
        .await?;

    device.owner.sign_out().await?;

    teardown(TEST_ID).await;

    Ok(())
}

/// Tests uploading then deleting an external file on multiple servers.
#[tokio::test]
async fn file_transfers_offline_multi_delete() -> Result<()> {
    const TEST_ID: &str = "file_transfers_offline_multi_delete";

    //crate::test_utils::init_tracing();

    // Spawn some backend servers
    let server1 = spawn(TEST_ID, None, Some("server1")).await?;
    let addr = server1.addr.clone();
    let server2 = spawn(TEST_ID, None, Some("server2")).await?;
    let origin = server2.origin.clone();

    // Prepare mock device
    let mut device = simulate_device(TEST_ID, 1, Some(&server1)).await?;
    let address = device.owner.address().clone();
    let default_folder = device.owner.default_folder().await.unwrap();
    device.owner.add_server(origin).await?;

    let server1_paths = server1.paths(&address);
    let server2_paths = server2.paths(&address);

    // Shutdown the first server
    drop(server1);

    // Create an external file secret
    let (secret_id, _, _, file_name) =
        create_file_secret(&mut device.owner, &default_folder, None).await?;
    let file = ExternalFile::new(*default_folder.id(), secret_id, file_name);

    // Wait for the file to exist
    wait_for_file(&server2_paths, &file).await?;

    let server1_path = device.server_path;
    let server2_path =
        server2.path.join(REMOTE_DIR).join(address.to_string());

    // Assert the files on server2 are equal
    assert_local_remote_file_eq(device.owner.paths(), &server2_path, &file)
        .await?;

    // Delete the secret and corresponding file
    device
        .owner
        .delete_secret(&secret_id, Default::default())
        .await?;

    // Wait for the file to be deleted
    wait_for_file_not_exist(&server2_paths, &file).await?;

    // Assert the files on server2 do not exist
    assert_local_remote_file_not_exist(
        device.owner.paths(),
        &server2_path,
        &file,
    )
    .await?;

    // Bring the server back online
    let _server1 = spawn(TEST_ID, Some(addr), Some("server1")).await?;

    // Wait for the file to be deleted
    wait_for_file_not_exist(&server1_paths, &file).await?;

    // Assert the files on server1 do not exist
    assert_local_remote_file_not_exist(
        device.owner.paths(),
        &server1_path,
        &file,
    )
    .await?;

    device.owner.sign_out().await?;

    teardown(TEST_ID).await;

    Ok(())
}

/// Tests uploading a file to multiple servers whilst one is
/// offline then downloading on a different device.
#[tokio::test]
async fn file_transfers_offline_multi_download() -> Result<()> {
    const TEST_ID: &str = "file_transfers_offline_multi_download";

    //crate::test_utils::init_tracing();

    // Spawn some backend servers
    let server1 = spawn(TEST_ID, None, Some("server1")).await?;
    let addr = server1.addr.clone();
    let server2 = spawn(TEST_ID, None, Some("server2")).await?;
    let origin = server2.origin.clone();

    // Prepare mock device
    let mut uploader = simulate_device(TEST_ID, 2, Some(&server1)).await?;
    let address = uploader.owner.address().clone();
    let default_folder = uploader.owner.default_folder().await.unwrap();
    uploader.owner.add_server(origin.clone()).await?;

    let server2_paths = server2.paths(&address);
    let server2_path =
        server2.path.join(REMOTE_DIR).join(address.to_string());

    // Shutdown the first server
    drop(server1);

    let mut downloader = uploader.connect(1, None).await?;
    downloader.owner.add_server(origin).await?;

    // Create file secret then wait and assert on the upload
    let file = {
        // Create an external file secret
        let (secret_id, _, _, file_name) =
            create_file_secret(&mut uploader.owner, &default_folder, None)
                .await?;
        let file =
            ExternalFile::new(*default_folder.id(), secret_id, file_name);

        // Wait for the file to exist
        wait_for_file(&server2_paths, &file).await?;

        assert_local_remote_file_eq(
            uploader.owner.paths(),
            &server2_path,
            &file,
        )
        .await?;

        file
    };

    {
        // Must bring the server back online otherwise the pending
        // upload will prevent the test from completing
        let _server1 = spawn(TEST_ID, Some(addr), Some("server1")).await?;

        // Sync pulls down the file event logs and
        // creates the pending download transfer operation
        //
        // We have an error here as the first server will fail
        // to connect for the sync.
        let sync_error = downloader.owner.sync().await;
        assert!(sync_error.is_none());

        // Wait for the file to exist
        let paths = downloader.owner.paths();
        wait_for_file(paths, &file).await?;

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
