//! Test for multiple server file transfers whilst
//! the first server is offline and the second server
//! is online.
use anyhow::Result;

use crate::test_utils::{
    assert_local_remote_file_eq, assert_local_remote_file_not_exist,
    mock::files::net::{create_file_secret, update_file_secret},
    simulate_device, spawn, sync_pause, teardown, wait_for_transfers,
};
use sos_net::{client::RemoteSync, sdk::prelude::*};

/// Tests uploading an external file to multiple servers
/// when the first server is offline.
#[tokio::test]
async fn file_transfers_multi_first_offline_upload() -> Result<()> {
    const TEST_ID: &str = "file_transfers_multi_first_offline_upload";

    //crate::test_utils::init_tracing();

    // Spawn some backend servers
    let server1 = spawn(TEST_ID, None, Some("server1")).await?;
    let addr = server1.addr.clone();
    let server2 = spawn(TEST_ID, None, Some("server2")).await?;
    let origin = server2.origin.clone();

    // Prepare mock device
    let mut device = simulate_device(TEST_ID, &server1, 1).await?;
    let address = device.owner.address().clone();
    let default_folder = device.owner.default_folder().await.unwrap();
    device.owner.add_server(origin).await?;

    // Shutdown the first server
    drop(server1);

    // Create an external file secret
    let (secret_id, _, _, file_name) =
        create_file_secret(&mut device.owner, &default_folder, None).await?;
    let file = ExternalFile::new(*default_folder.id(), secret_id, file_name);

    // Wait a while which should give the second server time
    // to complete the operation
    sync_pause(Some(1000)).await;

    let server1_path = device.server_path;
    let server2_path =
        server2.path.join(REMOTE_DIR).join(address.to_string());

    // Assert the files on server2 are equal
    assert_local_remote_file_eq(device.owner.paths(), &server2_path, &file)
        .await?;

    // Bring the server back online
    let server1 = spawn(TEST_ID, Some(addr), Some("server1")).await?;

    // Wait for the transfers to complete
    wait_for_transfers(&device.owner).await?;

    // Assert the files on server1 are equal
    assert_local_remote_file_eq(device.owner.paths(), &server1_path, &file)
        .await?;

    teardown(TEST_ID).await;

    Ok(())
}

/// Tests uploading an external file after updating
/// the file content on multiple servers.
#[tokio::test]
async fn file_transfers_multi_first_offline_update() -> Result<()> {
    const TEST_ID: &str = "file_transfers_multi_first_offline_update";

    //crate::test_utils::init_tracing();

    // Spawn some backend servers
    let server1 = spawn(TEST_ID, None, Some("server1")).await?;
    let addr = server1.addr.clone();
    let server2 = spawn(TEST_ID, None, Some("server2")).await?;
    let origin = server2.origin.clone();

    // Prepare mock device
    let mut device = simulate_device(TEST_ID, &server1, 1).await?;
    let address = device.owner.address().clone();
    let default_folder = device.owner.default_folder().await.unwrap();
    device.owner.add_server(origin).await?;

    // Shutdown the first server
    drop(server1);

    // Create an external file secret
    let (secret_id, data, _, _) =
        create_file_secret(&mut device.owner, &default_folder, None).await?;

    // Wait a while which should give the second server time
    // to complete the operation
    sync_pause(Some(1000)).await;

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

    // Wait a while which should give the second server time
    // to complete the operation
    sync_pause(Some(1000)).await;

    let server1_path = device.server_path;
    let server2_path =
        server2.path.join(REMOTE_DIR).join(address.to_string());

    // Assert the files on server2 are equal
    assert_local_remote_file_eq(device.owner.paths(), &server2_path, &file)
        .await?;

    // Bring the server back online
    let server1 = spawn(TEST_ID, Some(addr), Some("server1")).await?;

    // Wait for the transfers to complete
    wait_for_transfers(&device.owner).await?;

    // Assert the files on server1 are equal
    assert_local_remote_file_eq(device.owner.paths(), &server1_path, &file)
        .await?;

    teardown(TEST_ID).await;

    Ok(())
}

/// Tests uploading an external file after moving
/// the secret to a different folder on multiple servers.
#[ignore = "flaky, sometimes test never completes: check wait_for_transfers()"]
#[tokio::test]
async fn file_transfers_multi_first_offline_move() -> Result<()> {
    const TEST_ID: &str = "file_transfers_multi_first_offline_move";

    //crate::test_utils::init_tracing();

    // Spawn some backend servers
    let server1 = spawn(TEST_ID, None, Some("server1")).await?;
    let addr = server1.addr.clone();
    let server2 = spawn(TEST_ID, None, Some("server2")).await?;
    let origin = server2.origin.clone();

    // Prepare mock device
    let mut device = simulate_device(TEST_ID, &server1, 1).await?;
    let address = device.owner.address().clone();
    let default_folder = device.owner.default_folder().await.unwrap();
    device.owner.add_server(origin).await?;

    // Shutdown the first server
    drop(server1);

    // Create an external file secret
    let (secret_id, _, _, file_name) =
        create_file_secret(&mut device.owner, &default_folder, None).await?;

    // Wait a while which should give the second server time
    // to complete the operation
    sync_pause(Some(1000)).await;

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

    // Wait a while which should give the second server time
    // to complete the operation
    sync_pause(Some(1000)).await;

    let server1_path = device.server_path;
    let server2_path =
        server2.path.join(REMOTE_DIR).join(address.to_string());

    // Assert the files on server2 are equal
    assert_local_remote_file_eq(device.owner.paths(), &server2_path, &file)
        .await?;

    // Bring the server back online
    let server1 = spawn(TEST_ID, Some(addr), Some("server1")).await?;

    //println!("waiting for transfers...");

    // Wait for the transfers to complete
    wait_for_transfers(&device.owner).await?;

    //println!("completed waiting for transfers...");

    // Assert the files on server1 are equal
    assert_local_remote_file_eq(device.owner.paths(), &server1_path, &file)
        .await?;

    teardown(TEST_ID).await;

    Ok(())
}

/// Tests uploading then deleting an external file on multiple servers.
#[tokio::test]
async fn file_transfers_multi_first_offline_delete() -> Result<()> {
    const TEST_ID: &str = "file_transfers_multi_first_offline_delete";

    //crate::test_utils::init_tracing();

    // Spawn some backend servers
    let server1 = spawn(TEST_ID, None, Some("server1")).await?;
    let addr = server1.addr.clone();
    let server2 = spawn(TEST_ID, None, Some("server2")).await?;
    let origin = server2.origin.clone();

    // Prepare mock device
    let mut device = simulate_device(TEST_ID, &server1, 1).await?;
    let address = device.owner.address().clone();
    let default_folder = device.owner.default_folder().await.unwrap();
    device.owner.add_server(origin).await?;

    // Shutdown the first server
    drop(server1);

    // Create an external file secret
    let (secret_id, _, _, file_name) =
        create_file_secret(&mut device.owner, &default_folder, None).await?;
    let file = ExternalFile::new(*default_folder.id(), secret_id, file_name);

    // Wait a while which should give the second server time
    // to complete the operation
    sync_pause(Some(1000)).await;

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

    // Wait a while which should give the second server time
    // to complete the operation
    sync_pause(Some(1000)).await;

    let local_paths = device.owner.paths();

    // Assert the files on server2 do not exist
    assert_local_remote_file_not_exist(local_paths, &server2_path, &file)
        .await?;

    // Bring the server back online
    let server1 = spawn(TEST_ID, Some(addr), Some("server1")).await?;

    // Wait for the transfers to complete
    wait_for_transfers(&device.owner).await?;

    // Assert the files on server1 do not exist
    assert_local_remote_file_not_exist(local_paths, &server1_path, &file)
        .await?;

    teardown(TEST_ID).await;

    Ok(())
}

/// Tests uploading a file to multiple servers whilst one is
/// offline then downloading on a different device.
#[tokio::test]
async fn file_transfers_multi_first_offline_download() -> Result<()> {
    const TEST_ID: &str = "file_transfers_multi_first_offline_download";

    //crate::test_utils::init_tracing();

    // Spawn some backend servers
    let server1 = spawn(TEST_ID, None, Some("server1")).await?;
    let server2 = spawn(TEST_ID, None, Some("server2")).await?;
    let origin = server2.origin.clone();

    // Prepare mock device
    let mut uploader = simulate_device(TEST_ID, &server1, 2).await?;
    let address = uploader.owner.address().clone();
    let default_folder = uploader.owner.default_folder().await.unwrap();
    uploader.owner.add_server(origin.clone()).await?;

    let server1_path =
        server1.path.join(REMOTE_DIR).join(address.to_string());
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

        // Wait a while which should give the second server time
        // to complete the operation
        sync_pause(Some(1000)).await;

        assert_local_remote_file_eq(
            uploader.owner.paths(),
            &server2_path,
            &file,
        )
        .await?;

        file
    };

    {
        // Sync pulls down the file event logs and
        // creates the pending download transfer operation
        //
        // We have an error here as the first server will fail
        // to connect for the sync.
        let sync_error = downloader.owner.sync().await;
        assert!(sync_error.is_some());

        wait_for_transfers(&downloader.owner).await?;

        assert_local_remote_file_eq(
            downloader.owner.paths(),
            &server2_path,
            &file,
        )
        .await?;
    }

    teardown(TEST_ID).await;

    Ok(())
}
