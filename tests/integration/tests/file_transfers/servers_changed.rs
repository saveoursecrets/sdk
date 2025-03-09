//! Test for single server file transfers whilst
//! the server is online.
use anyhow::Result;

use crate::test_utils::{
    assert_local_remote_file_eq, mock::files::create_file_secret,
    simulate_device, spawn, teardown, wait_for_num_transfers,
};
use sos_account::Account;
use sos_core::ExternalFile;
use sos_sdk::prelude::*;

/// Tests uploading an external file to a server that was
/// added.
#[tokio::test]
async fn file_transfers_servers_changed_upload() -> Result<()> {
    const TEST_ID: &str = "file_transfers_servers_changed_upload";

    //crate::test_utils::init_tracing();

    // Spawn a backend server and wait for it to be listening
    let server = spawn(TEST_ID, None, Some("server")).await?;

    // Prepare mock device connected to the first server
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

    // Start a new server
    let server2 = spawn(TEST_ID, None, Some("server2")).await?;
    let new_origin = server2.origin.clone();

    // Add the new server which triggers an initial sync
    // which in turn will queue the file transfers for upload
    device.owner.add_server(new_origin).await?;

    // Wait until the transfers are completed
    wait_for_num_transfers(&device.owner, 1).await?;

    device.owner.sign_out().await?;

    teardown(TEST_ID).await;

    Ok(())
}
