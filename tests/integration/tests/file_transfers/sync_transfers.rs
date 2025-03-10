//! Tests for creating files before a remote server is configured
//! then starting a server, adding it to the client, syncing and
//! transferring the files to the server.
use crate::test_utils::{
    assert_local_remote_file_eq,
    mock::files::{create_attachment, create_file_secret},
    simulate_device, spawn, teardown, wait_for_num_transfers,
};
use anyhow::Result;
use sos_account::Account;
use sos_core::ExternalFile;
use sos_sdk::prelude::*;

/// Tests creating external files then adding a remote
/// server, syncing and uploading the files.
///
/// This differs from the late upload test in that we
/// first wipe out any pending transfers and use
/// the transfers computed when `sync_file_transfers()`
/// is called internally when the remote bridge creates
/// an account for the first time.
#[tokio::test]
async fn file_transfers_sync_file_transfers() -> Result<()> {
    const TEST_ID: &str = "file_transfers_sync_file_transfers";

    //crate::test_utils::init_tracing();

    // Prepare mock device
    let mut device = simulate_device(TEST_ID, 1, None).await?;
    let default_folder = device.owner.default_folder().await.unwrap();

    // Files to assert on after uploading
    let mut files = Vec::new();

    // Create an external file secret
    let (secret_id, _, _, file_name) =
        create_file_secret(&mut device.owner, &default_folder, None).await?;
    files.push(ExternalFile::new(
        SecretPath(*default_folder.id(), secret_id),
        file_name,
    ));

    // Add an attachment to the secret
    let (_, _, file_name) = create_attachment(
        &mut device.owner,
        &secret_id,
        &default_folder,
        None,
    )
    .await?;
    files.push(ExternalFile::new(
        SecretPath(*default_folder.id(), secret_id),
        file_name,
    ));

    // Spawn a backend server and wait for it to be listening
    let server = spawn(TEST_ID, None, None).await?;

    // Connect to the server which will perform an initial sync
    device.owner.add_server(server.origin.clone()).await?;

    // Wait until the transfers are completed
    wait_for_num_transfers(&device.owner, 2).await?;

    let server_paths = server.paths(device.owner.account_id());

    // Assert the files on disc are equal
    for file in files {
        assert_local_remote_file_eq(
            device.owner.paths(),
            &*server_paths,
            &file,
        )
        .await?;
    }

    device.owner.sign_out().await?;

    teardown(TEST_ID).await;

    Ok(())
}
