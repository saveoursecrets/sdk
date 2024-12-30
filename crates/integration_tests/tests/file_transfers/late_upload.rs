//! Tests for creating files before a remote server is configured
//! then starting a server, adding it to the client, syncing and
//! transferring the files to the server.
use crate::test_utils::{
    assert_local_remote_file_eq,
    mock::files::{create_attachment, create_file_secret},
    simulate_device, spawn, teardown, wait_for_num_transfers,
};
use anyhow::Result;
use sos_account::{Account, FolderCreate, SecretMove};
use sos_core::ExternalFile;
use sos_net::sdk::prelude::*;

/// Tests creating external files then adding a remote
/// server, syncing and uploading the files.
#[tokio::test]
async fn file_transfers_late_upload() -> Result<()> {
    const TEST_ID: &str = "file_transfers_late_upload";

    // crate::test_utils::init_tracing();

    // Prepare mock device
    let mut device = simulate_device(TEST_ID, 1, None).await?;
    let address = device.owner.address().clone();
    let default_folder = device.owner.default_folder().await.unwrap();

    // Create an external file secret then delete it,
    let (secret_id, _, _, _) =
        create_file_secret(&mut device.owner, &default_folder, None).await?;
    device
        .owner
        .delete_secret(&secret_id, Default::default())
        .await?;

    // Files to assert on after uploading
    let mut files = Vec::new();

    // Create an external file secret
    let (secret_id, _, _, file_name) =
        create_file_secret(&mut device.owner, &default_folder, None).await?;
    files.push(ExternalFile::new(
        SecretPath(*default_folder.id(), secret_id),
        file_name,
    ));

    // Create a file secret and move to a different folder
    let (secret_id, _, _, file_name) =
        create_file_secret(&mut device.owner, &default_folder, None).await?;
    let FolderCreate {
        folder: destination,
        ..
    } = device
        .owner
        .create_folder("new_folder".to_owned(), Default::default())
        .await?;
    let SecretMove { id: secret_id, .. } = device
        .owner
        .move_secret(
            &secret_id,
            &default_folder,
            &destination,
            Default::default(),
        )
        .await?;
    files.push(ExternalFile::new(
        SecretPath(*destination.id(), secret_id),
        file_name,
    ));

    // Add an attachment to the moved secret
    let (_, _, file_name) =
        create_attachment(&mut device.owner, &secret_id, &destination, None)
            .await?;
    files.push(ExternalFile::new(
        SecretPath(*destination.id(), secret_id),
        file_name,
    ));

    // Spawn a backend server and wait for it to be listening
    let server = spawn(TEST_ID, None, None).await?;
    let server_paths = server.account_path(&address);

    // Connect to the server
    device.owner.add_server(server.origin.clone()).await?;

    // Wait until the transfers are completed
    wait_for_num_transfers(&device.owner, 3).await?;

    // Assert the files on disc are equal
    for file in files {
        assert_local_remote_file_eq(
            device.owner.paths(),
            &server_paths,
            &file,
        )
        .await?;
    }

    device.owner.sign_out().await?;

    teardown(TEST_ID).await;

    Ok(())
}
