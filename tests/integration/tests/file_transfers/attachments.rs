//! Tests for attachment external files.
use crate::test_utils::{
    assert_local_remote_file_eq, assert_local_remote_file_not_exist,
    mock::files::{create_attachment, create_file_secret, update_attachment},
    simulate_device, spawn, teardown, wait_for_num_transfers,
};
use anyhow::Result;
use sos_account::{Account, FolderCreate, SecretMove};
use sos_client_storage::NewFolderOptions;
use sos_core::ExternalFile;
use sos_sdk::prelude::*;

/// Tests creating an attachment.
#[tokio::test]
async fn file_transfers_attach_create() -> Result<()> {
    const TEST_ID: &str = "file_transfers_attach_create";

    // crate::test_utils::init_tracing();

    // Spawn a backend server and wait for it to be listening
    let server = spawn(TEST_ID, None, None).await?;

    // Prepare mock device
    let mut device = simulate_device(TEST_ID, 1, Some(&server)).await?;
    let default_folder = device.owner.default_folder().await.unwrap();

    let mut files = Vec::new();

    // Create an external file secret
    let (secret_id, _, _, file_name) =
        create_file_secret(&mut device.owner, &default_folder, None).await?;
    wait_for_num_transfers(&device.owner, 1).await?;
    files.push(ExternalFile::new(
        SecretPath(*default_folder.id(), secret_id),
        file_name,
    ));

    // Create an attachment
    let (_, _, file_name) = create_attachment(
        &mut device.owner,
        &secret_id,
        &default_folder,
        None,
    )
    .await?;
    wait_for_num_transfers(&device.owner, 1).await?;
    files.push(ExternalFile::new(
        SecretPath(*default_folder.id(), secret_id),
        file_name,
    ));

    let server_account_paths = server.paths(device.owner.account_id());

    // Assert the files on disc are equal
    for file in &files {
        assert_local_remote_file_eq(
            device.owner.paths(),
            &*server_account_paths,
            file,
        )
        .await?;
    }

    device.owner.sign_out().await?;

    teardown(TEST_ID).await;

    Ok(())
}

/// Tests updating an attachment.
#[tokio::test]
async fn file_transfers_attach_update() -> Result<()> {
    const TEST_ID: &str = "file_transfers_attach_update";

    //crate::test_utils::init_tracing();

    // Spawn a backend server and wait for it to be listening
    let server = spawn(TEST_ID, None, None).await?;

    // Prepare mock device
    let mut device = simulate_device(TEST_ID, 1, Some(&server)).await?;
    let default_folder = device.owner.default_folder().await.unwrap();

    let mut files = Vec::new();

    // Create an external file secret
    let (secret_id, _, _, file_name) =
        create_file_secret(&mut device.owner, &default_folder, None).await?;
    wait_for_num_transfers(&device.owner, 1).await?;
    files.push(ExternalFile::new(
        SecretPath(*default_folder.id(), secret_id),
        file_name,
    ));

    // Create an attachment
    let (attachment_id, mut secret_data, _) = create_attachment(
        &mut device.owner,
        &secret_id,
        &default_folder,
        None,
    )
    .await?;
    wait_for_num_transfers(&device.owner, 1).await?;

    // Update the attachment
    let (_, _, file_name) = update_attachment(
        &mut device.owner,
        &mut secret_data,
        &attachment_id,
        &default_folder,
        None,
    )
    .await?;

    wait_for_num_transfers(&device.owner, 2).await?;
    files.push(ExternalFile::new(
        SecretPath(*default_folder.id(), secret_id),
        file_name,
    ));

    let server_account_paths = server.paths(device.owner.account_id());

    // Assert the files on disc are equal
    for file in &files {
        assert_local_remote_file_eq(
            device.owner.paths(),
            &*server_account_paths,
            file,
        )
        .await?;
    }

    device.owner.sign_out().await?;

    teardown(TEST_ID).await;

    Ok(())
}

/// Tests moving a secret containing an attachment.
#[tokio::test]
async fn file_transfers_attach_move() -> Result<()> {
    const TEST_ID: &str = "file_transfers_attach_move";

    //crate::test_utils::init_tracing();

    // Spawn a backend server and wait for it to be listening
    let server = spawn(TEST_ID, None, None).await?;

    // Prepare mock device
    let mut device = simulate_device(TEST_ID, 1, Some(&server)).await?;
    let default_folder = device.owner.default_folder().await.unwrap();

    let mut files = Vec::new();

    // Create an external file secret
    let (secret_id, _, _, file_name) =
        create_file_secret(&mut device.owner, &default_folder, None).await?;
    wait_for_num_transfers(&device.owner, 1).await?;

    // Create an attachment
    let (_, _, attachment_file_name) = create_attachment(
        &mut device.owner,
        &secret_id,
        &default_folder,
        None,
    )
    .await?;
    wait_for_num_transfers(&device.owner, 1).await?;

    // Create a folder
    let FolderCreate {
        folder: destination,
        ..
    } = device
        .owner
        .create_folder(NewFolderOptions::new("new_folder".to_owned()))
        .await?;

    // Moving the secret also needs to move the files
    let SecretMove { id: secret_id, .. } = device
        .owner
        .move_secret(
            &secret_id,
            default_folder.id(),
            destination.id(),
            Default::default(),
        )
        .await?;

    // Use the new folder and secret identifiers after moving
    files.push(ExternalFile::new(
        SecretPath(*destination.id(), secret_id),
        file_name,
    ));
    files.push(ExternalFile::new(
        SecretPath(*destination.id(), secret_id),
        attachment_file_name,
    ));

    // Wait until the transfers are completed
    wait_for_num_transfers(&device.owner, 2).await?;

    let server_account_paths = server.paths(device.owner.account_id());

    // Assert the files on disc are equal
    for file in &files {
        assert_local_remote_file_eq(
            device.owner.paths(),
            &*server_account_paths,
            file,
        )
        .await?;
    }

    device.owner.sign_out().await?;

    teardown(TEST_ID).await;

    Ok(())
}

/// Tests creating then deleting an attachment.
#[tokio::test]
async fn file_transfers_attach_delete() -> Result<()> {
    const TEST_ID: &str = "file_transfers_attach_delete";

    //crate::test_utils::init_tracing();

    // Spawn a backend server and wait for it to be listening
    let server = spawn(TEST_ID, None, None).await?;

    // Prepare mock device
    let mut device = simulate_device(TEST_ID, 1, Some(&server)).await?;
    let default_folder = device.owner.default_folder().await.unwrap();

    let mut files = Vec::new();

    // Create an external file secret
    let (secret_id, _, _, file_name) =
        create_file_secret(&mut device.owner, &default_folder, None).await?;
    wait_for_num_transfers(&device.owner, 1).await?;
    files.push(ExternalFile::new(
        SecretPath(*default_folder.id(), secret_id),
        file_name,
    ));

    // Create an attachment
    let (_, _, file_name) = create_attachment(
        &mut device.owner,
        &secret_id,
        &default_folder,
        None,
    )
    .await?;
    wait_for_num_transfers(&device.owner, 1).await?;
    files.push(ExternalFile::new(
        SecretPath(*default_folder.id(), secret_id),
        file_name,
    ));

    // Delete the secret to remove both files
    device
        .owner
        .delete_secret(&secret_id, Default::default())
        .await?;
    wait_for_num_transfers(&device.owner, 2).await?;

    let server_paths = server.paths(device.owner.account_id());

    // Assert the files on disc do not exist
    for file in &files {
        assert_local_remote_file_not_exist(
            device.owner.paths(),
            &*server_paths,
            file,
        )
        .await?;
    }

    device.owner.sign_out().await?;

    teardown(TEST_ID).await;

    Ok(())
}
