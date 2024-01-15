//! Tests for creating files before a remote server is configured 
//! then starting a server, adding it to the client, syncing and 
//! transferring the files to the server.
use crate::test_utils::{
    assert_local_remote_file_eq,
    mock::{self, files::net::create_file_secret},
    simulate_device_maybe_server, spawn, teardown, wait_for_transfers,
};
use anyhow::Result;
use sos_net::{client::RemoteSync, sdk::prelude::*};
use std::sync::Arc;

/// Tests creating external files then adding a remote
/// server, syncing and uploading the files.
#[tokio::test]
async fn file_transfers_late_upload() -> Result<()> {
    const TEST_ID: &str = "file_transfers_late_upload";

    //crate::test_utils::init_tracing();

    // Prepare mock device
    let mut device = simulate_device_maybe_server(TEST_ID, 1, None).await?;
    let key: AccessKey = device.password.clone().into();
    let address = device.owner.address().clone();
    let default_folder = device.owner.default_folder().await.unwrap();

    // Create an external file secret then delete it,
    // this will be normalized to a single delete operation
    let (secret_id, _, _, file_name) =
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
        *default_folder.id(),
        secret_id,
        file_name,
    ));

    // Create a file secret and move to a different folder
    let (secret_id, _, _, file_name) =
        create_file_secret(&mut device.owner, &default_folder, None).await?;
    let (destination, _) =
        device.owner.create_folder("new_folder".to_owned()).await?;
    let ((secret_id, _), _) = device
        .owner
        .move_secret(
            &secret_id,
            &default_folder,
            &destination,
            Default::default(),
        )
        .await?;
    files.push(ExternalFile::new(*destination.id(), secret_id, file_name));

    // Add an attachment to the moved secret
    let (mut secret_data, _) = device
        .owner
        .read_secret(&secret_id, Some(destination.clone()))
        .await?;
    let (meta, secret, _) = mock::file_text_secret()?;
    let attachment_id = SecretId::new_v4();
    let attachment = SecretRow::new(attachment_id, meta, secret);
    secret_data.secret_mut().add_field(attachment);
    device
        .owner
        .update_secret(
            &secret_id,
            secret_data.meta().clone(),
            Some(secret_data.secret().clone()),
            AccessOptions {
                folder: Some(destination.clone()),
                file_progress: None,
            },
            None,
        )
        .await?;
    let (mut secret_data, _) = device
        .owner
        .read_secret(&secret_id, Some(destination.clone()))
        .await?;
    let attached = secret_data
        .secret()
        .find_field_by_id(&attachment_id)
        .expect("attachment to exist");
    let attachment_checksum = if let Secret::File {
        content: FileContent::External { checksum, .. },
        ..
    } = attached.secret()
    {
        *checksum
    } else {
        panic!("expecting file secret variant (attachment)");
    };
    files.push(ExternalFile::new(
        *destination.id(),
        secret_id,
        attachment_checksum.into(),
    ));

    // Should have transfer operations for each file in
    // the transfers queue
    {
        let transfers = device.owner.transfers().await?;
        let mut transfers = transfers.write().await;

        // Must normalize before asserting
        transfers
            .normalize(Arc::new(device.owner.paths().clone()))
            .await?;

        for file in &files {
            assert!(transfers.queue().get(file).is_some());
        }
    }

    // Spawn a backend server and wait for it to be listening
    let server = spawn(TEST_ID, None, None).await?;
    let server_paths = server.account_path(&address);

    // Connect to the server
    device.owner.add_server(server.origin.clone()).await?;

    // Sync so the upload will succeed (otherwise 404)
    assert!(device.owner.sync().await.is_none());

    // Wait until the transfers are completed
    wait_for_transfers(&device.owner).await?;

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
