//! Tests for attachment external files.
use crate::test_utils::{
    assert_local_remote_file_eq,
    mock::{
        self,
        files::{create_attachment, create_file_secret},
    },
    simulate_device, spawn, teardown, wait_for_transfers,
};
use anyhow::Result;
use sos_net::{client::RemoteSync, sdk::prelude::*};
use std::sync::Arc;

/// Tests creating an attachment.
#[tokio::test]
async fn file_transfers_attach_create() -> Result<()> {
    const TEST_ID: &str = "file_transfers_attach_create";

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
    files.push(ExternalFile::new(*default_folder.id(), secret_id, file_name));
    
    // Create an attachment
    let (_, _, file_name) =
        create_attachment(&mut device.owner, &secret_id, &default_folder, None)
            .await?;
    files.push(ExternalFile::new(*default_folder.id(), secret_id, file_name));

    // Wait until the transfers are completed
    wait_for_transfers(&device.owner).await?;

    // Assert the files on disc are equal
    for file in &files {
        assert_local_remote_file_eq(
            device.owner.paths(),
            &device.server_path,
            &file,
        )
        .await?;
    }

    device.owner.sign_out().await?;

    teardown(TEST_ID).await;

    Ok(())
}
