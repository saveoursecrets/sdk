//! Tests for file transfer normalization.
use crate::test_utils::{
    assert_local_remote_file_not_exist, mock::files::net::create_file_secret,
    simulate_device_maybe_server, spawn, teardown, wait_for_transfers,
};
use anyhow::Result;
use sos_net::sdk::prelude::*;
use std::sync::Arc;

/// Tests creating then deleting an external file whilst
/// not connected to any servers and that the corresponding
/// transfer list is normalized just to a delete operation.
#[tokio::test]
async fn file_transfers_normalize_upload_delete() -> Result<()> {
    const TEST_ID: &str = "file_transfers_normalize_upload_delete";

    //crate::test_utils::init_tracing();

    // Prepare mock device
    let mut device = simulate_device_maybe_server(TEST_ID, 1, None).await?;
    let address = device.owner.address().clone();
    let default_folder = device.owner.default_folder().await.unwrap();

    // Create an external file secret
    let (secret_id, _, _, file_name) =
        create_file_secret(&mut device.owner, &default_folder, None).await?;
    let file = ExternalFile::new(*default_folder.id(), secret_id, file_name);

    // Delete the secret
    device
        .owner
        .delete_secret(&secret_id, Default::default())
        .await?;

    {
        // Before the transfer list is normalized we have
        // upload and delete operations
        let transfers = device.owner.transfers().await?;
        let mut transfers = transfers.write().await;
        let ops = transfers.queue().get(&file).unwrap().clone();
        let ops = ops.into_iter().collect::<Vec<_>>();
        assert!(matches!(ops.get(0), Some(&TransferOperation::Upload)));
        assert!(matches!(ops.get(1), Some(&TransferOperation::Delete)));

        // Normalize the transfers queue
        transfers
            .normalize(Arc::new(device.owner.paths().clone()))
            .await?;

        // Should now just have the delete operation
        let ops = transfers.queue().get(&file).unwrap().clone();
        let ops = ops.into_iter().collect::<Vec<_>>();
        assert!(matches!(ops.get(0), Some(&TransferOperation::Delete)));
    }

    // Spawn a backend server and wait for it to be listening
    let server = spawn(TEST_ID, None, None).await?;
    let server_paths = server.account_path(&address);

    // Connect to the server
    device.owner.add_server(server.origin.clone()).await?;

    // Wait until the transfers are completed
    wait_for_transfers(&device.owner).await?;

    // Assert the files do not exist on local and remote
    let local_paths = device.owner.paths();
    assert_local_remote_file_not_exist(local_paths, &server_paths, &file)
        .await?;

    device.owner.sign_out().await?;

    teardown(TEST_ID).await;

    Ok(())
}
