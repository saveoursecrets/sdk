//! Tests for loading the transfers queue from disc.
use crate::test_utils::{
    assert_local_remote_file_eq, mock::files::create_file_secret,
    simulate_device, spawn, teardown, wait_for_transfers,
};
use anyhow::Result;
use sos_net::{client::RemoteSync, sdk::prelude::*};

/// Tests creating an external file, signing out and then
/// signing in again.
///
/// When we sign in again the transfers queue should be loaded
/// from disc and we should be able to sync and then complete
/// the upload.
#[tokio::test]
async fn file_transfers_load_queue() -> Result<()> {
    const TEST_ID: &str = "file_transfers_load_queue";

    //crate::test_utils::init_tracing();

    // Prepare mock device
    let mut device = simulate_device(TEST_ID, 1, None).await?;
    let key: AccessKey = device.password.clone().into();
    let address = device.owner.address().clone();
    let default_folder = device.owner.default_folder().await.unwrap();

    // Create an external file secret
    let (secret_id, _, _, file_name) =
        create_file_secret(&mut device.owner, &default_folder, None).await?;
    let file = ExternalFile::new(*default_folder.id(), secret_id, file_name);

    {
        let transfers = device.owner.transfers()?;
        let transfers = transfers.read().await;
        let ops = transfers.queue().get(&file).unwrap().clone();
        let ops = ops.into_iter().collect::<Vec<_>>();
        assert!(matches!(ops.get(0), Some(&TransferOperation::Upload)));
    }

    // Sign out to stop the transfers background task
    // and clear the in-memory transfers list
    device.owner.sign_out().await?;

    // Sign in again to load the transfers queue from disc
    device.owner.sign_in(&key).await?;

    {
        let transfers = device.owner.transfers()?;
        let transfers = transfers.read().await;
        let ops = transfers.queue().get(&file).unwrap().clone();
        let ops = ops.into_iter().collect::<Vec<_>>();
        assert!(matches!(ops.get(0), Some(&TransferOperation::Upload)));
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
    assert_local_remote_file_eq(device.owner.paths(), &server_paths, &file)
        .await?;

    device.owner.sign_out().await?;

    teardown(TEST_ID).await;

    Ok(())
}
