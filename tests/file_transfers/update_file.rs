use anyhow::Result;

use crate::test_utils::{
    assert_local_remote_file_eq,
    mock::files::{create_file_secret, update_file_secret},
    simulate_device, spawn, teardown, wait_for_transfers,
};
use sos_net::sdk::storage::files::{ExternalFile, TransferOperation};

const TEST_ID: &str = "file_transfers_update";

/// Tests uploading an updated external file.
#[tokio::test]
async fn file_transfers_update() -> Result<()> {
    //crate::test_utils::init_tracing();

    // Spawn a backend server and wait for it to be listening
    let server = spawn(TEST_ID, None, None).await?;

    // Prepare mock device
    let device = simulate_device(TEST_ID, &server, 1).await?;
    let default_folder = device.owner.default_folder().await.unwrap();
    let account = device.owner.local_account();
    let mut account = account.lock().await;

    // Create an external file secret
    let (id, _, _) =
        create_file_secret(&mut *account, &default_folder, None).await?;

    // Wait for the upload event
    wait_for_transfers(&account).await?;

    let (data, _) = account.read_secret(&id, None).await?;

    // Update the file secret with new file content
    update_file_secret(&mut *account, &default_folder, &data, None, None)
        .await?;

    // Check we have a pending transfer operation
    let file = {
        let transfers = account.transfers().await?;
        let transfers = transfers.read().await;

        // Updating file content yields delete
        // and upload events
        assert_eq!(2, transfers.len());

        let mut file: Option<ExternalFile> = None;
        for (key, ops) in transfers.queue() {
            let mut ops = ops.clone();
            let first = ops.drain(..).next().unwrap();
            if let TransferOperation::Upload = first {
                file = Some(*key);
            }
        }

        if let Some(file) = file {
            file
        } else {
            panic!("expecting upload transfer operation");
        }
    };

    // Wait until the transfers are completed
    wait_for_transfers(&account).await?;

    // Assert the files on disc are equal
    assert_local_remote_file_eq(account.paths(), &device.server_path, &file)
        .await?;

    teardown(TEST_ID).await;

    Ok(())
}
