use anyhow::Result;
use sos_net::sdk::prelude::*;

use crate::test_utils::{
    assert_local_remote_file_eq, mock::files::create_file_secret,
    simulate_device, spawn, teardown, wait_for_transfers,
};

const TEST_ID: &str = "file_transfers_delete";

/// Tests uploading then deleting an external file.
#[tokio::test]
async fn file_transfers_delete() -> Result<()> {
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

    // Check we have a pending transfer operation
    let file = {
        let transfers = account.transfers().await?;
        let transfers = transfers.read().await;
        assert_eq!(1, transfers.len());
        transfers
            .queue()
            .keys()
            .copied()
            .collect::<Vec<_>>()
            .remove(0)
    };

    // Wait until the transfers are completed
    wait_for_transfers(&account).await?;

    // Assert the files on disc are equal
    assert_local_remote_file_eq(account.paths(), &device.server_path, &file)
        .await?;

    account.delete_secret(&id, Default::default()).await?;

    // Check we have a pending transfer operation
    let file = {
        let transfers = account.transfers().await?;
        let transfers = transfers.read().await;
        assert_eq!(1, transfers.len());
        transfers
            .queue()
            .keys()
            .copied()
            .collect::<Vec<_>>()
            .remove(0)
    };

    // Wait until the transfers are completed
    wait_for_transfers(&account).await?;

    let local_paths = account.paths();
    let expected_client_file = local_paths.file_location(
        file.vault_id(),
        file.secret_id(),
        file.file_name().to_string(),
    );
    let expected_server_file = device
        .server_path
        .join(FILES_DIR)
        .join(file.vault_id().to_string())
        .join(file.secret_id().to_string())
        .join(file.file_name().to_string());

    assert!(!vfs::try_exists(expected_client_file).await?);
    assert!(!vfs::try_exists(expected_server_file).await?);

    teardown(TEST_ID).await;

    Ok(())
}
