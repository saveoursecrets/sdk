use anyhow::Result;

use crate::test_utils::{
    assert_local_remote_file_eq, mock::files::create_file_secret,
    simulate_device, spawn, teardown, wait_for_transfers,
};
use sos_net::sdk::storage::files::TransferOperation;

const TEST_ID: &str = "file_transfers_move";

/// Tests uploading an external file after moving 
/// the secret to a different folder.
#[tokio::test]
async fn file_transfers_move() -> Result<()> {
    //crate::test_utils::init_tracing();

    // Spawn a backend server and wait for it to be listening
    let server = spawn(TEST_ID, None, None).await?;

    // Prepare mock device
    let device = simulate_device(TEST_ID, &server, 1).await?;
    let default_folder = device.owner.default_folder().await.unwrap();
    let account = device.owner.local_account();
    let mut account = account.lock().await;

    // Create an external file secret
    let (id, _, _) = create_file_secret(&mut *account, &default_folder, None).await?;

    // Wait until the upload is completed
    wait_for_transfers(&account).await?;

    // Create a folder
    let (destination, _, _) =
        account.create_folder("new_folder".to_owned()).await?;
    
    // Moving the secret also needs to move the file
    account.move_secret(
        &id,
        &default_folder,
        &destination,
        Default::default()).await?;

    // Check we have a pending transfer operation
    let file = {
        let transfers = account.transfers().await?;
        let transfers = transfers.read().await;
        assert_eq!(1, transfers.len());
        let mut ops = transfers
            .queue()
            .values()
            .cloned()
            .collect::<Vec<_>>()
            .remove(0);
        let move_file = ops.drain(..).next().unwrap();
        if let TransferOperation::Move(dest) = move_file {
            dest
        } else {
            panic!("expecting move file transfer operation");
        }
    };

    // Wait until the move is completed
    wait_for_transfers(&account).await?;
    
    // Assert the files on disc are equal
    assert_local_remote_file_eq(account.paths(), &device.server_path, &file)
        .await?;

    teardown(TEST_ID).await;

    Ok(())
}
