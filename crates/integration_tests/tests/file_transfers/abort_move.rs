//! Test for aborting an existing transfer when moving a secret.
use anyhow::Result;

use crate::test_utils::{
    assert_local_remote_file_eq, mock::files::create_file_secret,
    simulate_device, spawn, teardown, wait_for_num_transfers,
};
use sos_net::sdk::prelude::*;

/// Tests uploading then moving an external file aborts
/// the existing transfer.
#[tokio::test]
async fn file_transfers_abort_move() -> Result<()> {
    const TEST_ID: &str = "file_transfers_abort_move";

    //crate::test_utils::init_tracing();

    // Spawn a backend server and wait for it to be listening
    let server = spawn(TEST_ID, None, None).await?;

    // Prepare mock device
    let mut device = simulate_device(TEST_ID, 1, Some(&server)).await?;
    let default_folder = device.owner.default_folder().await.unwrap();

    // Create a folder
    let FolderCreate {
        folder: destination,
        ..
    } = device.owner.create_folder("new_folder".to_owned()).await?;

    // Create an external file secret
    let (secret_id, _, _, file_name) =
        create_file_secret(&mut device.owner, &default_folder, None).await?;

    // Moving the secret will queue a file move
    // event for transfer which in turn will cancel
    // the upload of the original file
    let SecretMove { id: secret_id, .. } = device
        .owner
        .move_secret(
            &secret_id,
            &default_folder,
            &destination,
            Default::default(),
        )
        .await?;
    let file = ExternalFile::new(
        SecretPath(*destination.id(), secret_id),
        file_name,
    );

    // Wait until the move transfer is completed
    wait_for_num_transfers(&device.owner, 1).await?;

    assert_local_remote_file_eq(
        device.owner.paths(),
        &device.server_path,
        &file,
    )
    .await?;

    device.owner.sign_out().await?;

    teardown(TEST_ID).await;

    Ok(())
}
