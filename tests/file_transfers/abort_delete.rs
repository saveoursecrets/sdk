//! Test for aborting an existing transfer when deleting a secret.
use anyhow::Result;

use crate::test_utils::{
    assert_local_remote_file_not_exist, mock::files::create_file_secret,
    simulate_device, spawn, teardown, wait_for_num_transfers,
};
use sos_net::sdk::prelude::*;

/// Tests uploading then deleting an external file aborts
/// the existing transfer.
#[tokio::test]
async fn file_transfers_abort_delete() -> Result<()> {
    const TEST_ID: &str = "file_transfers_abort_delete";

    //crate::test_utils::init_tracing();

    // Spawn a backend server and wait for it to be listening
    let server = spawn(TEST_ID, None, None).await?;

    // Prepare mock device
    let mut device = simulate_device(TEST_ID, 1, Some(&server)).await?;
    let default_folder = device.owner.default_folder().await.unwrap();

    // Create an external file secret
    let (secret_id, _, _, file_name) =
        create_file_secret(&mut device.owner, &default_folder, None).await?;
    let file = ExternalFile::new(*default_folder.id(), secret_id, file_name);

    // Deleting the secret will queue a file delete
    // event for transfer which in turn will cancel
    // the inflight upload
    device
        .owner
        .delete_secret(&secret_id, Default::default())
        .await?;

    // Wait until the delete transfer is completed
    wait_for_num_transfers(&device.owner, 1).await?;

    let local_paths = device.owner.paths();

    assert_local_remote_file_not_exist(
        local_paths,
        &device.server_path,
        &file,
    )
    .await?;

    device.owner.sign_out().await?;

    teardown(TEST_ID).await;

    Ok(())
}
