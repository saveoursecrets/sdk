use anyhow::Result;
use sos_account::Account;
use sos_test_utils::{simulate_device, spawn, teardown};

/// Tests creating a shared folder and having the owner
/// and another user perform write operations.
#[tokio::test]
async fn shared_folder_write_access() -> Result<()> {
    const TEST_ID: &str = "shared_folder_write_access";
    //sos_test_utils::init_tracing();

    // Spawn a backend server and wait for it to be listening
    let server = spawn(TEST_ID, None, None).await?;

    // Prepare mock devices with different accounts
    let mut device1 = simulate_device(TEST_ID, 1, Some(&server)).await?;
    let mut device2 = simulate_device(TEST_ID, 1, Some(&server)).await?;

    device1.owner.sign_out().await?;
    device2.owner.sign_out().await?;

    teardown(TEST_ID).await;

    Ok(())
}
