use anyhow::Result;
use sos_account::Account;
use sos_client_storage::NewFolderOptions;
use sos_test_utils::{simulate_device, spawn, teardown};

/// Tests creating a shared folder and having the owner
/// perform basic secret lifecycle operations.
#[tokio::test]
async fn shared_folder_secret_lifecycle() -> Result<()> {
    const TEST_ID: &str = "shared_folder_secret_lifecycle";
    // sos_test_utils::init_tracing();

    // Spawn a backend server and wait for it to be listening
    let server = spawn(TEST_ID, None, None).await?;

    // Prepare mock device
    let mut device = simulate_device(TEST_ID, 1, Some(&server)).await?;
    let password = device.password.clone();

    let folder_name = "shared_folder";
    let options = NewFolderOptions::new(folder_name.to_string());
    device.owner.create_shared_folder(options).await?;

    let folders = device.owner.list_folders().await?;
    println!("FOLDER LEN: {}", folders.len());
    let shared_folder =
        folders.iter().find(|f| f.name() == folder_name).unwrap();

    super::assert_shared_folder_lifecycle(
        &mut device.owner,
        shared_folder.id(),
        password,
        TEST_ID,
    )
    .await?;

    let folders = device.owner.list_folders().await?;
    println!("FOLDER LEN: {}", folders.len());

    device.owner.sign_out().await?;

    teardown(TEST_ID).await;

    Ok(())
}
