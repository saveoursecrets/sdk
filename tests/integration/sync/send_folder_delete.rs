use anyhow::Result;

use sos_net::sdk::{
    constants::{EVENT_LOG_EXT, VAULT_EXT},
    vault::Summary,
    vfs,
};

use crate::test_utils::{spawn, teardown};

use super::{num_events, simulate_device, SimulatedDevice};

const TEST_ID: &str = "sync_delete_folder";

/// Tests sending delete folder events to a remote.
#[ignore]
#[tokio::test]
async fn integration_sync_delete_folder() -> Result<()> {
    //crate::test_utils::init_tracing();

    // Spawn a backend server and wait for it to be listening
    let server = spawn(TEST_ID, None, None).await?;

    // Prepare a mock device
    let device = simulate_device(TEST_ID, &server, 1).await?;
    let SimulatedDevice {
        mut owner, folders, ..
    } = device;

    let _original_summaries_len = folders.len();

    // Path that we expect the remote server to write to
    let server_path = server.account_path(owner.address());
    let address = owner.address().to_string();

    let (new_folder, sync_error) = owner
        .create_folder("sync_delete_folder".to_string())
        .await?;
    assert!(sync_error.is_none());

    // Our new local folder should have the single create vault event
    assert_eq!(1, num_events(&mut owner, new_folder.id()).await);

    let sync_error = owner.delete_folder(&new_folder).await?;
    assert!(sync_error.is_none());

    let updated_summaries: Vec<Summary> = {
        let storage = owner.storage()?;
        let reader = storage.read().await;
        reader.folders().to_vec()
    };

    assert_eq!(folders.len(), updated_summaries.len());

    let expected_vault_file = server_path.join(&address).join(format!(
        "{}.{}",
        new_folder.id(),
        VAULT_EXT
    ));

    let expected_event_file = server_path.join(&address).join(format!(
        "{}.{}",
        new_folder.id(),
        EVENT_LOG_EXT
    ));

    assert!(!vfs::try_exists(expected_vault_file).await?);
    assert!(!vfs::try_exists(expected_event_file).await?);

    teardown(TEST_ID).await;

    Ok(())
}
