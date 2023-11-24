use anyhow::Result;
use std::{path::PathBuf, sync::Arc};

use sos_net::{
    client::{ListenOptions, RemoteBridge, RemoteSync, UserStorage},
    sdk::{
        constants::{EVENT_LOG_EXT, VAULT_EXT},
        vault::Summary,
        vfs,
    },
};

use crate::test_utils::{
    create_local_account, setup, spawn, sync_pause, teardown,
};

use super::{num_events, simulate_device, SimulatedDevice};

const TEST_ID: &str = "sync_listen_delete_folder";

/// Tests syncing delete folder events between two clients
/// where the second client listens for changes emitted
/// by the first client via the remote.
#[tokio::test]
async fn integration_sync_listen_delete_folder() -> Result<()> {
    //crate::test_utils::init_tracing();

    // Spawn a backend server and wait for it to be listening
    let server = spawn(TEST_ID, None, None).await?;

    // Prepare mock devices
    let mut device1 = simulate_device(TEST_ID, &server, 2).await?;
    let default_folder_id = device1.default_folder_id.clone();
    let origin = device1.origin.clone();
    let folders = device1.folders.clone();
    let address = device1.owner.address().to_string();
    let server_path = device1.server_path.clone();
    let mut device2 = device1.connect(1, None).await?;
    
    // Start listening for change notifications (first client)
    device1.owner.listen(&origin, ListenOptions::new("device_1".to_string())?)?;

    // Start listening for change notifications (second client)
    device2.owner
        .listen(&origin, ListenOptions::new("device_2".to_string())?)?;

    let (new_folder, sync_error) =
        device1.owner.create_folder("sync_folder".to_string()).await?;
    assert!(sync_error.is_none());

    let sync_error = device1.owner.delete_folder(&new_folder).await?;
    assert!(sync_error.is_none());

    // Pause a while to give the listener some time to process
    // the change notification
    sync_pause().await;

    let updated_summaries: Vec<Summary> = {
        let storage = device1.owner.storage();
        let reader = storage.read().await;
        reader.state().summaries().to_vec()
    };
    assert_eq!(folders.len(), updated_summaries.len());

    // Check the server removed the files
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

    // Check the first client removed the files
    let expected_vault_file =
        device1.owner.paths().vault_path(new_folder.id().to_string());
    let expected_event_file =
        device1.owner.paths().vault_path(new_folder.id().to_string());
    assert!(!vfs::try_exists(expected_vault_file).await?);
    assert!(!vfs::try_exists(expected_event_file).await?);

    // Check the listening client removed the files
    let expected_vault_file =
        device2.owner.paths().vault_path(new_folder.id().to_string());
    let expected_event_file =
        device2.owner.paths().vault_path(new_folder.id().to_string());
    assert!(!vfs::try_exists(expected_vault_file).await?);
    assert!(!vfs::try_exists(expected_event_file).await?);

    teardown(TEST_ID).await;

    Ok(())
}
