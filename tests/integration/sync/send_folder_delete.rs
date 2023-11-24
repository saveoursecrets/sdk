use anyhow::Result;
use std::path::PathBuf;

use sos_net::{
    client::RemoteSync,
    sdk::{
        constants::{EVENT_LOG_EXT, VAULT_EXT},
        vault::Summary,
        vfs,
    },
};

use crate::test_utils::{create_local_account, setup, spawn, teardown};

use super::num_events;

const TEST_ID: &str = "sync_delete_folder";

/// Tests sending delete folder events to a remote.
#[tokio::test]
async fn integration_sync_delete_folder() -> Result<()> {
    //crate::test_utils::init_tracing();

    let dirs = setup(TEST_ID, 1).await?;
    let test_data_dir = dirs.clients.get(0).unwrap();

    // Spawn a backend server and wait for it to be listening
    let server = spawn(TEST_ID, None, None).await?;

    let (mut owner, _, default_folder, _) =
        create_local_account(TEST_ID, Some(test_data_dir.clone())).await?;

    // Folders on the local account must be loaded into memory
    let expected_summaries: Vec<Summary> = {
        let storage = owner.storage();
        let mut writer = storage.write().await;
        writer
            .load_vaults()
            .await?
            .into_iter()
            .map(|s| s.clone())
            .collect()
    };

    let original_summaries_len = expected_summaries.len();

    // Path that we expect the remote server to write to
    let server_path = server.account_path(owner.address());
    let address = owner.address().to_string();

    // Create the remote provider
    let origin = server.origin.clone();
    let remote_origin = origin.clone();
    let provider = owner.remote_bridge(&origin).await?;

    // Insert the remote for the primary owner
    owner.insert_remote(origin, Box::new(provider));

    let default_folder_id = *default_folder.id();
    owner.open_folder(&default_folder).await?;

    // Before we begin the client should have a single event
    assert_eq!(1, num_events(&mut owner, &default_folder_id).await);

    // Sync the local account to create the account on remote
    owner.sync().await?;

    let (new_folder, sync_error) = owner
        .create_folder("sync_delete_folder".to_string())
        .await?;
    assert!(sync_error.is_none());

    // Our new local folder should have the single create vault event
    assert_eq!(1, num_events(&mut owner, new_folder.id()).await);

    let sync_error = owner.delete_folder(&new_folder).await?;
    assert!(sync_error.is_none());

    let updated_summaries: Vec<Summary> = {
        let storage = owner.storage();
        let reader = storage.read().await;
        reader.state().summaries().to_vec()
    };

    assert_eq!(expected_summaries.len(), updated_summaries.len());

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
