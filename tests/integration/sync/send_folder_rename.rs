use anyhow::Result;
use std::path::PathBuf;

use sos_net::{
    client::{RemoteBridge, RemoteSync},
    sdk::vault::Summary,
};

use crate::test_utils::{
    create_local_account, mock_note, setup, spawn, teardown,
};

use super::{assert_local_remote_events_eq, assert_local_remote_vaults_eq};

const TEST_ID: &str = "sync_rename_folder";

/// Tests sending create folder events to a remote.
#[tokio::test]
async fn integration_sync_rename_folder() -> Result<()> {
    //crate::test_utils::init_tracing();

    let dirs = setup(TEST_ID, 1).await?;
    let test_data_dir = dirs.clients.get(0).unwrap();

    // Spawn a backend server and wait for it to be listening
    let server = spawn(TEST_ID, None).await?;

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

    // Path that we expect the remote server to write to
    let server_path = server.account_path(owner.address());

    // Create the remote provider
    let origin = server.origin.clone();
    let remote_origin = origin.clone();
    let provider = owner.remote_bridge(&origin).await?;

    // Insert the remote for the primary owner
    owner.insert_remote(origin, Box::new(provider));

    owner.open_folder(&default_folder).await?;

    // Sync the local account to create the account on remote
    owner.sync().await?;

    let sync_error = owner
        .rename_folder(&default_folder, "new_name".to_string())
        .await?;
    assert!(sync_error.is_none());

    // Get the remote out of the owner so we can
    // assert on equality between local and remote
    let mut provider = owner.delete_remote(&remote_origin).unwrap();
    let remote_provider = provider
        .as_any_mut()
        .downcast_mut::<RemoteBridge>()
        .expect("to be a remote provider");

    assert_local_remote_vaults_eq(
        expected_summaries.clone(),
        &server_path,
        &mut owner,
        remote_provider,
    )
    .await?;

    assert_local_remote_events_eq(
        expected_summaries.clone(),
        &mut owner,
        remote_provider,
    )
    .await?;

    teardown(TEST_ID).await;

    Ok(())
}
