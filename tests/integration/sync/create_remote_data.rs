use anyhow::Result;

use sos_net::{
    client::{RemoteBridge, RemoteSync},
    sdk::vault::Summary,
};

use crate::test_utils::{create_local_account, setup, spawn, teardown};

use super::{assert_local_remote_events_eq, assert_local_remote_vaults_eq};

const TEST_ID: &str = "sync_create_remote_data";

/// Tests creating all the account data on a remote
/// when the server does not have the account data yet.
#[tokio::test]
async fn integration_sync_create_remote_data() -> Result<()> {
    //crate::test_utils::init_tracing();

    let mut dirs = setup(TEST_ID, 1).await?;
    let test_data_dir = dirs.clients.remove(0);

    // Spawn a backend server and wait for it to be listening
    let server = spawn(TEST_ID, None).await?;

    let (mut owner, _, _default_folder, _) =
        create_local_account(TEST_ID, Some(test_data_dir)).await?;

    // Folders on the local account
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

    // Path that we expect the remote server to write the
    // account data to
    let server_path = server.account_path(owner.address());

    // Create the remote provider
    let origin = server.origin.clone();
    let remote_origin = origin.clone();
    let provider = owner.remote_bridge(&origin).await?;
    owner.insert_remote(origin, Box::new(provider));

    // Sync with a local account that does not exist on
    // the remote which should create the account on the remote
    owner.sync().await?;

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
        expected_summaries,
        &mut owner,
        remote_provider,
    )
    .await?;

    teardown(TEST_ID).await;

    Ok(())
}
