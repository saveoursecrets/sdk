use anyhow::Result;
use serial_test::serial;
use std::path::PathBuf;

use sos_net::{
    client::{RemoteBridge, RemoteSync},
    sdk::vault::Summary,
};

use crate::test_utils::{create_local_account, origin, setup, spawn};

use super::{assert_local_remote_events_eq, assert_local_remote_vaults_eq};

/// Tests creating all the account data on a remote
/// when the server does not have the account data yet.
#[tokio::test]
#[serial]
async fn integration_sync_create_remote_data() -> Result<()> {
    //crate::test_utils::init_tracing();

    let mut dirs = setup(1).await?;
    let test_data_dir = dirs.clients.remove(0);

    // Spawn a backend server and wait for it to be listening
    let (rx, _handle) = spawn()?;
    let _ = rx.await?;

    let (mut owner, _, _default_folder, _) =
        create_local_account("sync_create_remote_data", Some(test_data_dir)).await?;

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

    // Path that we expect the remote server to write to
    let server_path = PathBuf::from(format!(
        "target/integration-test/server/{}",
        owner.address()
    ));

    // Create the remote provider
    let origin = origin();
    let remote_origin = origin.clone();
    let provider = owner.create_remote_provider(&origin, None).await?;
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
        &server_path,
        &mut owner,
        remote_provider,
    )
    .await?;

    Ok(())
}
