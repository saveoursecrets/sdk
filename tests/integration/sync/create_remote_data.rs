use anyhow::Result;
use serial_test::serial;
use std::{path::PathBuf, any::Any};

use sos_net::{
    client::{provider::RemoteProvider, user::Origin, RemoteSync},
    sdk::{
        constants::{EVENT_LOG_EXT, VAULT_EXT},
        mpc::{Keypair, PATTERN},
        storage::AppPaths,
        vault::Summary,
        vfs,
    },
};

use crate::test_utils::{
    create_local_account, mock_note, server, server_public_key, setup, spawn,
};

use super::{assert_local_remote_eq, create_remote_provider};

/// Tests creating all the account data on a remote
/// when the server does not have the account data yet.
#[tokio::test]
#[serial]
async fn integration_sync_create_remote_data() -> Result<()> {
    let dirs = setup(1).await?;

    let test_data_dir = dirs.clients.get(0).unwrap();
    AppPaths::set_data_dir(test_data_dir.clone());
    AppPaths::scaffold().await?;

    // Spawn a backend server and wait for it to be listening
    let (rx, _handle) = spawn()?;
    let _ = rx.await?;

    let (mut owner, _, default_folder, _) =
        create_local_account("sync_basic_1").await?;

    // Folders on the local account
    let expected_summaries: Vec<Summary> = owner
        .storage_mut()
        .load_vaults()
        .await?
        .into_iter()
        .map(|s| s.clone())
        .collect();

    // Path that we expect the remote server to write to
    let server_path = PathBuf::from(format!(
        "target/integration-test/server/{}",
        owner.address()
    ));
    
    // Create the remote provider
    let signer = owner.user().identity().signer().clone();
    let (origin, provider) = create_remote_provider(signer).await?;

    let remote_origin = origin.clone();

    owner.insert_remote(origin, Box::new(provider));

    // Sync with a local account that does not exist on
    // the remote which should create the account on the remote
    owner.sync().await?;
    
    // Get the remote out of the owner so we can
    // assert on equality between local and remote
    let mut provider = owner.delete_remote(&remote_origin).unwrap();
    let remote_provider = provider
        .as_any_mut()
        .downcast_mut::<RemoteProvider>()
        .expect("to be a remote provider");
    
    assert_local_remote_eq(
        expected_summaries,
        &server_path,
        &mut owner,
        remote_provider,
    )
    .await?;

    Ok(())
}
