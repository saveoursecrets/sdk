use anyhow::Result;
use std::path::PathBuf;
use serial_test::serial;

use sos_net::{
    client::{provider::ProviderFactory, user::Origin},
    sdk::{
        constants::{VAULT_EXT, EVENT_LOG_EXT},
        mpc::{Keypair, PATTERN},
        storage::AppPaths,
        vault::Summary,
        vfs,
    },
};

use crate::test_utils::{
    create_local_account, mock_note, server, server_public_key, setup, spawn,
};

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
    let expected_summaries: Vec<Summary> = owner.storage_mut().load_vaults().await?
        .into_iter()
        .map(|s| s.clone())
        .collect();
    
    // Path that we expect the remote server to write to
    let server_path = PathBuf::from(format!("target/integration-test/server/{}", owner.address()));

    // Setup a remote origin
    let server = server();
    let server_public_key = server_public_key()?;
    let origin = Origin {
        name: "origin".to_owned(),
        url: server.clone(),
    };

    // Prepare a provider for the remote service
    let factory = ProviderFactory::Remote {
        server,
        server_public_key,
    };

    let signer = owner.user().identity().signer().clone();
    let keypair = Keypair::new(PATTERN.parse()?)?;

    let (mut provider, address) =
        factory.create_provider(signer, keypair).await?;

    // Noise protocol handshake
    provider.handshake().await?;

    // Sync with a local account that does not exist on
    // the remote which should create the account on the remote
    provider.sync().await?;

    // Compare vault buffers
    for summary in expected_summaries {
        let local_folder = owner.storage().vault_path(&summary);
        let remote_folder = server_path.join(
            format!("{}.{}", summary.id(), VAULT_EXT));
        let local_buffer = vfs::read(&local_folder).await?;
        let remote_buffer = vfs::read(&remote_folder).await?;
        assert_eq!(local_buffer, remote_buffer);
    }

    // Compare event log status (commit proofs)
    let local_status = owner.storage_mut().account_status().await?;
    let remote_status = provider.account_status().await?;
    assert_eq!(local_status, remote_status);

    Ok(())
}
