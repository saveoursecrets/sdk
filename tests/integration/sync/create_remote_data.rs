use anyhow::Result;
use serial_test::serial;

use sos_net::{
    sdk::{storage::AppPaths, mpc::{Keypair, PATTERN}},
    client::{user::Origin, provider::ProviderFactory},
};

use crate::test_utils::{create_local_account, mock_note, setup, server, server_public_key};

/// Tests creating all the account data on a remote
/// when the server does not have the account data yet.
#[tokio::test]
#[serial]
async fn integration_sync_create_remote_data() -> Result<()> {
    let dirs = setup(1).await?;

    let test_data_dir = dirs.clients.get(0).unwrap();
    AppPaths::set_data_dir(test_data_dir.clone());
    AppPaths::scaffold().await?;

    let (mut owner, _, default_folder, _) =
        create_local_account("sync_basic_1").await?;

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

    let (mut provider, address) = factory.create_provider(
        signer, keypair).await?;

    //let remote = 

    //let status = provider.status(&default_folder).await?;
    
    /*
    // Create a secret in the default folder
    let (meta, secret) = mock_note("Mock note", "Note value");
    let (_, _) = owner
        .create_secret(meta, secret, default_folder.into())
        .await?;
    */

    Ok(())
}
