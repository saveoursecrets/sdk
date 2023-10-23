use anyhow::Result;
use serial_test::serial;

use crate::test_utils::*;

use sos_net::{
    client::provider::StorageProvider,
    sdk::mpc::generate_keypair,
};

#[tokio::test]
#[serial]
async fn integration_patch_conflict_resolve() -> Result<()> {
    let dirs = setup(2).await?;

    let (rx, _handle) = spawn()?;
    let _ = rx.await?;

    let server_url = server();

    // Signup a new account
    let (_, credentials, mut client1, signer) = signup(&dirs, 0).await?;
    let AccountCredentials {
        summary,
        encryption_passphrase,
        ..
    } = credentials;

    // Set up another connected client using a different
    // cache directory and sharing the same credentials
    let data_dir = dirs.clients.get(1).unwrap().to_path_buf();
    let mut client2 =
        login(server_url, data_dir, &signer, generate_keypair()?).await?;
    let _ = client2.load_vaults().await?;
    //let _ = client2.pull(&summary, true).await?;

    // Both client use the login vault
    client1
        .open_vault(&summary, encryption_passphrase.clone().into(), None)
        .await?;
    client2
        .open_vault(&summary, encryption_passphrase.clone().into(), None)
        .await?;

    // Create some secrets in client 1
    let _notes = create_secrets(&mut client1, &summary).await?;

    // Create some secrets in client 2
    //
    // This triggers the code path where an attempted patch
    // will return a CONFLICT which can be resolved with a pull
    // and then this node can try the patch again.
    let _notes = create_secrets(&mut client2, &summary).await?;

    // Close the vaults
    client1.close_vault();
    client2.close_vault();

    Ok(())
}
