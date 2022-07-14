use anyhow::Result;
use serial_test::serial;

use crate::test_utils::*;

use sos_node::client::{
    account::{login, AccountCredentials},
    ClientCache,
};

#[tokio::test]
#[serial]
async fn integration_patch_conflict_resolve() -> Result<()> {
    let dirs = setup(2)?;

    let (rx, _handle) = spawn()?;
    let _ = rx.await?;

    let server_url = server();

    // Signup a new account
    let (_, credentials, mut client1) = signup(&dirs, 0).await?;
    let AccountCredentials {
        summary,
        encryption_passphrase,
        keystore_file,
        keystore_passphrase,
        ..
    } = credentials;

    // Set up another connected client using a different
    // cache directory but sharing the same credentials
    let cache_dir = dirs.clients.get(1).unwrap().to_path_buf();
    let mut client2 =
        login(server_url, cache_dir, keystore_file, keystore_passphrase)?;
    let _ = client2.load_vaults().await?;

    // Both client use the login vault
    client1.open_vault(&summary, &encryption_passphrase).await?;
    client2.open_vault(&summary, &encryption_passphrase).await?;

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
