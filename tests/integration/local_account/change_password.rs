use anyhow::Result;

use crate::test_utils::{
    create_local_provider, create_secrets, setup, teardown,
    AccountCredentials,
};

use sos_net::sdk::{
    passwd::diceware::generate_passphrase, signer::ecdsa::SingleParty,
};

const TEST_ID: &str = "change_password";

/// Tests changing the encryption password of a folder.
#[tokio::test]
async fn integration_change_password() -> Result<()> {
    let mut dirs = setup(TEST_ID, 1).await?;
    let test_data_dir = dirs.clients.remove(0);

    let signer = Box::new(SingleParty::new_random());
    let (credentials, mut provider) =
        create_local_provider(signer, Some(test_data_dir)).await?;

    let AccountCredentials {
        summary,
        encryption_passphrase,
        ..
    } = credentials;

    // Use the new vault
    provider
        .open_vault(&summary, encryption_passphrase.clone().into(), None)
        .await?;

    // Create some secrets
    let _notes = create_secrets(&mut provider, &summary).await?;

    // Check our new list of secrets has the right length
    let keeper = provider.current().unwrap();

    let index = keeper.index();
    let index_reader = index.read().await;
    let meta = index_reader.values();
    assert_eq!(3, meta.len());
    drop(index_reader);

    let keeper = provider.current_mut().unwrap();
    let (new_passphrase, _) = generate_passphrase()?;

    let vault = keeper.vault().clone();

    provider
        .change_password(
            &vault,
            encryption_passphrase.into(),
            new_passphrase.into(),
        )
        .await?;

    // Close the vault
    provider.close_vault();

    teardown(TEST_ID).await;

    Ok(())
}
