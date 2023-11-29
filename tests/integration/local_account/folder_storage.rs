use crate::test_utils::{
    create_local_provider, create_secrets, delete_secret, setup, teardown,
    AccountCredentials,
};
use anyhow::Result;
use sos_net::sdk::{
    constants::DEFAULT_VAULT_NAME, signer::ecdsa::SingleParty,
    vault::FolderRef,
};

const TEST_ID: &str = "folder_storage";

/// Tests basic operations directly on folder storage.
#[tokio::test]
async fn integration_folder_storage() -> Result<()> {
    //crate::test_utils::init_tracing();

    let mut dirs = setup(TEST_ID, 1).await?;
    let test_data_dir = dirs.clients.remove(0);

    let signer = Box::new(SingleParty::new_random());
    let (credentials, mut provider) =
        create_local_provider(signer, Some(test_data_dir)).await?;
    let AccountCredentials { summary, .. } = credentials;
    let _login_vault_id = *summary.id();

    // Create a new vault
    let new_vault_name = String::from("My Vault");
    let (_, new_passphrase, _) =
        provider.create_vault(new_vault_name.clone(), None).await?;

    // Check our new vault is found in the local cache
    let vault_ref = FolderRef::Name(new_vault_name.clone());
    let new_vault_summary = provider.find_folder(&vault_ref).unwrap().clone();
    assert_eq!(&new_vault_name, new_vault_summary.name());

    // Need this for some assertions later
    let _new_vault_id = *new_vault_summary.id();

    // Trigger code path for finding by id
    let id_ref = FolderRef::Id(*new_vault_summary.id());
    let new_vault_summary_by_id =
        provider.find_folder(&id_ref).unwrap().clone();
    assert_eq!(new_vault_summary_by_id, new_vault_summary);

    // Load vaults list
    let cached_vaults = provider.folders().to_vec();
    let vaults = provider.load_vaults().await?;
    assert_eq!(2, vaults.len());
    assert_eq!(&cached_vaults, &vaults);

    // Remove the default vault
    let default_ref = FolderRef::Name(DEFAULT_VAULT_NAME.to_owned());
    let default_vault_summary =
        provider.find_folder(&default_ref).unwrap().clone();
    provider.remove_vault(&default_vault_summary).await?;
    let vaults = provider.load_vaults().await?;
    assert_eq!(1, vaults.len());
    assert_eq!(1, provider.folders().len());

    // Use the new vault
    provider
        .open_vault(&new_vault_summary, new_passphrase)
        .await?;

    // Create some secrets
    let notes = create_secrets(&mut provider, &new_vault_summary).await?;

    // Ensure we have a commit tree
    assert!(provider.commit_tree(&new_vault_summary).is_some());

    // Check the event log history has the right length
    let history = provider.history(&new_vault_summary).await?;
    assert_eq!(4, history.len());

    // Delete a secret
    let delete_secret_id = notes.get(0).unwrap().0;
    delete_secret(&mut provider, &new_vault_summary, &delete_secret_id)
        .await?;

    // Check our new list of secrets has the right length
    let keeper = provider.current().unwrap();

    // Set the vault name
    provider
        .set_vault_name(&new_vault_summary, DEFAULT_VAULT_NAME)
        .await?;

    // Verify local event log integrity
    provider.verify(&new_vault_summary).await?;

    // Close the vault
    provider.close_vault();

    teardown(TEST_ID).await;

    Ok(())
}
