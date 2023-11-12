use anyhow::Result;
use serial_test::serial;

use crate::test_utils::*;

use futures::stream::StreamExt;
use std::{
    sync::{Arc, RwLock},
    time::Duration,
};
use url::Url;

use sos_net::{
    client::{
        net::{
            changes::{changes, connect},
            RpcClient,
        },
        provider::StorageProvider,
    },
    sdk::{
        commit::CommitRelationship,
        constants::DEFAULT_VAULT_NAME,
        events::{ChangeEvent, ChangeNotification},
        mpc::generate_keypair,
        storage::AppPaths,
        vault::VaultRef,
    },
};

#[tokio::test]
#[serial]
async fn integration_simple_session() -> Result<()> {
    
    let (address, credentials, mut provider, signer) =
        signup_local(None).await?;
    let AccountCredentials { summary, .. } = credentials;
    let login_vault_id = *summary.id();
    
    // Create a new vault
    let new_vault_name = String::from("My Vault");
    let (_, new_passphrase, _) = provider
        .create_vault(new_vault_name.clone(), None)
        .await?;

    // Check our new vault is found in the local cache
    let vault_ref = VaultRef::Name(new_vault_name.clone());
    let new_vault_summary =
        provider.state().find_vault(&vault_ref).unwrap().clone();
    assert_eq!(&new_vault_name, new_vault_summary.name());

    // Need this for some assertions later
    let new_vault_id = *new_vault_summary.id();

    // Trigger code path for finding by id
    let id_ref = VaultRef::Id(*new_vault_summary.id());
    let new_vault_summary_by_id =
        provider.state().find_vault(&id_ref).unwrap().clone();
    assert_eq!(new_vault_summary_by_id, new_vault_summary);

    // Load vaults list
    let cached_vaults = provider.vaults().to_vec();
    let vaults = provider.load_vaults().await?;
    assert_eq!(2, vaults.len());
    assert_eq!(&cached_vaults, &vaults);

    // Remove the default vault
    let default_ref = VaultRef::Name(DEFAULT_VAULT_NAME.to_owned());
    let default_vault_summary =
        provider.state().find_vault(&default_ref).unwrap().clone();
    provider.remove_vault(&default_vault_summary).await?;
    let vaults = provider.load_vaults().await?;
    assert_eq!(1, vaults.len());
    assert_eq!(1, provider.vaults().len());

    // Use the new vault
    provider
        .open_vault(&new_vault_summary, new_passphrase, None)
        .await?;

    // Create some secrets
    let notes = create_secrets(&mut provider, &new_vault_summary).await?;

    // Ensure we have a commit tree
    assert!(provider.commit_tree(&new_vault_summary).is_some());

    // Check the event log history has the right length
    let history = provider.history(&new_vault_summary).await?;
    assert_eq!(4, history.len());

    // Check the vault status
    let (status, _) = provider.status(&new_vault_summary).await?;
    let equals = matches!(status, CommitRelationship::Equal(_));
    assert!(equals);

    // Delete a secret
    let delete_secret_id = notes.get(0).unwrap().0;
    delete_secret(&mut provider, &new_vault_summary, &delete_secret_id)
        .await?;

    // Check our new list of secrets has the right length
    let keeper = provider.current().unwrap();
    let index = keeper.index();
    let index_reader = index.read().await;
    let meta = index_reader.values();
    assert_eq!(2, meta.len());
    drop(index_reader);

    // Set the vault name
    provider
        .set_vault_name(&new_vault_summary, DEFAULT_VAULT_NAME)
        .await?;
    
    /*
    // Try to pull whilst up to date
    let _ = provider.pull(&new_vault_summary, false).await?;
    // Now force a pull
    let _ = provider.pull(&new_vault_summary, true).await?;

    // Try to push whilst up to date
    let _ = provider.push(&new_vault_summary, false).await?;
    // Now force a push
    let _ = provider.push(&new_vault_summary, true).await?;
    */

    // Verify local event log ingegrity
    provider.verify(&new_vault_summary).await?;

    // Close the vault
    provider.close_vault();

    Ok(())
}
