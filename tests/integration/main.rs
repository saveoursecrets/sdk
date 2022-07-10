use anyhow::Result;

mod test_utils;

use test_utils::*;

use sos_client::{
    create_account, create_signing_key, ClientCache, ClientCredentials,
    ClientKey, FileCache, SyncStatus,
};
use sos_core::{
    address::AddressStr,
    constants::DEFAULT_VAULT_NAME,
    events::SyncEvent,
    secret::{Secret, SecretId, SecretMeta, SecretRef},
    vault::Summary,
};
use web3_keystore::{decrypt, KeyStore};

#[tokio::test]
async fn integration_tests() -> Result<()> {
    let dirs = setup()?;

    let (rx, _handle) = spawn()?;
    let _ = rx.await?;

    let server_url = server();

    let (address, _, mut file_cache) = signup(&dirs).await?;

    let _ = FileCache::cache_dir()?;

    assert_eq!(&server_url, file_cache.server());
    assert_eq!(address, file_cache.address()?);

    // Create a new vault
    let new_vault_name = String::from("My Vault");
    let new_passphrase =
        file_cache.create_vault(new_vault_name.clone()).await?;

    // Check our new vault is found in the local cache
    let vault_ref = SecretRef::Name(new_vault_name.clone());
    let new_vault_summary =
        file_cache.find_vault(&vault_ref).unwrap().clone();
    assert_eq!(&new_vault_name, new_vault_summary.name());

    let id_ref = SecretRef::Id(*new_vault_summary.id());
    let new_vault_summary_by_id =
        file_cache.find_vault(&id_ref).unwrap().clone();
    assert_eq!(new_vault_summary_by_id, new_vault_summary);

    // Load vaults list
    let cached_vaults = file_cache.vaults().to_vec();
    let vaults = file_cache.load_vaults().await?;
    assert_eq!(2, vaults.len());
    assert_eq!(&cached_vaults, &vaults);

    // Remove the default vault
    let default_ref = SecretRef::Name(DEFAULT_VAULT_NAME.to_owned());
    let default_vault_summary =
        file_cache.find_vault(&default_ref).unwrap().clone();
    file_cache.remove_vault(&default_vault_summary).await?;
    let vaults = file_cache.load_vaults().await?;
    assert_eq!(1, vaults.len());
    assert_eq!(1, file_cache.vaults().len());

    // Use the new vault
    file_cache
        .open_vault(&new_vault_summary, &new_passphrase)
        .await?;

    // Create some secrets
    let notes = create_secrets(&mut file_cache, &new_vault_summary).await?;

    // Ensure we have a commit tree
    assert!(file_cache.wal_tree(&new_vault_summary).is_some());

    // Check the WAL history has the right length
    let history = file_cache.history(&new_vault_summary)?;
    assert_eq!(4, history.len());

    // Check the vault status
    let (status, _) = file_cache.vault_status(&new_vault_summary).await?;
    let equals = if let SyncStatus::Equal(_) = status { true } else { false };
    assert!(equals);

    // Delete a secret
    let first_id = notes.get(0).unwrap().0;
    delete_secret(&mut file_cache, &new_vault_summary, &first_id).await?;

    // Check our new list of secrets has the right length
    let keeper = file_cache.current().unwrap();
    let meta = keeper.meta_data()?;
    assert_eq!(2, meta.len());
    drop(keeper);

    // Set the vault name
    file_cache.set_vault_name(&new_vault_summary, DEFAULT_VAULT_NAME).await?;

    // Take a snapshot - need to do these assertions before pull/push
    let (_snapshot, created) = file_cache.take_snapshot(&new_vault_summary)?;
    assert!(created);
    let snapshots = file_cache.snapshots().list(new_vault_summary.id())?;
    assert!(!snapshots.is_empty());

    // Try to pull whilst up to date
    let _ = file_cache.pull(&new_vault_summary, false).await?;
    // Now force a pull
    let _ = file_cache.pull(&new_vault_summary, true).await?;

    // Try to push whilst up to date
    let _ = file_cache.push(&new_vault_summary, false).await?;
    // Now force a push
    let _ = file_cache.push(&new_vault_summary, true).await?;

    // Verify local WAL ingegrity
    file_cache.verify(&new_vault_summary)?;

    // Compact the vault history
    let _ = file_cache.compact(&new_vault_summary).await?;

    // Close the vault
    file_cache.close_vault();

    Ok(())
}

async fn signup(dirs: &TestDirs) -> Result<(AddressStr, ClientCredentials, FileCache)> {
    let TestDirs {
        target: destination,
        client: cache_dir,
        ..
    } = dirs;

    let server = server();
    let name = None;
    let key = create_signing_key()?;

    let address = key.address().to_owned();

    let expected_keystore =
        destination.join(&format!("{}.json", key.address()));

    let ClientKey(signing_key, _, _) = &key;
    let expected_signing_key = *signing_key;

    let (credentials, disc_cache) = create_account(
        server,
        destination.to_path_buf(),
        name,
        key,
        cache_dir.to_path_buf(),
    )
    .await?;

    assert_eq!(expected_keystore, credentials.keystore_file);
    assert!(expected_keystore.is_file());

    assert!(!credentials.encryption_passphrase.is_empty());
    assert!(!credentials.keystore_passphrase.is_empty());

    let keystore = std::fs::read(&expected_keystore)?;
    let keystore: KeyStore = serde_json::from_slice(&keystore)?;

    let signing_key: [u8; 32] =
        decrypt(&keystore, &credentials.keystore_passphrase)?
            .as_slice()
            .try_into()?;

    assert_eq!(expected_signing_key, signing_key);

    Ok((address, credentials, disc_cache))
}

async fn create_secrets(
    file_cache: &mut FileCache,
    summary: &Summary,
) -> Result<Vec<(SecretId, &'static str)>> {
    let notes = vec![
        ("note1", "secret1"),
        ("note2", "secret2"),
        ("note3", "secret3"),
    ];

    let keeper = file_cache.current_mut().unwrap();

    let mut results = Vec::new();

    // Create some notes locally and get the events
    // to send in a patch.
    let mut create_events = Vec::new();
    for item in notes.iter() {
        let (meta, secret) = mock_note(item.0, item.1);
        let event = keeper.create(meta, secret)?;

        let id = if let SyncEvent::CreateSecret(secret_id, _) = &event {
            *secret_id
        } else {
            unreachable!()
        };

        let event = event.into_owned();
        create_events.push(event);

        results.push((id, item.0));
    }

    assert_eq!(3, keeper.vault().len());

    // Send the patch to the remote server
    file_cache.patch_vault(summary, create_events).await?;

    Ok(results)
}

async fn delete_secret(
    file_cache: &mut FileCache,
    summary: &Summary,
    id: &SecretId,
) -> Result<()> {
    let keeper = file_cache.current_mut().unwrap();
    let event = keeper.delete(id)?.unwrap();
    let event = event.into_owned();

    // Send the patch to the remote server
    file_cache.patch_vault(summary, vec![event]).await?;
    Ok(())
}

fn mock_note(label: &str, text: &str) -> (SecretMeta, Secret) {
    let secret_value = Secret::Note(text.to_string());
    let secret_meta = SecretMeta::new(label.to_string(), secret_value.kind());
    (secret_meta, secret_value)
}
