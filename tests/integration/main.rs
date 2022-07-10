use anyhow::Result;

mod test_utils;

use test_utils::*;

use sos_client::{
    create_account, create_signing_key, ClientCache, ClientCredentials,
    ClientKey, FileCache,
};
use sos_core::{
    events::SyncEvent,
    secret::{Secret, SecretMeta, SecretRef, SecretId},
    vault::Summary,
};
use web3_keystore::{decrypt, KeyStore};

#[tokio::test]
async fn integration_tests() -> Result<()> {
    let dirs = setup()?;

    let (rx, _handle) = spawn()?;
    let _ = rx.await?;

    let (credentials, mut file_cache) = signup(&dirs).await?;

    // Create a new vault
    let new_vault_name = String::from("My Vault");
    let new_passphrase =
        file_cache.create_vault(new_vault_name.clone()).await?;

    // Check our new vault is found in the local cache
    let vault_ref = SecretRef::Name(new_vault_name.clone());
    let new_vault_summary =
        file_cache.find_vault(&vault_ref).unwrap().clone();
    assert_eq!(&new_vault_name, new_vault_summary.name());

    // Load vaults list
    let cached_vaults = file_cache.vaults().to_vec();
    let vaults = file_cache.load_vaults().await?;
    assert_eq!(2, vaults.len());

    assert_eq!(&cached_vaults, &vaults);

    // Use the new vault
    file_cache
        .open_vault(&new_vault_summary, &new_passphrase)
        .await?;

    // Create some secrets
    let notes = create_secrets(&mut file_cache, &new_vault_summary).await?;

    let first_id = notes.get(0).unwrap().0;
    delete_secret(&mut file_cache, &new_vault_summary, &first_id).await?;

    Ok(())
}

async fn signup(dirs: &TestDirs) -> Result<(ClientCredentials, FileCache)> {
    let TestDirs {
        target: destination,
        client: cache_dir,
        ..
    } = dirs;

    let server = server();
    let name = None;
    let key = create_signing_key()?;

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

    Ok((credentials, disc_cache))
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
