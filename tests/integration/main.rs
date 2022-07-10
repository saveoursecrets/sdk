use anyhow::Result;

mod test_utils;

use test_utils::*;

use sos_client::{
    create_account, create_signing_key, ClientCache, ClientCredentials,
    ClientKey, FileCache,
};
use sos_core::secret::SecretRef;
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
    let vaults = file_cache.load_vaults().await?;
    assert_eq!(2, vaults.len());

    // Use the new vault
    file_cache
        .open_vault(&new_vault_summary, &new_passphrase)
        .await?;

    //file_cache.patch_vault(&summary, create_events).await?;

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
