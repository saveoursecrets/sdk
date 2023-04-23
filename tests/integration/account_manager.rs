use anyhow::Result;
use secrecy::ExposeSecret;
use serial_test::serial;
use std::{path::PathBuf, sync::Arc};

use parking_lot::RwLock as SyncRwLock;
use sos_core::{
    account::{AccountBuilder, ImportedAccount, NewAccount},
    constants::{LOGIN_AGE_KEY_URN, LOGIN_SIGNING_KEY_URN},
    hex,
    passwd::diceware::generate_passphrase,
    search::SearchIndex,
    storage::{FileStorage, StorageDirs},
    vault::{secret::SecretId, Gatekeeper, VaultId},
};
use sos_node::client::{
    account_manager::AccountManager,
    provider::{ProviderFactory, RestoreOptions},
};

use urn::Urn;

use crate::test_utils::*;

#[tokio::test]
#[serial]
async fn integration_account_manager() -> Result<()> {
    let dirs = setup(1)?;

    let test_cache_dir = dirs.clients.get(0).unwrap();
    StorageDirs::set_cache_dir(test_cache_dir.clone());

    assert_eq!(StorageDirs::cache_dir(), Some(test_cache_dir.clone()));

    let account_name = "Mock account name".to_string();
    let folder_name = Some("Default folder".to_string());
    let (passphrase, _) = generate_passphrase()?;

    let new_account =
        AccountBuilder::new(account_name.clone(), passphrase.clone())
            .save_passphrase(true)
            .create_archive(true)
            .create_authenticator(true)
            .create_contacts(true)
            .create_file_password(true)
            .default_folder_name(folder_name)
            .finish()?;

    // Create local provider
    let factory = ProviderFactory::Local;
    let (mut provider, _) =
        factory.create_provider(new_account.user.signer.clone())?;

    let imported_account = provider.import_new_account(&new_account).await?;

    let NewAccount { address, .. } = new_account;
    let ImportedAccount { summary, .. } = imported_account;

    let accounts = AccountManager::list_accounts()?;
    assert_eq!(1, accounts.len());

    let identity_index = Arc::new(SyncRwLock::new(SearchIndex::new(None)));
    let (_info, user, mut identity_keeper, _device_signer) =
        AccountManager::sign_in(
            &address,
            passphrase.clone(),
            Arc::clone(&identity_index),
        )
        .await?;

    AccountManager::rename_identity(
        &address,
        "New account name".to_string(),
        Some(&mut identity_keeper),
    )?;
    assert_eq!("New account name", identity_keeper.vault().name());

    let vaults = AccountManager::list_local_vaults(&address, false)?;
    // Default, Contacts, Authenticator and Archive vaults
    assert_eq!(4, vaults.len());

    let identity_reader = identity_index.read();

    // Check we can find the signing key
    let signing_urn: Urn = LOGIN_SIGNING_KEY_URN.parse()?;
    let signing_key =
        identity_reader.find_by_urn(identity_keeper.id(), &signing_urn);
    assert!(signing_key.is_some());

    // Check AGE key
    let age_urn: Urn = LOGIN_AGE_KEY_URN.parse()?;
    let age_key = identity_reader.find_by_urn(identity_keeper.id(), &age_urn);
    assert!(age_key.is_some());

    // Make sure we can find a vault passphrase and unlock it
    let default_vault_passphrase = AccountManager::find_vault_passphrase(
        &identity_keeper,
        summary.id(),
    )?;

    let (default_vault_summary, _) =
        AccountManager::find_default_vault(&address)?;
    assert_eq!(summary, default_vault_summary);

    let default_index = Arc::new(SyncRwLock::new(SearchIndex::new(None)));
    let (default_vault, _) =
        AccountManager::find_local_vault(&address, summary.id(), false)?;
    let mut default_vault_keeper =
        Gatekeeper::new(default_vault, Some(default_index));
    default_vault_keeper.unlock(default_vault_passphrase.expose_secret())?;

    let file_passphrase =
        AccountManager::find_file_encryption_passphrase(&identity_keeper)?;
    let source_file = PathBuf::from("tests/fixtures/test-file.txt");

    // Encrypt
    let files_dir = StorageDirs::files_dir(&address)?;
    let vault_id = VaultId::new_v4();
    let secret_id = SecretId::new_v4();
    let target = files_dir
        .join(vault_id.to_string())
        .join(secret_id.to_string());
    std::fs::create_dir_all(&target)?;
    let digest = FileStorage::encrypt_file_passphrase(
        &source_file,
        &target,
        file_passphrase.clone(),
    )?;

    // Decrypt
    let destination = target.join(hex::encode(digest));
    let buffer =
        FileStorage::decrypt_file_passphrase(destination, &file_passphrase)?;

    let expected = std::fs::read(source_file)?;
    assert_eq!(expected, buffer);

    let archive_buffer = AccountManager::export_archive_buffer(&address)?;
    let _inventory =
        AccountManager::restore_archive_inventory(archive_buffer.clone())?;

    // Restore from archive whilst signed in (with provider),
    // overwrites existing data (backup)
    let factory = ProviderFactory::Local;
    let (mut provider, _) = factory.create_provider(user.signer)?;
    let options = RestoreOptions {
        selected: vaults.clone().into_iter().map(|v| v.0).collect(),
        passphrase: Some(passphrase.clone()),
        files_dir: Some(files_dir.clone()),
        files_dir_builder: None,
    };
    AccountManager::restore_archive_buffer(
        archive_buffer.clone(),
        options,
        Some(&mut provider),
    )
    .await?;

    // Remove the account
    AccountManager::delete_account(&address)?;

    // Restore when not signed in - the account must not exist,
    // equivalent to importing an account
    let options = RestoreOptions {
        selected: vaults.into_iter().map(|v| v.0).collect(),
        passphrase: Some(passphrase),
        files_dir: Some(files_dir),
        files_dir_builder: None,
    };
    AccountManager::restore_archive_buffer(archive_buffer, options, None)
        .await?;

    // Reset the cache dir so we don't interfere
    // with other tests
    StorageDirs::clear_cache_dir();

    Ok(())
}
