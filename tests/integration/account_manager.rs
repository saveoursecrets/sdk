use anyhow::Result;
use secrecy::ExposeSecret;
use serial_test::serial;
use std::{sync::Arc, path::PathBuf};

use parking_lot::RwLock as SyncRwLock;
use sos_core::{
    constants::{LOGIN_AGE_KEY_URN, LOGIN_SIGNING_KEY_URN},
    generate_passphrase,
    search::SearchIndex,
    Gatekeeper,
};
use sos_node::{
    cache_dir, clear_cache_dir,
    client::account_manager::{
        AccountManager, NewAccountRequest, NewAccountResponse,
    },
    set_cache_dir,
};

use urn::Urn;

use crate::test_utils::*;

#[serial]
#[test]
fn integration_account_manager() -> Result<()> {
    let dirs = setup(1)?;

    let test_cache_dir = dirs.clients.get(0).unwrap();
    set_cache_dir(test_cache_dir.clone());

    assert_eq!(cache_dir(), Some(test_cache_dir.clone()));

    let account_name = "Mock account name".to_string();
    let folder_name = Some("Default folder".to_string());
    let (passphrase, _) = generate_passphrase()?;

    let account = NewAccountRequest {
        account_name: account_name.clone(),
        passphrase: passphrase.clone(),
        save_passphrase: true,
        create_archive: true,
        create_authenticator: true,
        create_contact: true,
        create_file_password: true,
        default_folder_name: folder_name,
    };

    let NewAccountResponse {
        address, summary, ..
    } = AccountManager::new_account(account)?;

    let accounts = AccountManager::list_accounts()?;
    assert_eq!(1, accounts.len());

    let identity_index = Arc::new(SyncRwLock::new(SearchIndex::new(None)));
    let (_info, _user, identity_keeper) = AccountManager::sign_in(
        &address,
        passphrase,
        Arc::clone(&identity_index),
    )?;

    let vaults = AccountManager::list_local_vaults(&address)?;
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
        AccountManager::find_local_vault(&address, summary.id())?;
    let mut default_vault_keeper =
        Gatekeeper::new(default_vault, Some(default_index));
    default_vault_keeper.unlock(default_vault_passphrase.expose_secret())?;

    let file_passphrase = AccountManager::find_file_encryption_passphrase(
        &identity_keeper,
    )?;
    let source_file = PathBuf::from("tests/fixtures/test-file.txt");
    
    // Encrypt
    let target = AccountManager::files_dir(&address)?;
    let digest = AccountManager::encrypt_file(
        &source_file, &target, file_passphrase.clone())?;

    // Decrypt
    let destination = target.join(hex::encode(digest));
    let buffer = AccountManager::decrypt_file(
        destination, &file_passphrase)?;

    let expected = std::fs::read(source_file)?;
    assert_eq!(expected, buffer);

    // TODO: test export/restore from archive

    // Reset the cache dir so we don't interfere
    // with other tests
    clear_cache_dir();

    Ok(())
}
