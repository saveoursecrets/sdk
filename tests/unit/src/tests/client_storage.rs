use anyhow::Result;
use futures::{pin_mut, StreamExt};
use secrecy::SecretString;
use sos_account::AccountBuilder;
use sos_backend::BackendTarget;
use sos_client_storage::{
    AccountPack, ClientAccountStorage, ClientBaseStorage,
    ClientFolderStorage, ClientStorage, NewFolderOptions,
};
use sos_core::{
    crypto::AccessKey, encode, events::EventLog, AccountId, FolderRef, Paths,
    VaultFlags, VaultId,
};
use sos_login::{DelegatedAccess, FolderKeys, Identity};
use sos_password::diceware::generate_passphrase;
use sos_sync::StorageEventLogs;
use sos_test_utils::mock::memory_database;
use std::collections::HashMap;
use tempfile::tempdir_in;

const ACCOUNT_NAME: &str = "client_storage";
const MAIN_NAME: &str = "main";
const NEW_NAME: &str = "new-folder";
const RENAME: &str = "renamed-folder";

#[tokio::test]
async fn fs_client_storage() -> Result<()> {
    let temp = tempdir_in("target")?;
    Paths::scaffold(Some(temp.path().to_owned())).await?;

    let account_id = AccountId::random();

    let paths = Paths::new_global(temp.path()).with_account_id(&account_id);
    paths.ensure().await?;

    let target = BackendTarget::FileSystem(paths.clone());

    // Prepare account then run assertions on the storage
    prepare_account(paths, account_id, target).await?;

    Ok(())
}

#[tokio::test]
async fn db_client_storage() -> Result<()> {
    let temp = tempdir_in("target")?;
    Paths::scaffold(Some(temp.path().to_owned())).await?;

    let account_id = AccountId::random();

    let client = memory_database().await?;
    let paths = Paths::new_global(temp.path()).with_account_id(&account_id);
    paths.ensure_db().await?;

    let target = BackendTarget::Database(client);

    // Prepare account then run assertions on the storage
    prepare_account(paths, account_id, target).await?;

    Ok(())
}

async fn prepare_account(
    paths: Paths,
    account_id: AccountId,
    target: BackendTarget,
) -> Result<()> {
    let (password, _) = generate_passphrase()?;
    let account_builder = AccountBuilder::new(
        ACCOUNT_NAME.to_string(),
        password.clone(),
        target.clone(),
    );

    let new_account = account_builder
        .default_folder_name(MAIN_NAME.to_owned())
        .create_file_password(true)
        .account_id(account_id)
        .finish()
        .await?;
    let (authenticated_user, account_pack) = new_account.into();

    let mut storage = ClientStorage::new_unauthenticated(
        &paths,
        &account_id,
        target.clone(),
    )
    .await?;
    assert_client_storage(
        &mut storage,
        &account_id,
        target,
        password,
        authenticated_user,
        account_pack,
    )
    .await?;
    Ok(())
}

/// Assert on client storage implementations.
///
/// Sets the description many times as setting the description
/// requires the vault to be correctly initialized so we verify
/// the state of the vault after certain operations.
async fn assert_client_storage(
    storage: &mut ClientStorage,
    account_id: &AccountId,
    target: BackendTarget,
    password: SecretString,
    mut authenticated_user: Identity,
    account_pack: AccountPack,
) -> Result<()> {
    assert_eq!(account_id, storage.account_id());

    storage.create_account(&account_pack).await?;

    let accounts = target.list_accounts().await?;
    assert_eq!(1, accounts.len());

    // Need folder access keys to initialize the search index
    let mut folder_keys = {
        let mut keys = HashMap::new();
        for folder in storage.list_folders() {
            if let Some(key) = authenticated_user
                .identity()?
                .find_folder_password(folder.id())
                .await?
            {
                keys.insert(*folder.id(), key);
            }
        }
        FolderKeys(keys)
    };

    let key: AccessKey = password.into();
    authenticated_user.sign_in(account_id, &key).await?;
    storage.authenticate(authenticated_user).await?;
    assert!(storage.is_authenticated());
    storage.initialize_search_index(&folder_keys).await?;

    let main = {
        let folders = storage.list_folders();
        assert_eq!(1, folders.len());
        let main = folders.get(0).unwrap();
        assert_eq!(MAIN_NAME, main.name());

        let main_folder_by_name = storage
            .find_folder(&FolderRef::Name(main.name().to_owned()))
            .unwrap();
        let main_folder_by_id =
            storage.find_folder(&FolderRef::Id(*main.id())).unwrap();
        assert_eq!(main, main_folder_by_name);
        assert_eq!(main, main_folder_by_id);
        main.clone()
    };

    // Store the vault so we can import after deletion
    let main_vault = storage.read_vault(main.id()).await?;
    let main_key = storage
        .authenticated_user()
        .unwrap()
        .find_folder_password(main.id())
        .await?
        .unwrap();
    let main_buffer = encode(&main_vault).await?;

    // Lock and unlock folder
    storage.lock_folder(main_vault.id()).await?;
    storage.unlock_folder(main_vault.id(), &main_key).await?;

    assert_description(storage, main_vault.id(), "main-folder").await?;

    assert!(storage.identity_state().await.is_ok());
    assert!(storage.commit_state(main.id()).await.is_ok());

    storage.open_folder(main.id())?;
    assert!(storage.current_folder().is_some());
    // Should close currently open folder on deletion
    storage.delete_folder(main.id(), true).await?;
    assert!(storage.current_folder().is_none());

    storage
        .import_folder(&main_buffer, Some(&main_key), true, None)
        .await?;
    assert_description(storage, main_vault.id(), "main-folder-after-import")
        .await?;

    // Should have the create vault event and update
    // from setting the description
    let events = storage.history(main_vault.id()).await?;
    assert_eq!(2, events.len());

    storage
        .create_folder(NewFolderOptions::new(NEW_NAME.to_owned()))
        .await?;
    {
        // In-memory
        let folders = storage.list_folders();
        assert_eq!(2, folders.len());

        // Read from storage
        let folders = storage.load_folders().await?;
        assert_eq!(2, folders.len());
    }

    storage.compact_folder(main_vault.id(), &main_key).await?;
    assert_description(storage, main_vault.id(), "main-folder-after-compact")
        .await?;

    storage.rename_folder(main_vault.id(), RENAME).await?;
    {
        // In-memory
        let folder = storage.find(|f| f.id() == main_vault.id()).unwrap();
        assert_eq!(RENAME, folder.name());

        // Read from storage
        let folders = storage.load_folders().await?;
        let folder =
            folders.iter().find(|f| f.id() == main_vault.id()).unwrap();
        assert_eq!(RENAME, folder.name());
    }

    let new_flags = VaultFlags::AUTHENTICATOR;
    storage
        .update_folder_flags(main_vault.id(), new_flags.clone())
        .await?;
    {
        // In-memory
        let folder = storage.find(|f| f.id() == main_vault.id()).unwrap();
        assert_eq!(&new_flags, folder.flags());

        // Read from storage
        let folders = storage.load_folders().await?;
        let folder =
            folders.iter().find(|f| f.id() == main_vault.id()).unwrap();
        assert_eq!(&new_flags, folder.flags());
    }

    // Collect events so we can restore the folder
    let events = {
        let mut events = Vec::new();
        let event_log = storage.folder_log(main_vault.id()).await?;
        let event_log = event_log.read().await;
        let stream = event_log.record_stream(false).await;
        pin_mut!(stream);
        while let Some(record) = stream.next().await {
            events.push(record?);
        }
        events
    };

    // Delete and then restore from events
    storage.delete_folder(main.id(), true).await?;
    storage.restore_folder(events.clone(), &main_key).await?;
    assert_description(storage, main_vault.id(), "main-folder-after-restore")
        .await?;

    // Update a vault from a collection of events
    let mut main_events = Vec::new();
    for event in &events {
        main_events.push(event.decode_event().await?);
    }
    storage.update_vault(&main_vault, main_events).await?;
    assert_description(storage, main_vault.id(), "main-folder-after-update")
        .await?;

    // Remove a folder from memory and re-load from disc
    storage.remove_folder(main_vault.id()).await?;
    storage.load_folders().await?;
    storage.unlock_folder(main_vault.id(), &main_key).await?;
    // Removing a non-existent folder
    assert!(!storage.remove_folder(&VaultId::new_v4()).await?);

    assert_description(storage, main_vault.id(), "main-folder-after-load")
        .await?;

    let (password, _) = generate_passphrase()?;
    let new_key: AccessKey = password.into();
    storage
        .change_password(&main_vault, main_key, new_key.clone())
        .await?;
    // Must save so we can unlock later
    folder_keys
        .save_folder_password(main_vault.id(), new_key)
        .await?;

    // Lock and unlock
    storage.lock().await;
    storage.unlock(&folder_keys).await?;

    // Sign out the authenticated user
    storage.sign_out().await?;

    Ok(())
}

async fn assert_description(
    storage: &mut ClientStorage,
    id: &VaultId,
    folder_description: &str,
) -> Result<()> {
    storage
        .set_description(id, folder_description.to_owned())
        .await?;
    let description = storage.description(id).await?;
    assert_eq!(folder_description, &description);
    Ok(())
}
