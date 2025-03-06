use anyhow::Result;
use futures::{pin_mut, StreamExt};
use secrecy::SecretString;
use sos_account::AccountBuilder;
use sos_backend::BackendTarget;
use sos_client_storage::{
    AccessOptions, AccountPack, ClientAccountStorage, ClientBaseStorage,
    ClientDeviceStorage, ClientFolderStorage, ClientSecretStorage,
    ClientStorage, NewFolderOptions,
};
use sos_core::{
    crypto::AccessKey, encode, events::EventLog, AccountId, FolderRef, Paths,
    SecretId, VaultFlags, VaultId,
};
use sos_core::{
    device::TrustedDevice,
    events::{patch::FolderPatch, DeviceEvent, EventRecord},
};
use sos_database::open_file;
use sos_login::{
    device::DeviceSigner, DelegatedAccess, FolderKeys, Identity,
};
use sos_password::diceware::generate_passphrase;
use sos_reducers::FolderReducer;
use sos_sync::{CreateSet, StorageEventLogs, SyncStorage};
use sos_test_utils::{mock, setup, teardown};
use sos_vault::secret::SecretRow;
use std::collections::HashMap;
use tempfile::tempdir_in;

const ACCOUNT_NAME: &str = "client_storage";
const MAIN_NAME: &str = "main";
const NEW_NAME: &str = "new-folder";
const RENAME: &str = "renamed-folder";

const MOCK_NOTE: &str = "mock-note";
const MOCK_VALUE: &str = "mock-value";

const MOCK_NOTE_UPDATED: &str = "mock-note-updated";
const MOCK_VALUE_UPDATED: &str = "mock-value-updated";

#[tokio::test]
async fn fs_client_storage() -> Result<()> {
    let temp = tempdir_in("target")?;
    Paths::scaffold(&temp.path().to_owned()).await?;

    let account_id = AccountId::random();

    let paths = Paths::new_client(temp.path()).with_account_id(&account_id);
    paths.ensure().await?;

    let target = BackendTarget::FileSystem(paths);

    // Prepare account then run assertions on the storage
    let (create_set, password, folder_id, secret_id) =
        prepare_account(account_id, target.clone()).await?;

    // Assert on importing an account as if it were fetched from
    // a remote, for example, when enrolling a new device
    prepare_import(
        account_id, target, create_set, password, folder_id, secret_id,
    )
    .await?;

    Ok(())
}

#[tokio::test]
async fn db_client_storage() -> Result<()> {
    const TEST_ID: &str = "db_client_storage";
    // sos_test_utils::init_tracing();

    let mut dirs = setup(TEST_ID, 1).await?;
    let data_dir = dirs.clients.remove(0);

    let account_id = AccountId::random();

    let paths = Paths::new_client(&data_dir).with_account_id(&account_id);
    paths.ensure_db().await?;

    let mut client = open_file(paths.database_file()).await?;
    sos_database::migrations::migrate_client(&mut client).await?;
    let target = BackendTarget::Database(paths.clone(), client);

    // Prepare account then run assertions on the storage
    let (create_set, password, folder_id, secret_id) =
        prepare_account(account_id, target.clone()).await?;

    // Assert on importing an account as if it were fetched from
    // a remote, for example, when enrolling a new device
    prepare_import(
        account_id, target, create_set, password, folder_id, secret_id,
    )
    .await?;

    teardown(TEST_ID).await;

    Ok(())
}

async fn prepare_account(
    account_id: AccountId,
    target: BackendTarget,
) -> Result<(CreateSet, SecretString, VaultId, SecretId)> {
    let (password, _) = generate_passphrase()?;
    let (new_folder_password, _) = generate_passphrase()?;

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

    let mut storage =
        ClientStorage::new_unauthenticated(target.clone(), &account_id)
            .await?;

    let (create_set, folder_id, secret_id) = assert_client_storage(
        &mut storage,
        &account_id,
        target,
        password.clone(),
        new_folder_password,
        authenticated_user,
        account_pack,
    )
    .await?;

    Ok((create_set, password, folder_id, secret_id))
}

async fn prepare_import(
    account_id: AccountId,
    target: BackendTarget,
    create_set: CreateSet,
    password: SecretString,
    folder_id: VaultId,
    secret_id: SecretId,
) -> Result<()> {
    // Create a new account like we would in a pairing enrollment
    let mut storage = ClientStorage::new_account(
        target.clone(),
        &account_id,
        "imported-account".to_owned(),
    )
    .await?;
    // Import the data and check we can sign in
    assert_import_account(
        &mut storage,
        &account_id,
        target,
        password,
        create_set,
        folder_id,
        secret_id,
    )
    .await?;
    Ok(())
}

async fn sign_in(
    storage: &mut ClientStorage,
    mut authenticated_user: Identity,
    account_id: &AccountId,
    password: SecretString,
) -> Result<(AccessKey, FolderKeys)> {
    let key: AccessKey = password.into();
    authenticated_user.sign_in(account_id, &key).await?;

    // Need folder access keys to initialize the search index
    let folder_keys = {
        let mut keys = HashMap::new();
        for folder in storage.list_folders() {
            if let Some(key) = authenticated_user
                .identity()?
                .find_folder_password(folder.id())
                .await?
            {
                keys.insert(*folder.id(), key);
            } else {
                panic!("no folder password for {}", folder.id());
            }
        }
        FolderKeys(keys)
    };

    storage.authenticate(authenticated_user).await?;
    assert!(storage.is_authenticated());
    storage.initialize_search_index(&folder_keys).await?;

    Ok((key, folder_keys))
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
    new_password: SecretString,
    authenticated_user: Identity,
    account_pack: AccountPack,
) -> Result<(CreateSet, VaultId, SecretId)> {
    assert_eq!(account_id, storage.account_id());

    storage.create_account(&account_pack).await?;

    let accounts = target.list_accounts().await?;
    assert_eq!(1, accounts.len());

    let (_, mut folder_keys) =
        sign_in(storage, authenticated_user, account_id, password.clone())
            .await?;

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

    let new_key: AccessKey = new_password.clone().into();
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

    // Create a secret
    let secret_id = SecretId::new_v4();
    let (meta, secret) = mock::note(MOCK_NOTE, MOCK_VALUE);
    let secret_data = SecretRow::new(secret_id, meta, secret);
    let options = AccessOptions {
        folder: Some(*main_vault.id()),
        ..Default::default()
    };
    storage
        .create_secret(secret_data.clone(), options.clone())
        .await?;

    // Should be able to read the raw encrypted data
    let result = storage.raw_secret(main_vault.id(), &secret_id).await?;
    assert!(result.is_some());

    // Assert on the read
    let (_, meta, secret, _) =
        storage.read_secret(&secret_id, &options).await?;
    assert_eq!(secret_data.meta(), &meta);
    assert_eq!(secret_data.secret(), &secret);

    // Update the secret
    let (new_meta, new_secret) =
        mock::note(MOCK_NOTE_UPDATED, MOCK_VALUE_UPDATED);
    storage
        .update_secret(
            &secret_id,
            new_meta.clone(),
            Some(new_secret.clone()),
            options.clone(),
        )
        .await?;
    let (_, meta, secret, _) =
        storage.read_secret(&secret_id, &options).await?;
    assert_eq!(&new_meta, &meta);
    assert_eq!(&new_secret, &secret);

    // Delete the secret
    storage.delete_secret(&secret_id, options).await?;

    // Recreate the secret so we can assert after
    // importing the account data
    let (meta, secret) = mock::note(MOCK_NOTE, MOCK_VALUE);
    let secret_data = SecretRow::new(secret_id, meta, secret);
    let options = AccessOptions {
        folder: Some(*main_vault.id()),
        ..Default::default()
    };
    storage
        .create_secret(secret_data.clone(), options.clone())
        .await?;

    // Device patch and revoke
    let device_signer = DeviceSigner::new_random();
    let device_public_key = device_signer.public_key();
    let user_device = TrustedDevice::new(device_public_key, None, None);
    let event = DeviceEvent::Trust(user_device);
    storage.patch_devices_unchecked(&[event]).await?;
    assert_eq!(2, storage.devices().len());
    storage.revoke_device(&device_public_key).await?;
    assert_eq!(1, storage.devices().len());

    // Check we can import folder patches
    let main_vault = storage.read_vault(main.id()).await?;
    let main_id = *main_vault.id();
    let (_, events) =
        FolderReducer::split::<sos_backend::Error>(main_vault).await?;
    let mut records = Vec::new();
    for event in &events {
        records.push(EventRecord::encode_event(event).await?);
    }
    let patch = FolderPatch::new(records);
    let mut patches = HashMap::new();
    patches.insert(main_id, patch);
    storage.import_folder_patches(patches).await?;

    assert_eq!(2, storage.list_folders().len());

    // Check we can import a login vault
    let login_vault = storage.read_login_vault().await?;
    storage.import_login_vault(login_vault).await?;

    let create_set = storage.create_set().await?;

    // debug_login_vault(storage, &password).await?;

    // Must be signed in to delete the account
    storage.delete_account().await?;

    Ok((create_set, main_id, secret_id))
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

async fn assert_import_account(
    storage: &mut ClientStorage,
    account_id: &AccountId,
    target: BackendTarget,
    password: SecretString,
    create_set: CreateSet,
    folder_id: VaultId,
    secret_id: SecretId,
) -> Result<()> {
    assert_eq!(account_id, storage.account_id());

    storage.import_account(&create_set).await?;

    // debug_login_vault(storage, &password).await?;

    let authenticated_user = Identity::new(target.clone());
    sign_in(storage, authenticated_user, account_id, password.clone())
        .await?;

    let options = AccessOptions {
        folder: Some(folder_id),
        ..Default::default()
    };

    let (_, meta, _, _) = storage.read_secret(&secret_id, &options).await?;
    assert_eq!(MOCK_NOTE, meta.label());

    // Sign out the authenticated user
    storage.sign_out().await?;

    Ok(())
}

/*
async fn debug_login_vault(
    storage: &mut ClientStorage,
    password: &SecretString,
) -> Result<()> {
    use sos_backend::AccessPoint;
    use sos_vault::SecretAccess;
    let login_vault = storage.read_login_vault().await?;
    println!("--- LOGIN ({}) ---", login_vault.len());
    let mut access_point = AccessPoint::new_vault(login_vault);
    let key: AccessKey = password.clone().into();
    access_point.unlock(&key).await?;
    for id in access_point.vault().keys() {
        let (meta, _, _) = access_point.read_secret(id).await?.unwrap();
        println!("urn: {:#?}", meta.urn());
    }
    Ok(())
}
*/
