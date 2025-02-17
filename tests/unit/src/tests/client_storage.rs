use anyhow::Result;
use secrecy::SecretString;
use sos_account::AccountBuilder;
use sos_backend::BackendTarget;
use sos_client_storage::{
    AccountPack, ClientAccountStorage, ClientBaseStorage,
    ClientFolderStorage, ClientStorage,
};
use sos_core::{encode, AccountId, FolderRef, Paths};
use sos_login::Identity;
use sos_sdk::{crypto::AccessKey, prelude::generate_passphrase};
use sos_test_utils::mock::memory_database;
use tempfile::tempdir_in;

const ACCOUNT_NAME: &str = "client_storage";
const MAIN_NAME: &str = "main";

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

    let key: AccessKey = password.into();
    authenticated_user.sign_in(account_id, &key).await?;
    storage.authenticate(authenticated_user).await?;

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
        .await?;

    assert!(storage.identity_state().await.is_ok());
    assert!(storage.commit_state(main.id()).await.is_ok());

    storage.open_folder(main.id())?;
    assert!(storage.current_folder().is_some());
    storage.delete_folder(main.id(), true).await?;
    assert!(storage.current_folder().is_none());

    let main_buffer = encode(&main_vault).await?;

    storage
        .import_folder(&main_buffer, main_key.as_ref(), true, None)
        .await?;

    Ok(())
}
