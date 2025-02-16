use anyhow::Result;
use sos_backend::BackendTarget;
use sos_client_storage::{
    AccountPack, ClientAccountStorage, ClientBaseStorage,
    ClientFolderStorage, ClientStorage,
};
use sos_core::{AccountId, Paths, VaultFlags};
use sos_sdk::prelude::generate_passphrase;
use sos_test_utils::mock::{insert_database_vault, memory_database};
use sos_vault::{BuilderCredentials, Vault, VaultBuilder};
use tempfile::tempdir_in;

#[tokio::test]
async fn fs_client_storage() -> Result<()> {
    let temp = tempdir_in("target")?;
    Paths::scaffold(Some(temp.path().to_owned())).await?;

    let account_id = AccountId::random();

    let paths = Paths::new_global(temp.path()).with_account_id(&account_id);
    paths.ensure().await?;

    let mut storage = ClientStorage::new_unauthenticated(
        &paths,
        &account_id,
        BackendTarget::FileSystem(paths.clone()),
    )
    .await?;
    assert_client_storage(&mut storage, &account_id).await?;
    Ok(())
}

#[tokio::test]
async fn db_client_storage() -> Result<()> {
    let temp = tempdir_in("target")?;
    Paths::scaffold(Some(temp.path().to_owned())).await?;

    let mut client = memory_database().await?;
    let mut vault: Vault = Default::default();
    *vault.flags_mut() = VaultFlags::IDENTITY;
    let (account_id, _, _) =
        insert_database_vault(&mut client, &vault, true).await?;

    let paths = Paths::new_global(temp.path()).with_account_id(&account_id);
    paths.ensure_db().await?;

    let mut storage = ClientStorage::new_unauthenticated(
        &paths,
        &account_id,
        BackendTarget::Database(client),
    )
    .await?;
    assert_client_storage(&mut storage, &account_id).await?;
    Ok(())
}

/// Assert on client storage implementations.
async fn assert_client_storage(
    storage: &mut ClientStorage,
    account_id: &AccountId,
) -> Result<()> {
    assert_eq!(account_id, storage.account_id());

    let identity_name = "login";
    let main_name = "main";

    let (password, _) = generate_passphrase()?;
    let identity_vault = VaultBuilder::new()
        .flags(VaultFlags::IDENTITY)
        .public_name(identity_name.to_owned())
        .build(BuilderCredentials::Password(password.clone(), None))
        .await?;

    let main_vault = VaultBuilder::new()
        .public_name(main_name.to_owned())
        .build(BuilderCredentials::Password(password.clone(), None))
        .await?;

    let account_folders = vec![main_vault];
    let account_pack = AccountPack {
        account_id: *account_id,
        identity_vault: identity_vault.clone(),
        folders: account_folders,
    };

    storage.create_account(&account_pack).await?;

    let folders = storage.list_folders();
    assert_eq!(1, folders.len());
    let main = folders.get(0).unwrap();
    assert_eq!(main_name, main.name());

    // println!("{:#?}", folders);

    Ok(())
}
