use anyhow::Result;
use sos_core::{AccountId, Paths, VaultFlags};
use sos_server_storage::{ServerAccountStorage, ServerStorage};
use sos_sync::{CreateSet, MergeOutcome, UpdateSet};
use sos_test_utils::mock::{insert_database_vault, memory_database};
use sos_vault::Vault;
use tempfile::tempdir_in;

#[tokio::test]
async fn fs_server_storage() -> Result<()> {
    let temp = tempdir_in("target")?;
    Paths::scaffold(Some(temp.path().to_owned())).await?;

    let account_id = AccountId::random();
    let mut storage = ServerStorage::new_fs(temp.path(), &account_id).await?;
    assert_server_storage(&mut storage, &account_id).await?;
    Ok(())
}

#[tokio::test]
async fn db_server_storage() -> Result<()> {
    let temp = tempdir_in("target")?;
    Paths::scaffold(Some(temp.path().to_owned())).await?;

    let mut client = memory_database().await?;
    let mut vault: Vault = Default::default();
    *vault.flags_mut() = VaultFlags::IDENTITY;
    let (account_id, _, _) =
        insert_database_vault(&mut client, &vault).await?;

    let mut storage =
        ServerStorage::new_db(client, &account_id, temp.path()).await?;
    assert_server_storage(&mut storage, &account_id).await?;
    Ok(())
}

/// Assert on server storage implementations.
async fn assert_server_storage(
    storage: &mut ServerStorage,
    account_id: &AccountId,
) -> Result<()> {
    assert_eq!(account_id, storage.account_id());
    assert!(storage.list_device_keys().is_empty());

    let paths = storage.paths();
    paths.ensure().await?;

    let account_data = CreateSet::default();
    storage.import_account(&account_data).await?;

    let mut outcome = MergeOutcome::default();
    let account_data = UpdateSet::default();
    storage.update_account(account_data, &mut outcome).await?;

    // Delete the account
    storage.delete_account().await?;

    Ok(())
}
