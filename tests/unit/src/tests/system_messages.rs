use anyhow::Result;
use sos_backend::{BackendTarget, SystemMessages};
use sos_core::{AccountId, Paths};
use sos_test_utils::{
    assert::assert_system_messages,
    mock::{insert_database_account, memory_database},
};
use tempfile::tempdir_in;

#[tokio::test]
async fn fs_system_messages() -> Result<()> {
    let temp = tempdir_in("target")?;
    let account_id = AccountId::random();
    let paths = Paths::new_client(temp.path()).with_account_id(&account_id);
    paths.ensure().await?;
    let mut messages =
        SystemMessages::new(BackendTarget::FileSystem(paths), &account_id);
    assert_system_messages(&mut messages).await?;
    temp.close()?;
    Ok(())
}

#[tokio::test]
async fn db_system_messages() -> Result<()> {
    let temp = tempdir_in("target")?;
    let mut client = memory_database().await?;
    let (account_id, _) = insert_database_account(&mut client).await?;
    let paths = Paths::new_client(temp.path()).with_account_id(&account_id);
    let mut messages = SystemMessages::new(
        BackendTarget::Database(paths, client),
        &account_id,
    );
    assert_system_messages(&mut messages).await?;
    temp.close()?;
    Ok(())
}
