use anyhow::Result;
use sos_backend::SystemMessages;
use sos_core::{AccountId, Paths};
use sos_test_utils::{
    assert::assert_system_messages,
    mock::{insert_database_account, memory_database},
};
use std::sync::Arc;
use tempfile::tempdir_in;

#[tokio::test]
async fn fs_system_messages() -> Result<()> {
    let temp = tempdir_in("target")?;
    let account_id = AccountId::random();
    let paths = Paths::new(temp.path(), account_id.to_string());
    paths.ensure().await?;
    let mut messages = SystemMessages::new_fs(Arc::new(paths));
    assert_system_messages(&mut messages).await?;
    Ok(())
}

#[tokio::test]
async fn db_system_messages() -> Result<()> {
    let mut client = memory_database().await?;
    let (account_id, _) = insert_database_account(&mut client).await?;
    let mut messages = SystemMessages::new_db(account_id, client);
    assert_system_messages(&mut messages).await?;
    Ok(())
}
