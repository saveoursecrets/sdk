use anyhow::Result;
use sos_backend::ServerOrigins;
use sos_core::{AccountId, Paths};
use sos_test_utils::{
    assert::assert_server_origins,
    mock::{insert_database_account, memory_database},
};
use std::sync::Arc;
use tempfile::tempdir_in;

#[tokio::test]
async fn fs_server_origins() -> Result<()> {
    let temp = tempdir_in("target")?;
    let account_id = AccountId::random();
    let paths = Paths::new(temp.path(), account_id.to_string());
    paths.ensure().await?;
    let mut servers = ServerOrigins::new_fs(Arc::new(paths));
    assert_server_origins(&mut servers).await?;
    Ok(())
}

#[tokio::test]
async fn db_server_origins() -> Result<()> {
    let mut client = memory_database().await?;
    let (account_id, _) = insert_database_account(&mut client).await?;
    let mut servers = ServerOrigins::new_db(client, account_id);
    assert_server_origins(&mut servers).await?;
    Ok(())
}
