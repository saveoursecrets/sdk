use anyhow::Result;
use sos_backend::{BackendTarget, ServerOrigins};
use sos_core::{AccountId, Paths};
use sos_test_utils::{
    assert::assert_server_origins,
    mock::{insert_database_account, memory_database},
};
use tempfile::tempdir_in;

#[tokio::test]
async fn fs_server_origins() -> Result<()> {
    let temp = tempdir_in("target")?;
    let account_id = AccountId::random();
    let paths = Paths::new_client(temp.path()).with_account_id(&account_id);
    paths.ensure().await?;
    let mut servers =
        ServerOrigins::new(BackendTarget::FileSystem(paths), &account_id);
    assert_server_origins(&mut servers).await?;
    Ok(())
}

#[tokio::test]
async fn db_server_origins() -> Result<()> {
    let temp = tempdir_in("target")?;
    let mut client = memory_database().await?;
    let (account_id, _) = insert_database_account(&mut client).await?;
    let paths = Paths::new_client(temp.path());
    let mut servers = ServerOrigins::new(
        BackendTarget::Database(paths, client),
        &account_id,
    );
    assert_server_origins(&mut servers).await?;
    Ok(())
}
