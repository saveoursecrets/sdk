use anyhow::Result;
use sos_backend::audit;
use sos_test_utils::{
    assert::assert_audit_provider,
    mock::{insert_database_account, memory_database},
};
use tempfile::NamedTempFile;

#[tokio::test]
async fn fs_audit_provider() -> Result<()> {
    let temp = NamedTempFile::new()?;
    let mut provider = audit::new_fs_provider(temp.path());
    assert_audit_provider(&mut provider).await?;
    Ok(())
}

#[tokio::test]
async fn db_audit_provider() -> Result<()> {
    let client = memory_database().await?;
    let mut provider = audit::new_db_provider(client);
    assert_audit_provider(&mut provider).await?;
    Ok(())
}
