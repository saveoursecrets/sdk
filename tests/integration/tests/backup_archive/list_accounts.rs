use anyhow::Result;
use sos_backend::archive::try_list_backup_archive_accounts;
use std::path::Path;

/// Test listing accounts in a v1 backup archive.
#[tokio::test]
async fn backup_list_accounts_v1() -> Result<()> {
    //crate::test_utils::init_tracing();
    let archive =
        "../fixtures/backups/v1/0xba0faea9bbc182e3f4fdb3eea7636b5bb31ea9ac.zip";
    assert_list_accounts(archive, 1).await?;
    Ok(())
}

/// Test listing accounts in a v2 backup archive.
#[tokio::test]
async fn backup_list_accounts_v2() -> Result<()> {
    //crate::test_utils::init_tracing();
    let archive =
        "../fixtures/backups/v2/0xba0faea9bbc182e3f4fdb3eea7636b5bb31ea9ac.zip";
    assert_list_accounts(archive, 1).await?;
    Ok(())
}

/// Test listing accounts in a v3 backup archive.
#[tokio::test]
async fn backup_list_accounts_v3() -> Result<()> {
    //crate::test_utils::init_tracing();
    let archive =
        "../fixtures/backups/v3/0xba0faea9bbc182e3f4fdb3eea7636b5bb31ea9ac.zip";
    assert_list_accounts(archive, 1).await?;
    Ok(())
}

/// Test listing accounts in a v3 backup archive
/// when multiple accounts are present.
#[tokio::test]
async fn backup_list_accounts_v3_multiple() -> Result<()> {
    //crate::test_utils::init_tracing();
    let archive = "../fixtures/backups/v3/multiple-accounts.zip";
    assert_list_accounts(archive, 2).await?;
    Ok(())
}

async fn assert_list_accounts(
    input: impl AsRef<Path>,
    expected: usize,
) -> Result<()> {
    let accounts = try_list_backup_archive_accounts(input.as_ref()).await?;
    assert_eq!(expected, accounts.len());
    Ok(())
}
