use anyhow::Result;
use sos_database::VaultDatabaseWriter;
use sos_filesystem::VaultFileWriter;
use sos_sdk::prelude::*;
use sos_test_utils::{mock, mock_vault_file};

#[tokio::test]
async fn vault_flags_filesystem() -> Result<()> {
    let (temp, _) = mock_vault_file().await?;
    let mut vault_access = VaultFileWriter::new(temp.path()).await?;
    test_vault_flags(&mut vault_access).await?;
    temp.close()?;
    Ok(())
}

#[tokio::test]
async fn vault_flags_database() -> Result<()> {
    let mut db_client = mock::memory_database().await?;
    let vault: Vault = Default::default();
    mock::insert_database_vault(&mut db_client, &vault).await?;
    let mut vault_access =
        VaultDatabaseWriter::new(db_client, *vault.id()).await;
    test_vault_flags(&mut vault_access).await?;
    Ok(())
}

async fn test_vault_flags(vault_access: &mut impl VaultAccess) -> Result<()> {
    let flags = VaultFlags::NO_SYNC;
    vault_access.set_vault_flags(flags.clone()).await?;
    let summary = vault_access.summary().await?;
    assert_eq!(summary.flags(), &flags);
    Ok(())
}
