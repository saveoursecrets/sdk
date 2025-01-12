use anyhow::Result;
use sos_backend::VaultWriter;
use sos_sdk::prelude::*;
use sos_test_utils::mock;

#[tokio::test]
async fn vault_flags_filesystem() -> Result<()> {
    let (temp, _, _) = mock::vault_file().await?;
    let mut vault_access = VaultWriter::new_fs(temp.path()).await?;
    test_vault_flags(&mut vault_access).await?;
    temp.close()?;
    Ok(())
}

#[tokio::test]
async fn vault_flags_database() -> Result<()> {
    let mut db_client = mock::memory_database().await?;
    let vault: Vault = Default::default();
    mock::insert_database_vault(&mut db_client, &vault).await?;
    let mut vault_access = VaultWriter::new_db(db_client, *vault.id()).await;
    test_vault_flags(&mut vault_access).await?;
    Ok(())
}

async fn test_vault_flags(
    vault_access: &mut impl EncryptedEntry,
) -> Result<()> {
    let flags = VaultFlags::NO_SYNC;
    vault_access.set_vault_flags(flags.clone()).await?;
    let summary = vault_access.summary().await?;
    assert_eq!(summary.flags(), &flags);
    Ok(())
}
