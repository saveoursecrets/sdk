use anyhow::Result;
use sos_backend::{BackendTarget, VaultWriter};
use sos_core::{encode, AccountId, Paths, VaultFlags};
use sos_test_utils::mock;
use sos_vault::{EncryptedEntry, Vault};
use sos_vfs as vfs;
use tempfile::tempdir_in;

#[tokio::test]
async fn vault_writer_flags_filesystem() -> Result<()> {
    let temp = tempdir_in("target")?;
    let account_id = AccountId::random();

    let (vault, _password) = mock::vault_memory().await?;
    Paths::scaffold(&temp.path().to_owned()).await?;

    let paths = Paths::new_client(temp.path()).with_account_id(&account_id);
    paths.ensure().await?;

    let buffer = encode(&vault).await?;
    vfs::write(paths.vault_path(vault.id()), &buffer).await?;

    let mut vault_access =
        VaultWriter::new(BackendTarget::FileSystem(paths), vault.id());

    test_vault_flags(&mut vault_access).await?;
    temp.close()?;
    Ok(())
}

#[tokio::test]
async fn vault_writer_flags_database() -> Result<()> {
    let temp = tempdir_in("target")?;
    let mut db_client = mock::memory_database().await?;
    let vault: Vault = Default::default();
    let (account_id, _, _) =
        mock::insert_database_vault(&mut db_client, &vault, false).await?;
    let paths = Paths::new_client(temp.path()).with_account_id(&account_id);
    let mut vault_access = VaultWriter::new(
        BackendTarget::Database(paths, db_client),
        vault.id(),
    );
    test_vault_flags(&mut vault_access).await?;
    temp.close()?;
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
