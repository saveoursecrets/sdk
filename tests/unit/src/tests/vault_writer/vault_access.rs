use super::create_secure_note;
use anyhow::Result;
use sos_backend::{BackendTarget, VaultWriter};
use sos_core::{
    constants::DEFAULT_VAULT_NAME, crypto::PrivateKey, encode, AccountId,
    Paths, VaultEntry,
};
use sos_test_utils::mock;
use sos_vault::{EncryptedEntry, Vault};
use sos_vfs as vfs;
use tempfile::tempdir_in;
use uuid::Uuid;

/// Test the EncryptedEntry implementation for the filesystem.
#[tokio::test]
async fn vault_writer_access_filesystem() -> Result<()> {
    let temp = tempdir_in("target")?;
    let account_id = AccountId::random();
    let (encryption_key, _, _) = mock::encryption_key()?;

    let (vault, _password) = mock::vault_memory().await?;
    Paths::scaffold(&temp.path().to_owned()).await?;

    let paths = Paths::new_client(temp.path()).with_account_id(&account_id);
    paths.ensure().await?;

    let buffer = encode(&vault).await?;
    vfs::write(paths.vault_path(vault.id()), &buffer).await?;

    let mut vault_access =
        VaultWriter::new(BackendTarget::FileSystem(paths), vault.id());
    assert_encrypted_entry(&mut vault_access, vault, &encryption_key).await?;
    temp.close()?;
    Ok(())
}

/// Test the EncryptedEntry implementation for the database.
#[tokio::test]
async fn vault_writer_access_database() -> Result<()> {
    let temp = tempdir_in("target")?;
    let (encryption_key, _, _) = mock::encryption_key()?;
    let mut db_client = mock::memory_database().await?;
    let vault: Vault = Default::default();
    let (account_id, _, _) =
        mock::insert_database_vault(&mut db_client, &vault, false).await?;
    let paths = Paths::new_client(temp.path()).with_account_id(&account_id);
    let mut vault_access = VaultWriter::new(
        BackendTarget::Database(paths, db_client),
        vault.id(),
    );
    assert_encrypted_entry(&mut vault_access, vault, &encryption_key).await?;
    temp.close()?;
    Ok(())
}

async fn assert_encrypted_entry(
    vault_access: &mut impl EncryptedEntry,
    vault: Vault,
    encryption_key: &PrivateKey,
) -> Result<()> {
    // Missing row should not exist
    let missing_id = Uuid::new_v4();
    let row = vault_access.read_secret(&missing_id).await?;
    assert!(row.is_none());

    // Create a secret note
    let secret_label = "Test note";
    let secret_note = "Super secret note for you to read.";
    let secret_id = create_secure_note(
        vault_access,
        &vault,
        encryption_key,
        secret_label,
        secret_note,
    )
    .await?;

    // Verify the secret exists
    let row = vault_access.read_secret(&secret_id).await?;
    assert!(row.is_some());

    // Delete the secret
    let _ = vault_access.delete_secret(&secret_id).await?;

    // Verify it does not exist after deletion
    let row = vault_access.read_secret(&secret_id).await?;
    assert!(row.is_none());

    // Create a new secure note so we can update it
    let secret_id = create_secure_note(
        vault_access,
        &vault,
        encryption_key,
        secret_label,
        secret_note,
    )
    .await?;

    // Update the secret with new values
    let updated_label = "Updated test note";
    let updated_note = "Updated note text.";
    let (_, _, meta_bytes, secret_bytes) =
        mock::secret_note(updated_label, updated_note).await?;

    let updated_meta = vault.encrypt(encryption_key, &meta_bytes).await?;
    let updated_secret = vault.encrypt(encryption_key, &secret_bytes).await?;
    let commit = Vault::commit_hash(&updated_meta, &updated_secret).await?;
    let _ = vault_access
        .update_secret(
            &secret_id,
            commit,
            VaultEntry(updated_meta, updated_secret),
        )
        .await?;

    // Clean up the secret for next test execution
    let _ = vault_access.delete_secret(&secret_id).await?;

    let vault_name = vault_access.vault_name().await?;
    assert_eq!(DEFAULT_VAULT_NAME, &vault_name);

    let new_name = String::from("New vault name");
    let _ = vault_access.set_vault_name(new_name.clone()).await;

    let vault_name = vault_access.vault_name().await?;
    assert_eq!(&new_name, &vault_name);

    // Reset the fixture vault name
    let _ = vault_access.set_vault_name(DEFAULT_VAULT_NAME.to_string());

    Ok(())
}
