use super::create_secure_note;
use anyhow::Result;
use sos_filesystem::VaultFileWriter;
use sos_sdk::prelude::*;
use sos_test_utils::{
    mock_encryption_key, mock_secret_note, mock_vault_file,
};
use uuid::Uuid;

/// Test the VaultAccess implementation for the filesystem.
#[tokio::test]
async fn vault_access_filesystem() -> Result<()> {
    let (encryption_key, _, _) = mock_encryption_key()?;
    let (temp, vault) = mock_vault_file().await?;
    let mut vault_access = VaultFileWriter::new(temp.path()).await?;
    test_vault_access(&mut vault_access, vault, &encryption_key).await?;
    temp.close()?;
    Ok(())
}

async fn test_vault_access(
    vault_access: &mut impl VaultAccess,
    vault: Vault,
    encryption_key: &PrivateKey,
) -> Result<()> {
    // Missing row should not exist
    let missing_id = Uuid::new_v4();
    let (row, _) = vault_access.read_secret(&missing_id).await?;
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
    let (row, _) = vault_access.read_secret(&secret_id).await?;
    assert!(row.is_some());

    // Delete the secret
    let _ = vault_access.delete_secret(&secret_id).await?;

    // Verify it does not exist after deletion
    let (row, _) = vault_access.read_secret(&secret_id).await?;
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
        mock_secret_note(updated_label, updated_note).await?;

    let updated_meta = vault.encrypt(encryption_key, &meta_bytes).await?;
    let updated_secret = vault.encrypt(encryption_key, &secret_bytes).await?;
    let (commit, _) =
        Vault::commit_hash(&updated_meta, &updated_secret).await?;
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
