use anyhow::Result;
use sos_sdk::{encoding::encoding_options, prelude::*};
use tokio::io::{AsyncRead, AsyncSeek, AsyncWrite};

use binary_stream::futures::{BinaryReader, BinaryWriter};
use futures::io::{BufReader, BufWriter, Cursor};

use uuid::Uuid;

use sos_test_utils::{
    mock_encryption_key, mock_secret_note, mock_vault_file,
};

async fn get_vault_entry(
    vault: &Vault,
    encryption_key: &PrivateKey,
    secret_label: &str,
    secret_note: &str,
) -> Result<(CommitHash, VaultEntry)> {
    let (_secret_meta, _secret_value, meta_bytes, secret_bytes) =
        mock_secret_note(secret_label, secret_note).await?;

    let meta_aead = vault.encrypt(encryption_key, &meta_bytes).await?;
    let secret_aead = vault.encrypt(encryption_key, &secret_bytes).await?;

    let (commit, _) = Vault::commit_hash(&meta_aead, &secret_aead).await?;

    let entry = VaultEntry(meta_aead, secret_aead);

    Ok((commit, entry))
}

async fn create_secure_note<
    F: AsyncRead + AsyncWrite + AsyncSeek + Unpin + Send,
>(
    vault_access: &mut VaultWriter<F>,
    vault: &Vault,
    encryption_key: &PrivateKey,
    secret_label: &str,
    secret_note: &str,
) -> Result<SecretId> {
    let (commit, entry) =
        get_vault_entry(vault, encryption_key, secret_label, secret_note)
            .await?;

    if let WriteEvent::CreateSecret(secret_id, _) =
        vault_access.create_secret(commit, entry).await?
    {
        Ok(secret_id)
    } else {
        panic!("expecting create secret payload");
    }
}

#[tokio::test]
async fn vault_encode_decode_row() -> Result<()> {
    let (encryption_key, _, _) = mock_encryption_key()?;
    let (_temp, vault) = mock_vault_file().await?;

    let secret_label = "Test note";
    let secret_note = "Super secret note for you to read.";
    let (commit, entry) =
        get_vault_entry(&vault, &encryption_key, secret_label, secret_note)
            .await?;

    let secret_id = SecretId::new_v4();
    let row = VaultCommit(commit, entry);

    let mut buffer = Vec::new();
    let mut stream = BufWriter::new(Cursor::new(&mut buffer));
    let mut writer = BinaryWriter::new(&mut stream, encoding_options());
    Contents::encode_row(&mut writer, &secret_id, &row).await?;
    writer.flush().await?;

    let mut stream = BufReader::new(Cursor::new(&mut buffer));
    let mut reader = BinaryReader::new(&mut stream, encoding_options());

    let (_secret_id, decoded_row) = Contents::decode_row(&mut reader).await?;
    assert_eq!(row, decoded_row);

    Ok(())
}

#[tokio::test]
async fn vault_file_access() -> Result<()> {
    let (encryption_key, _, _) = mock_encryption_key()?;
    let (temp, vault) = mock_vault_file().await?;

    let vault_file = VaultWriter::open(temp.path()).await?;
    let mut vault_access = VaultWriter::new(temp.path(), vault_file)?;

    // Missing row should not exist
    let missing_id = Uuid::new_v4();
    let (row, _) = vault_access.read_secret(&missing_id).await?;
    assert!(row.is_none());

    // Create a secret note
    let secret_label = "Test note";
    let secret_note = "Super secret note for you to read.";
    let secret_id = create_secure_note(
        &mut vault_access,
        &vault,
        &encryption_key,
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
        &mut vault_access,
        &vault,
        &encryption_key,
        secret_label,
        secret_note,
    )
    .await?;

    // Update the secret with new values
    let updated_label = "Updated test note";
    let updated_note = "Updated note text.";
    let (_, _, meta_bytes, secret_bytes) =
        mock_secret_note(updated_label, updated_note).await?;

    let updated_meta = vault.encrypt(&encryption_key, &meta_bytes).await?;
    let updated_secret =
        vault.encrypt(&encryption_key, &secret_bytes).await?;
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

    temp.close()?;

    Ok(())
}

#[tokio::test]
async fn vault_file_del_splice() -> Result<()> {
    let (encryption_key, _, _) = mock_encryption_key()?;
    let (temp, vault) = mock_vault_file().await?;

    let vault_file = VaultWriter::open(temp.path()).await?;
    let mut vault_access = VaultWriter::new(temp.path(), vault_file)?;

    let secrets = [
        ("Note one", "First note"),
        ("Note two", "Second note"),
        ("Note three", "Third note"),
    ];

    let mut secret_ids = Vec::new();
    for note_data in secrets {
        let secret_id = create_secure_note(
            &mut vault_access,
            &vault,
            &encryption_key,
            note_data.0,
            note_data.1,
        )
        .await?;
        secret_ids.push(secret_id);
    }

    let del_secret_id = secret_ids.get(1).unwrap();
    let _ = vault_access.delete_secret(del_secret_id).await?;

    // Check the file identity is good after the deletion splice
    assert!(Header::read_header_file(temp.path()).await.is_ok());

    // Clean up other secrets
    for secret_id in secret_ids {
        let _ = vault_access.delete_secret(&secret_id).await?;
    }

    // Verify again to finish up
    assert!(Header::read_header_file(temp.path()).await.is_ok());

    temp.close()?;

    Ok(())
}
