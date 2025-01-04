//! Test utility functions.
use anyhow::Result;
use argon2::password_hash::SaltString;
use secrecy::{SecretBox, SecretString};
use sha2::{Digest, Sha256};
use sos_core::commit::CommitHash;
use sos_password::diceware::generate_passphrase;
use sos_sdk::{
    crypto::{KeyDerivation, PrivateKey},
    encode,
    events::{EventLogExt, FolderEventLog, WriteEvent},
    vault::{
        secret::{FileContent, Secret, SecretId, SecretMeta},
        BuilderCredentials, Vault, VaultAccess, VaultBuilder, VaultEntry,
    },
};
use std::io::Write;
use tempfile::NamedTempFile;
use uuid::Uuid;

/// Generate a mock encyption key.
pub fn mock_encryption_key() -> Result<(PrivateKey, SaltString, SecretString)>
{
    let salt = KeyDerivation::generate_salt();
    let (passphrase, _) = generate_passphrase()?;
    let kdf: KeyDerivation = Default::default();
    let deriver = kdf.deriver();
    let derived_key = deriver.derive(&passphrase, &salt, None)?;
    Ok((PrivateKey::Symmetric(derived_key), salt, passphrase))
}

/// Generate a mock secret note.
pub async fn mock_secret_note(
    label: &str,
    text: &str,
) -> Result<(SecretMeta, Secret, Vec<u8>, Vec<u8>)> {
    let secret_value = Secret::Note {
        text: text.to_string().into(),
        user_data: Default::default(),
    };
    let secret_meta = SecretMeta::new(label.to_string(), secret_value.kind());
    let meta_bytes = encode(&secret_meta).await?;
    let secret_bytes = encode(&secret_value).await?;
    Ok((secret_meta, secret_value, meta_bytes, secret_bytes))
}

/// Generate a mock secret file.
pub async fn mock_secret_file(
    label: &str,
    name: &str,
    mime: &str,
    buffer: Vec<u8>,
) -> Result<(SecretMeta, Secret, Vec<u8>, Vec<u8>)> {
    let checksum = Sha256::digest(&buffer);
    let secret_value = Secret::File {
        content: FileContent::Embedded {
            name: name.to_string(),
            mime: mime.to_string(),
            checksum: checksum.into(),
            buffer: SecretBox::new(buffer.into()),
        },
        user_data: Default::default(),
    };
    let secret_meta = SecretMeta::new(label.to_string(), secret_value.kind());
    let meta_bytes = encode(&secret_meta).await?;
    let secret_bytes = encode(&secret_value).await?;
    Ok((secret_meta, secret_value, meta_bytes, secret_bytes))
}

/// Generate a mock secret note and add it to a vault.
pub async fn mock_vault_note(
    vault: &mut Vault,
    encryption_key: &PrivateKey,
    secret_label: &str,
    secret_note: &str,
) -> Result<(Uuid, CommitHash, SecretMeta, Secret, WriteEvent)> {
    let (secret_meta, secret_value, meta_bytes, secret_bytes) =
        mock_secret_note(secret_label, secret_note).await?;

    let meta_aead = vault.encrypt(encryption_key, &meta_bytes).await?;

    let secret_aead = vault.encrypt(encryption_key, &secret_bytes).await?;

    let (commit, _) = Vault::commit_hash(&meta_aead, &secret_aead).await?;
    let event = vault
        .create_secret(commit, VaultEntry(meta_aead, secret_aead))
        .await?;
    let secret_id = match &event {
        WriteEvent::CreateSecret(secret_id, _) => *secret_id,
        _ => unreachable!(),
    };

    Ok((secret_id, commit, secret_meta, secret_value, event))
}

/// Generate a mock secret note and update a vault entry.
pub async fn mock_vault_note_update(
    vault: &mut Vault,
    encryption_key: &PrivateKey,
    id: &SecretId,
    secret_label: &str,
    secret_note: &str,
) -> Result<(CommitHash, SecretMeta, Secret, Option<WriteEvent>)> {
    let (secret_meta, secret_value, meta_bytes, secret_bytes) =
        mock_secret_note(secret_label, secret_note).await?;

    let meta_aead = vault.encrypt(encryption_key, &meta_bytes).await?;
    let secret_aead = vault.encrypt(encryption_key, &secret_bytes).await?;

    let (commit, _) = Vault::commit_hash(&meta_aead, &secret_aead).await?;
    let event = vault
        .update_secret(id, commit, VaultEntry(meta_aead, secret_aead))
        .await?;
    Ok((commit, secret_meta, secret_value, event))
}

/// Create a mock vault in a temp file.
pub async fn mock_vault_file() -> Result<(NamedTempFile, Vault)> {
    let mut temp = NamedTempFile::new()?;
    let (passphrase, _) = generate_passphrase()?;
    let vault = VaultBuilder::new()
        .build(BuilderCredentials::Password(passphrase, None))
        .await?;

    let buffer = encode(&vault).await?;
    temp.write_all(&buffer)?;
    Ok((temp, vault))
}

/// Create a mock event log in a temp file.
pub async fn mock_event_log_file(
) -> Result<(NamedTempFile, FolderEventLog, PrivateKey)> {
    let (encryption_key, _, _) = mock_encryption_key()?;
    let (_, mut vault) = mock_vault_file().await?;

    let temp = NamedTempFile::new()?;
    let mut event_log = FolderEventLog::new(temp.path()).await?;

    // Create the vault
    let event = vault.into_event().await?;
    event_log.apply(vec![&event]).await?;

    // Create a secret
    let (secret_id, _, _, _, event) = mock_vault_note(
        &mut vault,
        &encryption_key,
        "event log Note",
        "This a event log note secret.",
    )
    .await?;
    event_log.apply(vec![&event]).await?;

    // Update the secret
    let (_, _, _, event) = mock_vault_note_update(
        &mut vault,
        &encryption_key,
        &secret_id,
        "event log Note Edited",
        "This a event log note secret that was edited.",
    )
    .await?;
    if let Some(event) = event {
        event_log.apply(vec![&event]).await?;
    }

    Ok((temp, event_log, encryption_key))
}
