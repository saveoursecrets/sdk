use crate::{
    crypto::secret_key::SecretKey,
    diceware::generate_passphrase,
    events::SyncEvent,
    secret::{Secret, SecretMeta},
    vault::{
        encode, CommitHash, SecretGroup, Vault, VaultAccess,
        DEFAULT_VAULT_NAME,
    },
    wal::{file::WalFile, WalProvider},
};
use std::{borrow::Cow, io::Write};
use uuid::Uuid;

use anyhow::Result;
use tempfile::NamedTempFile;

use argon2::password_hash::SaltString;

pub fn mock_encryption_key() -> Result<(SecretKey, SaltString)> {
    let salt = SecretKey::generate_salt();
    let (passphrase, _) = generate_passphrase(None)?;
    let encryption_key = SecretKey::derive_32(&passphrase, &salt)?;
    Ok((encryption_key, salt))
}

pub fn mock_vault() -> Vault {
    let vault: Vault = Default::default();
    vault
}

pub fn mock_vault_file() -> Result<(NamedTempFile, Vault, Vec<u8>)> {
    let mut temp = NamedTempFile::new()?;
    let vault = mock_vault();
    let buffer = encode(&vault)?;
    temp.write_all(&buffer)?;
    Ok((temp, vault, buffer))
}

pub fn mock_secret_note(
    label: &str,
    text: &str,
) -> Result<(SecretMeta, Secret, Vec<u8>, Vec<u8>)> {
    let secret_value = Secret::Note(text.to_string());
    let secret_meta = SecretMeta::new(label.to_string(), secret_value.kind());
    let meta_bytes = encode(&secret_meta)?;
    let secret_bytes = encode(&secret_value)?;
    Ok((secret_meta, secret_value, meta_bytes, secret_bytes))
}

pub fn mock_vault_note(
    vault: &mut Vault,
    encryption_key: &SecretKey,
    secret_label: &str,
    secret_note: &str,
) -> Result<(Uuid, CommitHash, SecretMeta, Secret)> {
    let (secret_meta, secret_value, meta_bytes, secret_bytes) =
        mock_secret_note(secret_label, secret_note)?;

    let meta_aead = vault.encrypt(encryption_key, &meta_bytes)?;
    let secret_aead = vault.encrypt(encryption_key, &secret_bytes)?;

    let (commit, _) = Vault::commit_hash(&meta_aead, &secret_aead)?;
    let secret_id =
        match vault.create(commit, SecretGroup(meta_aead, secret_aead))? {
            SyncEvent::CreateSecret(_, secret_id, _) => secret_id,
            _ => unreachable!(),
        };

    Ok((secret_id, commit, secret_meta, secret_value))
}

pub fn mock_wal_file() -> Result<(NamedTempFile, WalFile, Vec<CommitHash>)> {
    let (_, _, buffer) = mock_vault_file()?;

    let temp = NamedTempFile::new()?;
    let mut wal = WalFile::new(temp.path().to_path_buf())?;
    let payload: SyncEvent = SyncEvent::CreateVault(Cow::Owned(buffer));

    let mut commits = Vec::new();
    commits.push(wal.append_event(&payload)?);
    commits.push(wal.append_event(&payload)?);
    commits.push(wal.append_event(&payload)?);
    Ok((temp, wal, commits))
}
