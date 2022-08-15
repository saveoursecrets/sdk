use crate::{
    crypto::secret_key::SecretKey,
    encode,
    events::SyncEvent,
    generate_passphrase,
    secret::{Secret, SecretId, SecretMeta},
    vault::{Vault, VaultAccess, VaultEntry},
    CommitHash,
};
use std::{borrow::Cow, io::Write};
use uuid::Uuid;

use anyhow::Result;
use secrecy::{ExposeSecret, SecretString};

use argon2::password_hash::SaltString;

pub fn mock_encryption_key() -> Result<(SecretKey, SaltString, SecretString)>
{
    let salt = SecretKey::generate_salt();
    let (passphrase, _) = generate_passphrase()?;
    let encryption_key =
        SecretKey::derive_32(passphrase.expose_secret(), &salt)?;
    Ok((encryption_key, salt, passphrase))
}

pub fn mock_vault() -> Vault {
    let vault: Vault = Default::default();
    vault
}

pub fn mock_secret_note(
    label: &str,
    text: &str,
) -> Result<(SecretMeta, Secret, Vec<u8>, Vec<u8>)> {
    let secret_value = Secret::Note(secrecy::Secret::new(text.to_string()));
    let secret_meta = SecretMeta::new(label.to_string(), secret_value.kind());
    let meta_bytes = encode(&secret_meta)?;
    let secret_bytes = encode(&secret_value)?;
    Ok((secret_meta, secret_value, meta_bytes, secret_bytes))
}

pub fn mock_vault_note<'a>(
    vault: &'a mut Vault,
    encryption_key: &SecretKey,
    secret_label: &str,
    secret_note: &str,
) -> Result<(Uuid, CommitHash, SecretMeta, Secret, SyncEvent<'a>)> {
    let (secret_meta, secret_value, meta_bytes, secret_bytes) =
        mock_secret_note(secret_label, secret_note)?;

    let meta_aead = vault.encrypt(encryption_key, &meta_bytes)?;
    let secret_aead = vault.encrypt(encryption_key, &secret_bytes)?;

    let (commit, _) = Vault::commit_hash(&meta_aead, &secret_aead)?;
    let event = vault.create(commit, VaultEntry(meta_aead, secret_aead))?;
    let secret_id = match &event {
        SyncEvent::CreateSecret(secret_id, _) => *secret_id,
        _ => unreachable!(),
    };

    Ok((secret_id, commit, secret_meta, secret_value, event))
}

pub fn mock_vault_note_update<'a>(
    vault: &'a mut Vault,
    encryption_key: &SecretKey,
    id: &SecretId,
    secret_label: &str,
    secret_note: &str,
) -> Result<(CommitHash, SecretMeta, Secret, Option<SyncEvent<'a>>)> {
    let (secret_meta, secret_value, meta_bytes, secret_bytes) =
        mock_secret_note(secret_label, secret_note)?;

    let meta_aead = vault.encrypt(encryption_key, &meta_bytes)?;
    let secret_aead = vault.encrypt(encryption_key, &secret_bytes)?;

    let (commit, _) = Vault::commit_hash(&meta_aead, &secret_aead)?;
    let event =
        vault.update(id, commit, VaultEntry(meta_aead, secret_aead))?;
    Ok((commit, secret_meta, secret_value, event))
}

#[cfg(not(target_arch = "wasm32"))]
mod file {
    use crate::{
        crypto::secret_key::SecretKey,
        encode,
        events::WalEvent,
        vault::Vault,
        wal::{file::WalFile, WalProvider},
        CommitHash,
    };
    use tempfile::NamedTempFile;

    use super::*;

    pub fn mock_vault_file() -> Result<(NamedTempFile, Vault, Vec<u8>)> {
        let mut temp = NamedTempFile::new()?;
        let vault = mock_vault();
        let buffer = encode(&vault)?;
        temp.write_all(&buffer)?;
        Ok((temp, vault, buffer))
    }

    pub fn mock_wal_file(
    ) -> Result<(NamedTempFile, WalFile, Vec<CommitHash>, SecretKey)> {
        let (encryption_key, _, _) = mock_encryption_key()?;
        let (_, mut vault, buffer) = mock_vault_file()?;

        let temp = NamedTempFile::new()?;
        let mut wal = WalFile::new(temp.path())?;

        let mut commits = Vec::new();

        // Create the vault
        let event = WalEvent::CreateVault(Cow::Owned(buffer));
        commits.push(wal.append_event(event)?);

        // Create a secret
        let (secret_id, _, _, _, event) = mock_vault_note(
            &mut vault,
            &encryption_key,
            "WAL Note",
            "This a WAL note secret.",
        )?;
        commits.push(wal.append_event(event.try_into()?)?);

        // Update the secret
        let (_, _, _, event) = mock_vault_note_update(
            &mut vault,
            &encryption_key,
            &secret_id,
            "WAL Note Edited",
            "This a WAL note secret that was edited.",
        )?;
        if let Some(event) = event {
            commits.push(wal.append_event(event.try_into()?)?);
        }

        Ok((temp, wal, commits, encryption_key))
    }
}

#[cfg(not(target_arch = "wasm32"))]
pub use self::file::*;
