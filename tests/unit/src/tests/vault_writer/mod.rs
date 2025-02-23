use anyhow::Result;
use sos_core::commit::CommitHash;
use sos_sdk::prelude::*;
use sos_test_utils::mock;

mod encode_decode;
mod vault_access;
mod vault_file_writer;
mod vault_flags;

pub(crate) async fn get_vault_entry(
    vault: &Vault,
    encryption_key: &PrivateKey,
    secret_label: &str,
    secret_note: &str,
) -> Result<(CommitHash, VaultEntry)> {
    let (_secret_meta, _secret_value, meta_bytes, secret_bytes) =
        mock::secret_note(secret_label, secret_note).await?;
    let meta_aead = vault.encrypt(encryption_key, &meta_bytes).await?;
    let secret_aead = vault.encrypt(encryption_key, &secret_bytes).await?;
    let commit = Vault::commit_hash(&meta_aead, &secret_aead).await?;
    let entry = VaultEntry(meta_aead, secret_aead);
    Ok((commit, entry))
}

pub(crate) async fn create_secure_note(
    vault_access: &mut impl EncryptedEntry,
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
