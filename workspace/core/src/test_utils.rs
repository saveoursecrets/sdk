use crate::{
    crypto::secret_key::SecretKey,
    diceware::generate_passphrase,
    secret::{Secret, SecretMeta},
    vault::{encode, Vault, DEFAULT_VAULT_NAME},
};

use anyhow::Result;
use uuid::Uuid;

use argon2::password_hash::SaltString;

pub fn mock_encryption_key() -> Result<(SecretKey, SaltString)> {
    let salt = SecretKey::generate_salt();
    let (passphrase, _) = generate_passphrase(None)?;
    let encryption_key = SecretKey::derive_32(&passphrase, &salt)?;
    Ok((encryption_key, salt))
}

pub fn mock_vault() -> Vault {
    let uuid = Uuid::new_v4();
    Vault::new(uuid, String::from(DEFAULT_VAULT_NAME), Default::default())
}

pub fn mock_secret_note(
    label: &str,
    text: &str,
) -> Result<(Uuid, SecretMeta, Secret, Vec<u8>, Vec<u8>)> {
    let secret_id = Uuid::new_v4();
    let secret_value = Secret::Note(text.to_string());
    let secret_meta = SecretMeta::new(label.to_string(), secret_value.kind());
    let meta_bytes = encode(&secret_meta)?;
    let secret_bytes = encode(&secret_value)?;
    Ok((
        secret_id,
        secret_meta,
        secret_value,
        meta_bytes,
        secret_bytes,
    ))
}
