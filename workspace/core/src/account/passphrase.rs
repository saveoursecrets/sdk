//! Generate and manage delegated passwords stored in an identity vault.
use crate::{
    passwd::diceware::generate_passphrase_words,
    vault::{
        secret::{Secret, SecretMeta},
        Gatekeeper, Vault, VaultId,
    },
    Error, Result,
};
use secrecy::SecretString;

/// Number of words to use when generating passphrases for vaults.
const VAULT_PASSPHRASE_WORDS: usize = 12;

/// Generate a vault passphrase.
pub fn generate_vault_passphrase() -> Result<SecretString> {
    let (vault_passphrase, _) =
        generate_passphrase_words(VAULT_PASSPHRASE_WORDS)?;
    Ok(vault_passphrase)
}

/// Save a vault passphrase into an identity vault.
pub fn save_vault_passphrase(
    identity: &mut Gatekeeper,
    vault_id: &VaultId,
    vault_passphrase: SecretString,
) -> Result<()> {
    let urn = Vault::vault_urn(vault_id)?;

    let secret = Secret::Password {
        name: None,
        password: vault_passphrase,
        user_data: Default::default(),
    };
    let mut meta = SecretMeta::new(urn.as_str().to_owned(), secret.kind());
    meta.set_urn(Some(urn));
    identity.create(meta, secret)?;
    Ok(())
}

/// Remove a vault passphrase from an identity vault.
pub fn remove_vault_passphrase(
    identity: &mut Gatekeeper,
    vault_id: &VaultId,
) -> Result<()> {
    let urn = Vault::vault_urn(vault_id)?;
    let index = identity.index();
    let index_reader = index.read();
    let document = index_reader
        .find_by_urn(identity.id(), &urn)
        .ok_or(Error::NoVaultEntry(urn.to_string()))?;

    let id = *document.id();

    // Must drop the index reader as deleting
    // will write to the index
    drop(index_reader);

    identity.delete(&id)?;

    Ok(())
}
