//! Generate and manage delegated passwords stored in an identity vault.
use crate::{
    constants::FILE_PASSWORD_URN,
    crypto::AccessKey,
    passwd::diceware::generate_passphrase_words,
    vault::{
        secret::{Secret, SecretMeta},
        Gatekeeper, Vault, VaultId,
    },
    Error, Result,
};
use secrecy::{ExposeSecret, SecretString};
use urn::Urn;

/// Number of words to use when generating passphrases for vaults.
const VAULT_PASSPHRASE_WORDS: usize = 12;

/// Delegated passphrase manager.
pub struct DelegatedPassphrase;

impl DelegatedPassphrase {
    /// Generate a vault passphrase.
    pub fn generate_vault_passphrase() -> Result<SecretString> {
        let (vault_passphrase, _) =
            generate_passphrase_words(VAULT_PASSPHRASE_WORDS)?;
        Ok(vault_passphrase)
    }

    /// Save a vault passphrase into an identity vault.
    pub async fn save_vault_passphrase(
        identity: &mut Gatekeeper,
        vault_id: &VaultId,
        key: AccessKey,
    ) -> Result<()> {
        let urn = Vault::vault_urn(vault_id)?;

        let secret = match key {
            AccessKey::Password(vault_passphrase) => Secret::Password {
                name: None,
                password: vault_passphrase,
                user_data: Default::default(),
            },
            AccessKey::Identity(id) => Secret::Age {
                version: Default::default(),
                key: id.to_string(),
                user_data: Default::default(),
            },
        };

        let mut meta =
            SecretMeta::new(urn.as_str().to_owned(), secret.kind());
        meta.set_urn(Some(urn));
        identity.create(meta, secret).await?;

        Ok(())
    }

    /// Remove a vault passphrase from an identity vault.
    pub async fn remove_vault_passphrase(
        identity: &mut Gatekeeper,
        vault_id: &VaultId,
    ) -> Result<()> {
        let urn = Vault::vault_urn(vault_id)?;
        let index = identity.index();
        let index_reader = index.read().await;
        let document = index_reader
            .find_by_urn(identity.id(), &urn)
            .ok_or(Error::NoVaultEntry(urn.to_string()))?;

        let id = *document.id();

        // Must drop the index reader as deleting
        // will write to the index
        drop(index_reader);

        identity.delete(&id).await?;

        Ok(())
    }

    /// Find a vault passphrase in an identity vault using the
    /// search index associated with the vault.
    ///
    /// The identity vault must already be unlocked to extract
    /// the secret passphrase.
    pub async fn find_vault_passphrase(
        identity: &Gatekeeper,
        vault_id: &VaultId,
    ) -> Result<AccessKey> {
        let urn = Vault::vault_urn(vault_id)?;
        let index = identity.index();
        let index_reader = index.read().await;
        let document = index_reader
            .find_by_urn(identity.id(), &urn)
            .ok_or_else(|| Error::NoVaultEntry(urn.to_string()))?;

        let (_, secret, _) = identity
            .read(document.id())
            .await?
            .ok_or_else(|| Error::NoVaultEntry(document.id().to_string()))?;

        let key = match secret {
            Secret::Password { password, .. } => {
                AccessKey::Password(password)
            }
            Secret::Age { key, .. } => {
                AccessKey::Identity(key.expose_secret().parse().map_err(
                    |s: &str| Error::InvalidAgeIdentity(s.to_owned()),
                )?)
            }
            _ => return Err(Error::VaultEntryKind(urn.to_string())),
        };
        Ok(key)
    }

    /// Find the passphrase used for symmetric file encryption (AGE).
    pub async fn find_file_encryption_passphrase(
        identity: &Gatekeeper,
    ) -> Result<SecretString> {
        let index = identity.index();
        let reader = index.read().await;
        let urn: Urn = FILE_PASSWORD_URN.parse()?;
        let document = reader
            .find_by_urn(identity.id(), &urn)
            .ok_or_else(|| Error::NoVaultEntry(urn.to_string()))?;
        let password =
            if let Some((_, Secret::Password { password, .. }, _)) =
                identity.read(document.id()).await?
            {
                password
            } else {
                return Err(Error::VaultEntryKind(urn.to_string()));
            };
        Ok(password)
    }
}
