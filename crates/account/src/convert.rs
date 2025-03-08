//! Convert account data.
use crate::{Account, Error, LocalAccount, Result};
use serde::{Deserialize, Serialize};
use sos_backend::AccessPoint;
use sos_client_storage::ClientFolderStorage;
use sos_core::{
    crypto::{AccessKey, Cipher, KeyDerivation},
    encode,
};
use sos_login::DelegatedAccess;
use sos_vault::{
    secret::SecretRow, BuilderCredentials, SecretAccess, Summary, Vault,
    VaultBuilder,
};

/// Comparison between an existing cipher and a
/// target cipher.
///
/// Used to determine which folders to modify when
/// changing the cipher for an account.
#[derive(Debug, Serialize, Deserialize)]
pub struct CipherComparison {
    /// Cipher to convert to.
    pub cipher: Cipher,
    /// Key derivation function.
    pub kdf: KeyDerivation,
    /// Identity folder conversion info.
    pub identity: Option<Summary>,
    /// User folders conversion info.
    pub folders: Vec<Summary>,
}

impl CipherComparison {
    /// Determine if this cipher conversion is empty.
    pub fn is_empty(&self) -> bool {
        self.identity.is_none() && self.folders.is_empty()
    }
}

impl LocalAccount {
    /// Build list of files to convert.
    pub(super) async fn compare_cipher(
        &self,
        cipher: &Cipher,
        kdf: Option<KeyDerivation>,
    ) -> Result<CipherComparison> {
        let kdf = kdf.unwrap_or_default();
        let identity = self.login_folder_summary().await?;

        let folders = self
            .storage
            .list_folders()
            .into_iter()
            .filter(|s| s.cipher() != cipher || s.kdf() != &kdf)
            .map(|s| s.clone())
            .collect::<Vec<_>>();

        let identity =
            if cipher != identity.cipher() || &kdf != identity.kdf() {
                Some(identity.clone())
            } else {
                None
            };

        Ok(CipherComparison {
            cipher: *cipher,
            kdf,
            identity,
            folders,
        })
    }

    /// Build list of files to convert.
    pub(super) async fn convert_cipher(
        &mut self,
        conversion: &CipherComparison,
        account_key: &AccessKey,
    ) -> Result<()> {
        for folder in &conversion.folders {
            let key = self
                .find_folder_password(folder.id())
                .await?
                .ok_or(Error::NoFolderPassword(*folder.id()))?;
            let vault = self
                .convert_folder_cipher(
                    &conversion.cipher,
                    &conversion.kdf,
                    folder,
                    &key,
                    true,
                )
                .await?;

            let buffer = encode(&vault).await?;
            self.import_folder_buffer(buffer, key, true).await?;
        }

        if let Some(identity) = &conversion.identity {
            let vault = self
                .convert_folder_cipher(
                    &conversion.cipher,
                    &conversion.kdf,
                    identity,
                    account_key,
                    false,
                )
                .await?;

            self.import_login_folder(vault).await?;
        };

        Ok(())
    }

    async fn convert_folder_cipher(
        &mut self,
        cipher: &Cipher,
        kdf: &KeyDerivation,
        folder: &Summary,
        key: &AccessKey,
        is_folder: bool,
    ) -> Result<Vault> {
        let id = folder.id();
        tracing::debug!(
            from = %folder.cipher(),
            to = %cipher,
            is_identity = %!is_folder,
            id = %id,
            "convert cipher");

        let vault = if is_folder {
            self.storage.read_vault(id).await?
        } else {
            self.storage.read_login_vault().await?
        };

        let seed = vault.seed().cloned();
        let name = vault.name().to_owned();
        let mut input = AccessPoint::from_vault(vault);
        input.unlock(key).await?;
        let meta = input.vault_meta().await?;

        let builder = VaultBuilder::new()
            .id(*input.id())
            .public_name(name)
            .description(meta.description().to_owned())
            .flags(folder.flags().clone())
            .kdf(kdf.clone())
            .cipher(*cipher);

        let output_vault = match key {
            AccessKey::Password(password) => {
                builder
                    .build(BuilderCredentials::Password(
                        password.clone(),
                        seed,
                    ))
                    .await?
            }
            _ => {
                todo!("handle asymmetric shared folders when changing cipher")
            }
        };

        let mut output = AccessPoint::from_vault(output_vault);
        output.unlock(key).await?;

        for key in input.vault().keys() {
            let (meta, secret, _) = input.read_secret(key).await?.unwrap();
            let secret_data = SecretRow::new(*key, meta, secret);
            output.create_secret(&secret_data).await?;
        }

        Ok(output.into())
    }
}
