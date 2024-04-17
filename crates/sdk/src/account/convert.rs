//! Convert account data.
use crate::{
    account::{Account, LocalAccount},
    crypto::{AccessKey, Cipher, KeyDerivation},
    decode, encode,
    vault::{
        secret::SecretRow, BuilderCredentials, Gatekeeper, Summary, Vault,
        VaultBuilder,
    },
    vfs, Result,
};
use serde::{Deserialize, Serialize};

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
        let identity = self.identity_folder_summary().await?;
        let folders = self
            .list_folders()
            .await?
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
            let key = self.find_folder_password(folder.id()).await?;
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

            self.import_identity_folder(vault).await?;
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

        let paths = self.paths();
        let vault_path = if is_folder {
            paths.vault_path(id)
        } else {
            paths.identity_vault()
        };
        // let events_path = paths.event_log_path(id);
        let buffer = vfs::read(&vault_path).await?;
        let input_vault: Vault = decode(&buffer).await?;

        let seed = input_vault.seed().cloned();
        let name = input_vault.name().to_owned();
        let mut input = Gatekeeper::new(input_vault);
        input.unlock(key).await?;
        let meta = input.vault_meta().await?;

        let builder = VaultBuilder::new()
            .id(*input.id())
            .public_name(name)
            .description(meta.description)
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

        let mut output = Gatekeeper::new(output_vault);
        output.unlock(key).await?;

        for key in input.vault().keys() {
            let (meta, secret, _) = input.read_secret(key).await?.unwrap();
            let secret_data = SecretRow::new(*key, meta, secret);
            output.create_secret(&secret_data).await?;
        }

        Ok(output.into())
    }
}
