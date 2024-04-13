//! Convert account data.
use crate::{
    account::Account,
    crypto::{AccessKey, Cipher, KeyDerivation},
    decode, encode,
    vault::{
        secret::SecretRow, BuilderCredentials, Gatekeeper, Summary, Vault,
        VaultBuilder,
    },
    vfs,
};
use serde::{Deserialize, Serialize};

/// Conversion paths for an account.
#[derive(Debug, Serialize, Deserialize)]
pub struct CipherConversion {
    /// Cipher to convert to.
    pub cipher: Cipher,
    /// Key derivation function.
    pub kdf: KeyDerivation,
    /// Identity folder conversion info.
    pub identity: Option<Summary>,
    /// User folders conversion info.
    pub folders: Vec<Summary>,
}

impl CipherConversion {
    /// Determine if this cipher conversion is empty.
    pub fn is_empty(&self) -> bool {
        self.identity.is_none() && self.folders.is_empty()
    }
}

/// Convert the cipher in use by an account.
pub struct ConvertCipher;

impl ConvertCipher {
    /// Build list of files to convert.
    pub(super) async fn build<'a, A>(
        account: &'a A,
        cipher: &Cipher,
        kdf: Option<KeyDerivation>,
    ) -> std::result::Result<CipherConversion, A::Error>
    where
        A: Account,
    {
        let kdf = kdf.unwrap_or_default();
        let identity = account.identity_folder_summary().await?;
        let folders = account
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

        Ok(CipherConversion {
            cipher: *cipher,
            kdf,
            identity,
            folders,
        })
    }

    /// Build list of files to convert.
    pub(super) async fn convert<'a, A>(
        account: &'a mut A,
        conversion: &CipherConversion,
        account_key: &AccessKey,
    ) -> std::result::Result<(), A::Error>
    where
        A: Account,
        A::Error: From<std::io::Error>,
        A::Error: From<crate::error::Error>,
    {
        for folder in &conversion.folders {
            let key = account.find_folder_password(folder.id()).await?;
            let vault = Self::convert_folder_cipher(
                account,
                &conversion.cipher,
                &conversion.kdf,
                folder,
                &key,
                true,
            )
            .await?;

            let buffer = encode(&vault).await?;
            account.import_folder_buffer(buffer, key, true).await?;
        }

        if let Some(identity) = &conversion.identity {
            let vault = Self::convert_folder_cipher(
                account,
                &conversion.cipher,
                &conversion.kdf,
                identity,
                account_key,
                false,
            )
            .await?;

            account.import_identity_vault(vault).await?;
        };

        Ok(())
    }

    async fn convert_folder_cipher<'a, A>(
        account: &'a mut A,
        cipher: &Cipher,
        kdf: &KeyDerivation,
        folder: &Summary,
        key: &AccessKey,
        is_folder: bool,
    ) -> std::result::Result<Vault, A::Error>
    where
        A: Account,
        A::Error: From<std::io::Error>,
        A::Error: From<crate::error::Error>,
    {
        let id = folder.id();
        tracing::debug!(
            from = %folder.cipher(),
            to = %cipher,
            is_identity = %!is_folder,
            id = %id,
            "convert cipher");

        let paths = account.paths();
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
