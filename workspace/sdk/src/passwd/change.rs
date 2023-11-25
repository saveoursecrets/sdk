//! Flow for changing a vault password.

use crate::{
    crypto::{AccessKey, KeyDerivation, PrivateKey, Seed},
    encode,
    events::WriteEvent,
    vault::{Vault, VaultAccess, VaultCommit, VaultEntry},
    Error, Result,
};

use std::borrow::Cow;

/// Builder that changes a vault password.
///
/// Generates a new vault derived from the original vault so
/// it is possible for callers to rollback to the original if
/// necessary.
pub struct ChangePassword<'a> {
    /// The in-memory vault.
    vault: &'a Vault,
    /// Existing encryption passphrase.
    current_key: AccessKey,
    /// New encryption passphrase.
    new_key: AccessKey,
    /// Optional seed for the new passphrase.
    seed: Option<Seed>,
}

impl<'a> ChangePassword<'a> {
    /// Create a new change password builder.
    pub fn new(
        vault: &'a Vault,
        current_key: AccessKey,
        new_key: AccessKey,
        seed: Option<Seed>,
    ) -> Self {
        Self {
            vault,
            current_key,
            new_key,
            seed,
        }
    }

    fn current_private_key(&self) -> Result<PrivateKey> {
        let salt = self.vault.salt().ok_or(Error::VaultNotInit)?;
        let salt = KeyDerivation::parse_salt(salt)?;
        self.current_key.clone().into_private(
            self.vault.kdf(),
            &salt,
            self.vault.seed(),
        )

        /*
        let salt = self.vault.salt().ok_or(Error::VaultNotInit)?;
        let salt = KeyDerivation::parse_salt(salt)?;
        let deriver = self.vault.deriver();
        let derived_private_key = deriver.derive(
            &self.current_key,
            &salt,
            self.vault.seed(),
        )?;
        Ok(PrivateKey::Symmetric(derived_private_key))
        */
    }

    fn new_private_key(&self, vault: &Vault) -> Result<PrivateKey> {
        let salt = vault.salt().ok_or(Error::VaultNotInit)?;
        let salt = KeyDerivation::parse_salt(salt)?;
        self.new_key
            .clone()
            .into_private(vault.kdf(), &salt, vault.seed())

        /*
        let salt = vault.salt().ok_or(Error::VaultNotInit)?;
        let salt = KeyDerivation::parse_salt(salt)?;
        let deriver = vault.deriver();
        let derived_private_key =
            deriver.derive(&self.new_key, &salt, vault.seed())?;
        Ok(PrivateKey::Symmetric(derived_private_key))
            */
    }

    /// Build a new vault.
    ///
    /// Yields the encrpytion passphrase for the new vault, the
    /// new computed vault and a collection of events that can
    /// be used to generate a fresh write-ahead log file.
    pub async fn build(
        self,
    ) -> Result<(AccessKey, Vault, Vec<WriteEvent<'static>>)> {
        // Decrypt current vault meta data blob
        let current_private_key = self.current_private_key()?;
        let vault_meta_aead =
            self.vault.header().meta().ok_or(Error::VaultNotInit)?;
        let vault_meta_blob = self
            .vault
            .decrypt(&current_private_key, vault_meta_aead)
            .await?;

        // Create new vault duplicated from the existing
        // vault header with zero secrets, this will inherit
        // the vault name, cipher etc.
        let new_header = self.vault.header().clone();
        let mut new_vault: Vault = new_header.into();

        // Initialize the new vault with the new passphrase
        // so that we create a new salt for the new passphrase.
        //
        // Must clear the existing salt so we can re-initialize.
        new_vault.header_mut().clear_salt();

        match &self.new_key {
            AccessKey::Password(password) => {
                new_vault.symmetric(password.clone(), self.seed).await?;
            }
            AccessKey::Identity(id) => {
                new_vault.asymmetric(id, vec![], true).await?;
            }
        }

        // Get a new secret key after we have initialized the new salt
        let new_private_key = self.new_private_key(&new_vault)?;

        // Encrypt the vault meta data using the new private key
        // and update the new vault header
        let vault_meta_aead = new_vault
            .encrypt(&new_private_key, &vault_meta_blob)
            .await?;
        new_vault.header_mut().set_meta(Some(vault_meta_aead));

        let mut event_log_events = Vec::new();

        let buffer = encode(&new_vault).await?;
        let create_vault = WriteEvent::CreateVault(buffer);
        event_log_events.push(create_vault);

        // Iterate the current vault and decrypt the secrets
        // inserting freshly encrypted content into the new vault
        for (id, VaultCommit(_, VaultEntry(meta_aead, secret_aead))) in
            self.vault.iter()
        {
            let meta_blob =
                self.vault.decrypt(&current_private_key, meta_aead).await?;
            let secret_blob = self
                .vault
                .decrypt(&current_private_key, secret_aead)
                .await?;

            let meta_aead =
                new_vault.encrypt(&new_private_key, &meta_blob).await?;
            let secret_aead =
                new_vault.encrypt(&new_private_key, &secret_blob).await?;

            // Need a new commit hash as the contents have changed
            let (commit, _) =
                Vault::commit_hash(&meta_aead, &secret_aead).await?;

            // Insert into the new vault preserving the secret identifiers
            let sync_event = new_vault
                .insert(*id, commit, VaultEntry(meta_aead, secret_aead))
                .await?;

            event_log_events.push(sync_event.into_owned());
        }

        event_log_events.sort();

        Ok((self.new_key, new_vault, event_log_events))
    }
}

#[cfg(test)]
mod test {
    use super::ChangePassword;
    use crate::{
        crypto::AccessKey,
        test_utils::*,
        vault::{Gatekeeper, VaultBuilder},
    };
    use anyhow::Result;

    #[tokio::test]
    async fn change_password() -> Result<()> {
        let (_, _, current_key) = mock_encryption_key()?;
        let mock_vault = VaultBuilder::new()
            .password(current_key.clone(), None)
            .await?;

        let mut keeper = Gatekeeper::new(mock_vault, None);
        keeper.unlock(current_key.clone().into()).await?;

        // Propagate some secrets
        let notes = vec![
            ("label1", "note1"),
            ("label2", "note2"),
            ("label3", "note3"),
        ];
        for item in notes {
            let (secret_meta, secret_value, _, _) =
                mock_secret_note(item.0, item.1).await?;
            keeper.create(secret_meta, secret_value).await?;
        }

        let expected_len = keeper.vault().len();
        assert_eq!(3, expected_len);

        let (_, _, new_key) = mock_encryption_key()?;

        let expected_passphrase = AccessKey::Password(new_key.clone());

        // Using an incorrect current passphrase should fail
        let bad_passphrase =
            AccessKey::Password(secrecy::Secret::new(String::from("oops")));
        assert!(ChangePassword::new(
            keeper.vault(),
            bad_passphrase,
            AccessKey::Password(new_key.clone()),
            None,
        )
        .build()
        .await
        .is_err());

        // Using a valid current passphrase should succeed
        let (new_key, new_vault, event_log_events) = ChangePassword::new(
            keeper.vault(),
            AccessKey::Password(current_key),
            AccessKey::Password(new_key),
            None,
        )
        .build()
        .await?;

        assert_eq!(expected_passphrase, new_key);
        assert_eq!(expected_len, new_vault.len());
        assert_eq!(expected_len + 1, event_log_events.len());

        Ok(())
    }
}
