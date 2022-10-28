//! Identity provides access to a login vault containing
//! a private signing key and master encryption passphrase
//! using known identifiers for the secrets.
//!
//! This enables user interfaces to protect both the signing
//! key and encryption passphrase using a single master
//! passphrase.
use std::path::Path;

use secrecy::{ExposeSecret, SecretString, SecretVec};

use crate::{
    constants::{
        DEFAULT_LOGIN_VAULT_NAME, LOGIN_ENCRYPTION_PASSPHRASE_NAME,
        LOGIN_SIGNING_KEY_NAME,
    },
    decode,
    diceware::generate_passphrase_words,
    gatekeeper::Gatekeeper,
    secret::{Secret, SecretMeta, SecretSigner},
    signer::{BoxedSigner, Signer, SingleParty},
    vault::{Vault, VaultFlags},
    Error, Result,
};

/// User information once authentication to a login vault succeeds.
pub struct AuthenticatedUser {
    /// Private signing key for the identity.
    pub signer: BoxedSigner,
    /// Encryption passphrase for the user's vaults.
    pub encryption: SecretString,
}

/// Represents an identity.
pub struct Identity;

impl Identity {
    /// Create a new login vault with a master passphrase.
    ///
    /// Generates a new random single party signing key and
    /// stores it in the new vault along with an encryption
    /// passphrase to use for vaults accessed by this identity.
    pub fn new_login_vault(
        master_passphrase: SecretString,
    ) -> Result<(String, Vault)> {
        let (encryption_passphrase, _) = generate_passphrase_words(12)?;

        let mut vault: Vault = Default::default();
        vault.flags_mut().set(VaultFlags::LOGIN, true);
        vault.set_name(DEFAULT_LOGIN_VAULT_NAME.to_owned());
        vault.initialize(master_passphrase.expose_secret())?;

        let mut keeper = Gatekeeper::new(vault);
        keeper.unlock(master_passphrase.expose_secret())?;

        // Store the signing key
        let signer = SingleParty::new_random();
        let address = signer.address()?.to_string();
        let secret_signer =
            SecretSigner::SinglePartyEcdsa(SecretVec::new(signer.to_bytes()));
        let signer_secret = Secret::Signer(secret_signer);
        let signer_meta = SecretMeta::new(
            LOGIN_SIGNING_KEY_NAME.to_owned(),
            signer_secret.kind(),
        );
        keeper.create(signer_meta, signer_secret)?;

        // Store the encryption passphrase
        let passphrase_secret = Secret::Note(SecretString::new(
            encryption_passphrase.expose_secret().to_owned(),
        ));
        let passphrase_meta = SecretMeta::new(
            LOGIN_ENCRYPTION_PASSPHRASE_NAME.to_owned(),
            passphrase_secret.kind(),
        );
        keeper.create(passphrase_meta, passphrase_secret)?;

        Ok((address, keeper.take()))
    }

    /// Attempt to login using a file path
    pub fn login_file<P: AsRef<Path>>(
        file: P,
        master_passphrase: SecretString,
    ) -> Result<AuthenticatedUser> {
        let buffer = std::fs::read(file.as_ref())?;
        Identity::login_buffer(buffer, master_passphrase)
    }

    /// Attempt to login using a buffer.
    pub fn login_buffer<B: AsRef<[u8]>>(
        buffer: B,
        master_passphrase: SecretString,
    ) -> Result<AuthenticatedUser> {
        let vault: Vault = decode(buffer.as_ref())?;
        let mut keeper = Gatekeeper::new(vault);
        keeper.unlock(master_passphrase.expose_secret())?;
        // Must create the index so we can find by name
        keeper.create_index()?;

        let signing_doc = keeper
            .index()
            .find_by_label(LOGIN_SIGNING_KEY_NAME)
            .ok_or(Error::NoLoginSigner)?;
        let encryption_doc = keeper
            .index()
            .find_by_label(LOGIN_ENCRYPTION_PASSPHRASE_NAME)
            .ok_or(Error::NoLoginPassphrase)?;

        let signing_data =
            keeper.read(signing_doc.id())?.ok_or(Error::NoLoginSecret)?;
        let encryption_data = keeper
            .read(encryption_doc.id())?
            .ok_or(Error::NoLoginSecret)?;

        let (_, signer_secret, _) = signing_data;
        let (_, encryption_secret, _) = encryption_data;

        let signer = if let Secret::Signer(signer) = signer_secret {
            Some(signer.into_boxed_signer()?)
        } else {
            None
        };
        let signer = signer.ok_or(Error::LoginSignerKind)?;

        let encryption =
            if let Secret::Note(encryption_passphrase) = encryption_secret {
                Some(encryption_passphrase)
            } else {
                None
            };

        let encryption = encryption.ok_or(Error::LoginEncryptionKind)?;

        Ok(AuthenticatedUser { signer, encryption })
    }
}

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use secrecy::{ExposeSecret, SecretString};
    use tempfile::NamedTempFile;

    use super::Identity;

    use crate::{diceware::generate_passphrase, encode};

    #[test]
    fn identity_create_login() -> Result<()> {
        let (master_passphrase, _) = generate_passphrase()?;
        let auth_master_passphrase =
            SecretString::new(master_passphrase.expose_secret().to_owned());
        let (_address, vault) = Identity::new_login_vault(master_passphrase)?;
        let buffer = encode(&vault)?;
        let temp = NamedTempFile::new()?;
        std::fs::write(temp.path(), buffer)?;
        let _ = Identity::login_file(temp.path(), auth_master_passphrase)?;
        Ok(())
    }
}
