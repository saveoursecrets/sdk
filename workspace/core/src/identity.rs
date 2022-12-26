//! Identity provides access to a login vault containing
//! a private signing key and master encryption passphrase
//! using known identifiers for the secrets.
//!
//! This enables user interfaces to protect both the signing
//! key and encryption passphrase using a single master
//! passphrase.
use secrecy::{ExposeSecret, SecretString, SecretVec};

#[cfg(not(target_arch = "wasm32"))]
use std::path::Path;

use crate::{
    constants::LOGIN_SIGNING_KEY_NAME,
    decode,
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
        name: String,
        master_passphrase: SecretString,
    ) -> Result<(String, Vault)> {
        let mut vault: Vault = Default::default();
        vault.flags_mut().set(VaultFlags::IDENTITY, true);
        vault.set_name(name);
        vault.initialize(master_passphrase.expose_secret())?;

        let mut keeper = Gatekeeper::new(vault, None);
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

        Ok((address, keeper.take()))
    }

    /// Attempt to login using a file path.
    #[cfg(not(target_arch = "wasm32"))]
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

        if !vault.flags().contains(VaultFlags::IDENTITY) {
            return Err(Error::NotIdentityVault);
        }

        let mut keeper = Gatekeeper::new(vault, None);
        keeper.unlock(master_passphrase.expose_secret())?;
        // Must create the index so we can find by name
        keeper.create_search_index()?;

        let index = keeper.index();
        let reader = index.read().unwrap();

        let signing_doc = reader
            .find_by_label(keeper.vault().id(), LOGIN_SIGNING_KEY_NAME)
            .ok_or(Error::NoIdentitySigner)?;
        let signing_data = keeper
            .read(signing_doc.id())?
            .ok_or(Error::NoIdentitySecret)?;

        let (_, signer_secret, _) = signing_data;

        let signer = if let Secret::Signer(signer) = signer_secret {
            Some(signer.into_boxed_signer()?)
        } else {
            None
        };
        let signer = signer.ok_or(Error::IdentitySignerKind)?;

        Ok(AuthenticatedUser { signer })
    }
}

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use secrecy::{ExposeSecret, SecretString};
    use tempfile::NamedTempFile;

    use super::Identity;

    use crate::{
        constants::LOGIN_SIGNING_KEY_NAME,
        diceware::generate_passphrase,
        encode,
        secret::{Secret, SecretMeta},
        vault::{Vault, VaultFlags},
        Error, Gatekeeper,
    };

    #[test]
    fn identity_create_login() -> Result<()> {
        let (master_passphrase, _) = generate_passphrase()?;
        let auth_master_passphrase =
            SecretString::new(master_passphrase.expose_secret().to_owned());
        let (_address, vault) =
            Identity::new_login_vault("Login".to_owned(), master_passphrase)?;
        let buffer = encode(&vault)?;
        let temp = NamedTempFile::new()?;
        std::fs::write(temp.path(), buffer)?;
        let _ = Identity::login_file(temp.path(), auth_master_passphrase)?;
        Ok(())
    }

    #[test]
    fn identity_not_identity_vault() -> Result<()> {
        let (master_passphrase, _) = generate_passphrase()?;

        let mut vault: Vault = Default::default();
        vault.initialize(master_passphrase.expose_secret())?;
        let buffer = encode(&vault)?;

        let result = Identity::login_buffer(buffer, master_passphrase);
        if let Err(Error::NotIdentityVault) = result {
            Ok(())
        } else {
            panic!("expecting identity vault error");
        }
    }

    #[test]
    fn identity_no_identity_signer() -> Result<()> {
        let (master_passphrase, _) = generate_passphrase()?;

        let mut vault: Vault = Default::default();
        vault.flags_mut().set(VaultFlags::IDENTITY, true);
        vault.initialize(master_passphrase.expose_secret())?;
        let buffer = encode(&vault)?;

        let result = Identity::login_buffer(buffer, master_passphrase);
        if let Err(Error::NoIdentitySigner) = result {
            Ok(())
        } else {
            panic!("expecting no identity signer error");
        }
    }

    #[test]
    fn identity_signer_kind() -> Result<()> {
        let (master_passphrase, _) = generate_passphrase()?;

        let mut vault: Vault = Default::default();
        vault.flags_mut().set(VaultFlags::IDENTITY, true);
        vault.initialize(master_passphrase.expose_secret())?;

        let mut keeper = Gatekeeper::new(vault, None);
        keeper.unlock(master_passphrase.expose_secret())?;

        // Create a secret using the expected name but of the wrong kind
        let signer_secret =
            Secret::Note(SecretString::new("Mock note".to_owned()));
        let signer_meta = SecretMeta::new(
            LOGIN_SIGNING_KEY_NAME.to_owned(),
            signer_secret.kind(),
        );
        keeper.create(signer_meta, signer_secret)?;

        let vault = keeper.take();
        let buffer = encode(&vault)?;

        let result = Identity::login_buffer(buffer, master_passphrase);
        if let Err(Error::IdentitySignerKind) = result {
            Ok(())
        } else {
            panic!("expecting identity signer kind error");
        }
    }
}
