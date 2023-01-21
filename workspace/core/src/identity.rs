//! Identity provides access to a login vault containing
//! a private signing key and master encryption passphrase
//! using known identifiers for the secrets.
//!
//! This enables user interfaces to protect both the signing
//! key and encryption passphrase using a single master
//! passphrase.
use secrecy::{ExposeSecret, SecretString, SecretVec};

use parking_lot::RwLock;
use std::sync::Arc;

#[cfg(not(target_arch = "wasm32"))]
use std::path::Path;

use urn::Urn;

use crate::{
    constants::LOGIN_SIGNING_KEY_URN,
    decode,
    gatekeeper::Gatekeeper,
    search::SearchIndex,
    secret::{Secret, SecretMeta, SecretSigner},
    signer::{BoxedSigner, Signer, SingleParty},
    vault::{Vault, VaultAccess, VaultFlags},
    Error, Result,
};

#[cfg(not(target_arch = "wasm32"))]
use crate::VaultFileAccess;

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
        let private_key =
            SecretSigner::SinglePartyEcdsa(SecretVec::new(signer.to_bytes()));
        let signer_secret = Secret::Signer {
            private_key,
            user_data: Default::default(),
        };
        let urn: Urn = LOGIN_SIGNING_KEY_URN.parse()?;
        let mut signer_meta =
            SecretMeta::new(urn.as_str().to_owned(), signer_secret.kind());
        signer_meta.set_urn(Some(urn));
        keeper.create(signer_meta, signer_secret)?;

        Ok((address, keeper.take()))
    }

    /// Attempt to login using a file path.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn login_file<P: AsRef<Path>>(
        file: P,
        master_passphrase: SecretString,
        search_index: Option<Arc<RwLock<SearchIndex>>>,
    ) -> Result<(AuthenticatedUser, Gatekeeper)> {
        let mirror =
            Box::new(VaultFileAccess::new(file.as_ref().to_path_buf())?);
        let buffer = std::fs::read(file.as_ref())?;
        Identity::login_buffer(
            buffer,
            master_passphrase,
            search_index,
            Some(mirror),
        )
    }

    /// Attempt to login using a buffer.
    pub fn login_buffer<B: AsRef<[u8]>>(
        buffer: B,
        master_passphrase: SecretString,
        search_index: Option<Arc<RwLock<SearchIndex>>>,
        mirror: Option<Box<dyn VaultAccess + Send + Sync>>,
    ) -> Result<(AuthenticatedUser, Gatekeeper)> {
        let vault: Vault = decode(buffer.as_ref())?;

        if !vault.flags().contains(VaultFlags::IDENTITY) {
            return Err(Error::NotIdentityVault);
        }

        let mut keeper = if let Some(mirror) = mirror {
            Gatekeeper::new_mirror(vault, mirror, search_index)
        } else {
            Gatekeeper::new(vault, search_index)
        };

        keeper.unlock(master_passphrase.expose_secret())?;
        // Must create the index so we can find by name
        keeper.create_search_index()?;

        let index = keeper.index();
        let reader = index.read();

        let urn: Urn = LOGIN_SIGNING_KEY_URN.parse()?;

        let signing_doc = reader
            .find_by_urn(keeper.vault().id(), &urn)
            .ok_or(Error::NoIdentitySigner)?;

        let signing_data = keeper
            .read(signing_doc.id())?
            .ok_or(Error::NoIdentitySecret)?;

        let (_, signer_secret, _) = signing_data;

        let signer = if let Secret::Signer { private_key, .. } = signer_secret
        {
            Some(private_key.into_boxed_signer()?)
        } else {
            None
        };
        let signer = signer.ok_or(Error::IdentitySignerKind)?;

        Ok((AuthenticatedUser { signer }, keeper))
    }
}

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use secrecy::{ExposeSecret, SecretString};
    use tempfile::NamedTempFile;
    use urn::Urn;

    use super::Identity;

    use crate::{
        constants::LOGIN_SIGNING_KEY_URN,
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
        let _ =
            Identity::login_file(temp.path(), auth_master_passphrase, None)?;
        Ok(())
    }

    #[test]
    fn identity_not_identity_vault() -> Result<()> {
        let (master_passphrase, _) = generate_passphrase()?;

        let mut vault: Vault = Default::default();
        vault.initialize(master_passphrase.expose_secret())?;
        let buffer = encode(&vault)?;

        let result =
            Identity::login_buffer(buffer, master_passphrase, None, None);
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

        let result =
            Identity::login_buffer(buffer, master_passphrase, None, None);
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
        let signer_secret = Secret::Note {
            text: SecretString::new("Mock note".to_owned()),
            user_data: Default::default(),
        };

        let urn: Urn = LOGIN_SIGNING_KEY_URN.parse()?;
        let mut signer_meta =
            SecretMeta::new(urn.as_str().to_owned(), signer_secret.kind());
        signer_meta.set_urn(Some(urn));
        keeper.create(signer_meta, signer_secret)?;

        let vault = keeper.take();
        let buffer = encode(&vault)?;

        let result =
            Identity::login_buffer(buffer, master_passphrase, None, None);
        if let Err(Error::IdentitySignerKind) = result {
            Ok(())
        } else {
            panic!("expecting identity signer kind error");
        }
    }
}
