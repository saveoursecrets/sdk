//! Login identity vault.
//!
//! Identity provides access to a login vault containing
//! the account signing key and delegated passwords used
//! for folders managed by the account.
//!
//! This enables user interfaces to protect both the signing
//! key and encryption passphrase using a single master
//! passphrase.
use secrecy::{ExposeSecret, SecretString, SecretVec};

use parking_lot::RwLock;
use std::sync::Arc;

use std::path::Path;

use urn::Urn;
use web3_address::ethereum::Address;

use crate::{
    constants::{LOGIN_AGE_KEY_URN, LOGIN_SIGNING_KEY_URN},
    crypto::secret_key::generate_seed,
    decode,
    search::SearchIndex,
    signer::{
        ecdsa::{BoxedEcdsaSigner, SingleParty},
        Signer,
    },
    vault::{
        secret::{Secret, SecretMeta, SecretSigner},
        Gatekeeper, Vault, VaultAccess, VaultFlags,
    },
    vfs, Error, Result,
};

use crate::vault::VaultFileAccess;

/// User identity containing the account signing keys.
///
/// Exposes access to the identity vault for access to
/// delegated passwords.
pub struct UserIdentity {
    /// Address of the signing key.
    address: Address,
    /// Private signing key for the identity.
    signer: BoxedEcdsaSigner,
    /// Gatekeeper for the identity vault.
    keeper: Gatekeeper,
    /// AGE identity keypair.
    #[allow(dead_code)]
    shared_private: age::x25519::Identity,
    /// AGE recipient public key.
    shared_public: age::x25519::Recipient,
}

impl UserIdentity {
    /// Address of the signing key.
    pub fn address(&self) -> &Address {
        &self.address
    }

    /// Signing key for this user.
    pub fn signer(&self) -> &BoxedEcdsaSigner {
        &self.signer
    }

    /// Reference to the gatekeeper for the identity vault.
    pub fn keeper(&self) -> &Gatekeeper {
        &self.keeper
    }

    /// Mutable reference to the gatekeeper for the identity vault.
    pub fn keeper_mut(&mut self) -> &mut Gatekeeper {
        &mut self.keeper
    }

    /// Recipient public key for sharing.
    pub fn recipient(&self) -> &age::x25519::Recipient {
        &self.shared_public
    }
}

/// Provides access to the login vault used for account authentication.
///
/// A login vault is the master vault for an account. It stores the
/// signing keys for the account and delegated passphrases for folders
/// managed by the account.
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
    ) -> Result<(Address, Vault)> {
        let mut vault: Vault = Default::default();
        vault.flags_mut().set(VaultFlags::IDENTITY, true);
        vault.set_name(name);
        vault.initialize(master_passphrase.clone(), Some(generate_seed()))?;

        let mut keeper = Gatekeeper::new(vault, None);
        keeper.unlock(master_passphrase)?;

        // Store the signing key
        let signer = SingleParty::new_random();
        let address = signer.address()?;
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

        // Store the AGE identity
        let age_secret = Secret::Age {
            version: Default::default(),
            key: age::x25519::Identity::generate().to_string(),
            user_data: Default::default(),
        };
        let urn: Urn = LOGIN_AGE_KEY_URN.parse()?;
        let mut age_meta =
            SecretMeta::new(urn.as_str().to_owned(), age_secret.kind());
        age_meta.set_urn(Some(urn));
        keeper.create(age_meta, age_secret)?;

        Ok((address, keeper.into()))
    }

    /// Attempt to login using a file path.
    pub async fn login_file<P: AsRef<Path>>(
        file: P,
        master_passphrase: SecretString,
        search_index: Option<Arc<RwLock<SearchIndex>>>,
    ) -> Result<UserIdentity> {
        let mirror = Box::new(VaultFileAccess::new(file.as_ref())?);
        let buffer = vfs::read(file.as_ref()).await?;
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
    ) -> Result<UserIdentity> {
        let vault: Vault = decode(buffer.as_ref())?;

        if !vault.flags().contains(VaultFlags::IDENTITY) {
            return Err(Error::NotIdentityVault);
        }

        let mut keeper = if let Some(mirror) = mirror {
            Gatekeeper::new_mirror(vault, mirror, search_index)
        } else {
            Gatekeeper::new(vault, search_index)
        };

        keeper.unlock(master_passphrase)?;
        // Must create the index so we can find by URN
        keeper.create_search_index()?;

        let index = keeper.index();
        let reader = index.read();

        let urn: Urn = LOGIN_SIGNING_KEY_URN.parse()?;
        let document = reader
            .find_by_urn(keeper.id(), &urn)
            .ok_or(Error::NoSecretUrn(*keeper.id(), urn))?;
        let data = keeper
            .read(document.id())?
            .ok_or(Error::NoSecretId(*keeper.id(), *document.id()))?;

        let (_, secret, _) = data;

        let signer = if let Secret::Signer { private_key, .. } = secret {
            Some(private_key.try_into_ecdsa_signer()?)
        } else {
            None
        };
        let signer = signer
            .ok_or(Error::WrongSecretKind(*keeper.id(), *document.id()))?;
        let address = signer.address()?;

        let urn: Urn = LOGIN_AGE_KEY_URN.parse()?;
        let document = reader
            .find_by_urn(keeper.id(), &urn)
            .ok_or(Error::NoSecretUrn(*keeper.id(), urn))?;
        let data = keeper
            .read(document.id())?
            .ok_or(Error::NoSecretId(*keeper.id(), *document.id()))?;

        let (_, secret, _) = data;

        let identity = if let Secret::Age { key, .. } = secret {
            let identity: age::x25519::Identity =
                key.expose_secret().parse().map_err(|s: &'static str| {
                    Error::AgeIdentityParse(s.to_string())
                })?;
            Some(identity)
        } else {
            None
        };
        let shared = identity
            .ok_or(Error::WrongSecretKind(*keeper.id(), *document.id()))?;
        Ok(UserIdentity {
            address,
            signer,
            shared_public: shared.to_public(),
            shared_private: shared,
            keeper,
        })
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
        encode,
        passwd::diceware::generate_passphrase,
        vault::{
            secret::{Secret, SecretMeta},
            Gatekeeper, Vault, VaultFlags,
        },
        Error,
    };

    #[tokio::test]
    async fn identity_create_login() -> Result<()> {
        let (master_passphrase, _) = generate_passphrase()?;
        let auth_master_passphrase =
            SecretString::new(master_passphrase.expose_secret().to_owned());
        let (_address, vault) =
            Identity::new_login_vault("Login".to_owned(), master_passphrase)?;
        let buffer = encode(&vault)?;
        let temp = NamedTempFile::new()?;
        std::fs::write(temp.path(), buffer)?;
        let _ =
            Identity::login_file(temp.path(), auth_master_passphrase, None)
                .await?;
        Ok(())
    }

    #[test]
    fn identity_not_identity_vault() -> Result<()> {
        let (master_passphrase, _) = generate_passphrase()?;

        let mut vault: Vault = Default::default();
        vault.initialize(master_passphrase.clone(), None)?;
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
        vault.initialize(master_passphrase.clone(), None)?;
        let buffer = encode(&vault)?;

        let result =
            Identity::login_buffer(buffer, master_passphrase, None, None);
        if let Err(Error::NoSecretUrn(_, _)) = result {
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
        vault.initialize(master_passphrase.clone(), None)?;

        let mut keeper = Gatekeeper::new(vault, None);
        keeper.unlock(master_passphrase.clone())?;

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

        let vault: Vault = keeper.into();
        let buffer = encode(&vault)?;

        let result =
            Identity::login_buffer(buffer, master_passphrase, None, None);
        if let Err(Error::WrongSecretKind(_, _)) = result {
            Ok(())
        } else {
            panic!("expecting identity signer kind error");
        }
    }
}
