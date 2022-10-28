//! Identity provides access to a login vault containing
//! a private signing key and master encryption passphrase
//! using known identifiers for the secrets.
//!
//! This enables user interfaces to protect both the signing
//! key and encryption passphrase using a single master
//! passphrase.

use secrecy::{SecretString, ExposeSecret, SecretVec};

use crate::{
    constants::{
        DEFAULT_LOGIN_VAULT_NAME, LOGIN_ENCRYPTION_PASSPHRASE_NAME,
        LOGIN_SIGNING_KEY_NAME,
    },
    diceware::generate_passphrase_words,
    gatekeeper::Gatekeeper,
    secret::{Secret, SecretMeta, SecretSigner},
    signer::{Signer, SingleParty},
    vault::Vault,
    Result,
};

/// Represents an identity.
pub struct Identity;

impl Identity {
    /// Create a new login vault with a master passphrase.
    ///
    /// Generates a new random single party signing key and
    /// stores it in the new vault along with an encryption
    /// passphrase to use for vaults accessed by this identity.
    pub fn new_login_vault(master_passphrase: SecretString)
        -> Result<(String, Vault)> {
        let (encryption_passphrase, _) = generate_passphrase_words(12)?;

        let mut vault: Vault = Default::default();
        vault.set_name(DEFAULT_LOGIN_VAULT_NAME.to_owned());
        vault.initialize(master_passphrase.expose_secret())?;

        let mut keeper = Gatekeeper::new(vault);
        keeper.unlock(master_passphrase.expose_secret())?;

        // Store the encryption passphrase
        let passphrase_secret =
            Secret::Note(
                SecretString::new(
                    encryption_passphrase.expose_secret().to_owned()));
        let passphrase_meta = SecretMeta::new(
            LOGIN_ENCRYPTION_PASSPHRASE_NAME.to_owned(),
            passphrase_secret.kind(),
        );
        keeper.create(passphrase_meta, passphrase_secret)?;

        // Store the signing key
        let signer = SingleParty::new_random();
        let address = signer.address()?.to_string();
        let secret_signer = SecretSigner::SinglePartyEcdsa(
            SecretVec::new(signer.to_bytes()));
        let signer_secret = Secret::Signer(secret_signer);
        let signer_meta = SecretMeta::new(
            LOGIN_SIGNING_KEY_NAME.to_owned(),
            signer_secret.kind(),
        );
        keeper.create(signer_meta, signer_secret)?;

        Ok((address, keeper.take()))
    }
}
