//! Account manager provides utility functions for
//! creating and managing local accounts.
use std::sync::Arc;

use parking_lot::RwLock;

use urn::Urn;

use crate::{
    account::{AccountInfo, DelegatedPassphrase, LocalAccounts},
    constants::{DEVICE_KEY_URN, VAULT_EXT},
    encode,
    search::SearchIndex,
    sha2::Digest,
    signer::{
        ed25519::{self, BoxedEd25519Signer},
        Signer,
    },
    storage::StorageDirs,
    vault::{
        secret::{Secret, SecretMeta, SecretSigner},
        Gatekeeper, Summary, Vault, VaultAccess,
    },
    wal::WalProvider,
};

use secrecy::{ExposeSecret, SecretString};

use super::{AuthenticatedUser, Identity};

use crate::{Error, Result};

/// Encapsulate device specific information for an account.
#[derive(Clone)]
pub struct DeviceSigner {
    /// The vault containing device specific keys.
    pub summary: Summary,
    /// The signing key for this device.
    pub signer: BoxedEd25519Signer,
    /// The address of this device.
    pub address: String,
}

/// Login to an account.
#[derive(Default)]
pub struct Login {}

impl Login {
    /// Sign in a user.
    pub async fn sign_in(
        address: &str,
        passphrase: SecretString,
        index: Arc<RwLock<SearchIndex>>,
    ) -> Result<(AccountInfo, AuthenticatedUser, Gatekeeper, DeviceSigner)>
    {
        let accounts = LocalAccounts::list_accounts()?;
        let account = accounts
            .into_iter()
            .find(|a| a.address == address)
            .ok_or_else(|| Error::NoAccount(address.to_string()))?;

        let identity_path = StorageDirs::identity_vault(address)?;
        let (user, mut keeper) =
            Identity::login_file(identity_path, passphrase, Some(index))?;

        // Lazily create or retrieve a device specific signing key
        let device_info =
            Self::ensure_device_vault(address, &user, &mut keeper).await?;

        Ok((account, user, keeper, device_info))
    }

    /// Ensure that the account has a vault for storing device specific
    /// information such as the private key used to identify a machine
    /// on a peer to peer network.
    async fn ensure_device_vault(
        address: &str,
        _user: &AuthenticatedUser,
        identity: &mut Gatekeeper,
    ) -> Result<DeviceSigner> {
        let vaults = LocalAccounts::list_local_vaults(address, true)?;
        let device_vault = vaults.into_iter().find_map(|(summary, _)| {
            if summary.flags().is_system() && summary.flags().is_device() {
                Some(summary)
            } else {
                None
            }
        });

        let urn: Urn = DEVICE_KEY_URN.parse()?;

        if let Some(summary) = device_vault {
            let device_passphrase =
                DelegatedPassphrase::find_vault_passphrase(
                    identity,
                    summary.id(),
                )?;

            let (vault, _) =
                LocalAccounts::find_local_vault(address, summary.id(), true)?;
            let search_index = Arc::new(RwLock::new(SearchIndex::new(None)));
            let mut device_keeper =
                Gatekeeper::new(vault, Some(search_index));
            device_keeper.unlock(device_passphrase.expose_secret())?;
            device_keeper.create_search_index()?;
            let index = device_keeper.index();
            let index_reader = index.read();
            let document = index_reader
                .find_by_urn(summary.id(), &urn)
                .ok_or(Error::NoVaultEntry(urn.to_string()))?;

            if let Some((
                _,
                Secret::Signer {
                    private_key: SecretSigner::SinglePartyEd25519(data),
                    ..
                },
                _,
            )) = device_keeper.read(document.id())?
            {
                let key: ed25519::SingleParty =
                    data.expose_secret().as_slice().try_into()?;
                let address = key.address()?;
                Ok(DeviceSigner {
                    summary,
                    signer: Box::new(key),
                    address,
                })
            } else {
                Err(Error::VaultEntryKind(urn.to_string()))
            }
        } else {
            // Prepare the passphrase for the device vault
            let device_passphrase =
                DelegatedPassphrase::generate_vault_passphrase()?;

            // Prepare the device vault
            let mut vault: Vault = Default::default();
            vault.set_name("Device".to_string());
            vault.set_system_flag(true);
            vault.set_device_flag(true);
            vault.set_no_sync_self_flag(true);
            vault.set_no_sync_other_flag(true);
            vault.initialize(device_passphrase.expose_secret(), None)?;

            DelegatedPassphrase::save_vault_passphrase(
                identity,
                vault.id(),
                device_passphrase.clone(),
            )?;

            let mut device_keeper = Gatekeeper::new(vault, None);
            device_keeper.unlock(device_passphrase.expose_secret())?;

            let key = ed25519::SingleParty::new_random();
            let device_address = key.address()?;

            let secret = Secret::Signer {
                private_key: key.clone().into(),
                user_data: Default::default(),
            };
            let mut meta =
                SecretMeta::new("Device Key".to_string(), secret.kind());
            meta.set_urn(Some(urn));
            device_keeper.create(meta, secret)?;

            let device_vault: Vault = device_keeper.into();
            let summary = device_vault.summary().clone();

            let buffer = encode(&device_vault)?;
            let vaults_dir = StorageDirs::local_vaults_dir(address)?;
            let mut device_vault_file =
                vaults_dir.join(summary.id().to_string());
            device_vault_file.set_extension(VAULT_EXT);
            std::fs::write(device_vault_file, buffer)?;

            /*
            // Write out the modified device vault to disc
            let factory = ProviderFactory::Local;
            let (mut provider, _) =
                factory.create_provider(user.signer.clone())?;

            let device_vault: Vault = device_keeper.into();
            let buffer = encode(&device_vault)?;
            let summary = provider.import_vault(buffer).await?;
            */

            Ok(DeviceSigner {
                summary,
                signer: Box::new(key),
                address: device_address,
            })
        }
    }

    /// Verify the master passphrase for an account.
    pub fn verify(address: &str, passphrase: SecretString) -> Result<bool> {
        let identity_path = StorageDirs::identity_vault(address)?;
        let result = Identity::login_file(identity_path, passphrase, None);
        Ok(result.is_ok())
    }
}
