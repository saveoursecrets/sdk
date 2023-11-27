//! Account manager provides utility functions for
//! creating and managing local accounts.
use std::sync::Arc;

use tokio::sync::RwLock;

use tracing::{span, Level};
use urn::Urn;
use web3_address::ethereum::Address;

use crate::{
    account::{
        password::DelegatedPassword, search::SearchIndex, AccountInfo,
        AccountsList, UserPaths,
    },
    constants::{DEVICE_KEY_URN, VAULT_EXT},
    crypto::AccessKey,
    encode,
    events::{AuditEvent, Event, EventKind},
    signer::{
        ed25519::{self, BoxedEd25519Signer, VerifyingKey},
        Signer,
    },
    vault::{
        secret::{Secret, SecretMeta, SecretSigner},
        Gatekeeper, Summary, Vault, VaultAccess, VaultBuilder, VaultFlags,
        VaultWriter,
    },
    vfs,
};

use secrecy::{ExposeSecret, SecretString};

use super::identity::{Identity, UserIdentity};

use crate::{Error, Result};

/// Encapsulate device specific information for an account.
#[derive(Clone)]
pub struct DeviceSigner {
    /// The vault containing device specific keys.
    summary: Summary,
    /// The signing key for this device.
    signer: BoxedEd25519Signer,
    /// The id of this device; Base58 encoded device public key.
    public_id: String,
}

impl DeviceSigner {
    /// Summary of the vault containing the device
    /// signing key.
    pub fn summary(&self) -> &Summary {
        &self.summary
    }

    /// Device signing key.
    pub fn signer(&self) -> &BoxedEd25519Signer {
        &self.signer
    }

    /// Identifier of the device public key.
    pub fn public_id(&self) -> &str {
        &self.public_id
    }

    /// Get the verifying key.
    pub fn verifying_key(&self) -> VerifyingKey {
        self.signer.verifying_key()
    }
}

/// Authenticated user, account and device information.
pub struct AuthenticatedUser {
    account: AccountInfo,
    identity: UserIdentity,
    device: DeviceSigner,
}

impl AuthenticatedUser {
    /// Account information.
    pub fn account(&self) -> &AccountInfo {
        &self.account
    }

    /// User identity reference.
    pub fn identity(&self) -> &UserIdentity {
        &self.identity
    }

    /// The device signing key.
    pub fn device(&self) -> &DeviceSigner {
        &self.device
    }

    /// Verify the passphrase for this account.
    pub async fn verify(&self, key: &AccessKey) -> bool {
        let keeper = self.identity().keeper();
        let reader = keeper.read().await;
        let result = reader.verify(key).await.ok();
        result.is_some()
    }

    /// Delete the account for this user.
    ///
    /// Moves the account identity vault and data directory to the
    /// trash directory.
    pub async fn delete_account(&self, paths: &UserPaths) -> Result<Event> {
        let address = self.identity.address().to_string();
        let identity_vault_file = paths.identity_vault();

        let local_dir = paths.local_dir();
        let identity_data_dir = local_dir.join(&address);

        let trash_dir = paths.trash_dir();
        let mut deleted_identity_vault_file = trash_dir.join(&address);
        deleted_identity_vault_file.set_extension(VAULT_EXT);

        let deleted_identity_data_dir = trash_dir.join(&address);

        // If the trash targets exist delete them first.
        //
        // This can only happen if somebody has manually restored
        // items from the trash using `cp` and then decides to delete
        // the accout again, so the rule is last deleted account wins.
        if vfs::try_exists(&deleted_identity_vault_file).await? {
            vfs::remove_file(&deleted_identity_vault_file).await?;
        }
        if vfs::try_exists(&deleted_identity_data_dir).await? {
            vfs::remove_dir_all(&deleted_identity_data_dir).await?;
        }

        vfs::rename(identity_vault_file, deleted_identity_vault_file).await?;

        // FIXME: We need a better solution (see #426)!
        //
        // FIXME: On windows if we try to rename the folder
        // FIXME: to move it to the trash then we get an
        // FIXME: "Access denied (os error 5)" error as Windows
        // FIXME: refuses to rename a folder that has an open file
        // FIXME: handle in it. The correct fix is to ensure all
        // FIXME: file handles have been closed.
        if cfg!(not(windows)) {
            vfs::rename(identity_data_dir, deleted_identity_data_dir).await?;
        }

        let event = Event::CreateAccount(AuditEvent::new(
            EventKind::DeleteAccount,
            self.identity.address().clone(),
            None,
        ));

        Ok(event)
    }

    /// Rename this account by changing the name of the identity vault.
    pub async fn rename_account(
        &mut self,
        paths: &UserPaths,
        account_name: String,
    ) -> Result<()> {
        // Update in-memory vault
        {
            let keeper = self.identity.keeper();
            let mut writer = keeper.write().await;
            writer.vault_mut().set_name(account_name.clone());
        }

        // Update vault file on disc
        let identity_vault_file = paths.identity_vault();

        let vault_file = VaultWriter::open(&identity_vault_file).await?;
        let mut access = VaultWriter::new(identity_vault_file, vault_file)?;
        access.set_vault_name(account_name.clone()).await?;

        // Update in-memory account information
        self.account.set_label(account_name);

        Ok(())
    }

    /// Sign out this user by locking the account identity vault.
    pub async fn sign_out(&mut self) {
        tracing::debug!("identity vault sign out");
        let keeper = self.identity.keeper();
        let mut writer = keeper.write().await;
        writer.lock();
    }
}

/// Login to an account.
#[derive(Default)]
pub struct Login;

impl Login {
    /// Sign in a user.
    pub async fn sign_in(
        address: &Address,
        paths: &UserPaths,
        passphrase: SecretString,
        index: Arc<RwLock<SearchIndex>>,
    ) -> Result<AuthenticatedUser> {
        let span = span!(Level::DEBUG, "login");
        let _enter = span.enter();

        let accounts = AccountsList::list_accounts(Some(paths)).await?;
        let account = accounts
            .into_iter()
            .find(|a| a.address() == address)
            .ok_or_else(|| Error::NoAccount(address.to_string()))?;

        let identity_path = paths.identity_vault();

        tracing::debug!(identity_path = ?identity_path);

        let mut identity =
            Identity::login_file(identity_path, passphrase, Some(index))
                .await?;

        tracing::debug!("identity verified");

        // Lazily create or retrieve a device specific signing key
        let device =
            Self::ensure_device_vault(address, paths, &mut identity).await?;

        Ok(AuthenticatedUser {
            account,
            identity,
            device,
        })
    }

    /// Ensure that the account has a vault for storing device specific
    /// information such as the private key used to identify a machine
    /// on a peer to peer network.
    async fn ensure_device_vault(
        _address: &Address,
        paths: &UserPaths,
        user: &mut UserIdentity,
    ) -> Result<DeviceSigner> {
        let local_accounts = AccountsList::new(paths);

        let vaults = local_accounts.list_local_vaults(true).await?;
        let device_vault = vaults.into_iter().find_map(|(summary, _)| {
            if summary.flags().is_system() && summary.flags().is_device() {
                Some(summary)
            } else {
                None
            }
        });

        let urn: Urn = DEVICE_KEY_URN.parse()?;

        if let Some(summary) = device_vault {
            let device_passphrase = DelegatedPassword::find_folder_password(
                user.keeper(),
                summary.id(),
            )
            .await?;

            let (vault, _) =
                local_accounts.find_local_vault(summary.id(), true).await?;
            let search_index = Arc::new(RwLock::new(SearchIndex::new()));
            let mut device_keeper =
                Gatekeeper::new(vault, Some(search_index));
            device_keeper.unlock(device_passphrase.into()).await?;
            device_keeper.create_search_index().await?;
            let index = device_keeper.index();
            let index_reader = index.read().await;
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
            )) = device_keeper.read(document.id()).await?
            {
                let key: ed25519::SingleParty =
                    data.expose_secret().as_slice().try_into()?;
                let public_id = key.address()?;
                Ok(DeviceSigner {
                    summary,
                    signer: Box::new(key),
                    public_id,
                })
            } else {
                Err(Error::VaultEntryKind(urn.to_string()))
            }
        } else {
            // Prepare the passphrase for the device vault
            let device_passphrase =
                DelegatedPassword::generate_folder_password()?;

            // Prepare the device vault
            let vault = VaultBuilder::new()
                .public_name("Device".to_string())
                .flags(
                    VaultFlags::SYSTEM
                        | VaultFlags::DEVICE
                        | VaultFlags::NO_SYNC_SELF
                        | VaultFlags::NO_SYNC_OTHER,
                )
                .password(device_passphrase.clone().into(), None)
                .await?;

            /*
            let mut vault: Vault = Default::default();
            vault.set_name("Device".to_string());
            vault.set_system_flag(true);
            vault.set_device_flag(true);
            vault.set_no_sync_self_flag(true);
            vault.set_no_sync_other_flag(true);
            vault.initialize(device_passphrase.clone(), None).await?;
            */

            DelegatedPassword::save_folder_password(
                user.keeper(),
                vault.id(),
                device_passphrase.clone().into(),
            )
            .await?;

            let mut device_keeper = Gatekeeper::new(vault, None);
            device_keeper.unlock(device_passphrase.into()).await?;

            let key = ed25519::SingleParty::new_random();
            let public_id = key.address()?;

            let secret = Secret::Signer {
                private_key: key.clone().into(),
                user_data: Default::default(),
            };
            let mut meta =
                SecretMeta::new("Device Key".to_string(), secret.kind());
            meta.set_urn(Some(urn));
            device_keeper.create(meta, secret).await?;

            let device_vault: Vault = device_keeper.into();
            let summary = device_vault.summary().clone();

            let buffer = encode(&device_vault).await?;
            let vaults_dir = paths.vaults_dir();
            let mut device_vault_file =
                vaults_dir.join(summary.id().to_string());
            device_vault_file.set_extension(VAULT_EXT);
            vfs::write(device_vault_file, buffer).await?;

            Ok(DeviceSigner {
                summary,
                signer: Box::new(key),
                public_id,
            })
        }
    }
}
