//! Login identity vault management.
//!
//! Provides access to an identity vault containing
//! the account signing key and delegated passwords used
//! for folders managed by an account.
//!
//! This enables user interfaces to protect both the signing
//! key and folder passwords using a single master password.
use crate::{
    crypto::AccessKey,
    events::{AuditEvent, Event, EventKind},
    identity::{IdentityVault, Login, PublicIdentity},
    signer::ecdsa::Address,
    vault::{secret::SecretId, Summary, Vault, VaultId},
    vfs, Error, Paths, Result,
};
use secrecy::SecretString;
use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::Arc,
};
use tracing::{span, Level};
use urn::Urn;

#[cfg(feature = "device")]
use crate::device::DeviceManager;

/// Collection of folder access keys.
pub struct FolderKeys(pub HashMap<Summary, AccessKey>);

impl FolderKeys {
    /// Find an access key by folder id.
    pub fn find(&self, id: &VaultId) -> Option<&AccessKey> {
        self.0
            .iter()
            .find_map(|(k, v)| if k.id() == id { Some(v) } else { None })
    }
}

/// Cache of mapping between secret URN
/// and secret identifiers to we can find identity
/// vault secrets quickly.
pub type UrnLookup = HashMap<(VaultId, Urn), SecretId>;

/// Identity manages access to an identity vault
/// and the private keys for a user.
pub struct Identity {
    paths: Arc<Paths>,
    account: Option<PublicIdentity>,
    identity: Option<IdentityVault>,
}

impl Identity {
    /// List account information for the identity vaults.
    pub async fn list_accounts(
        paths: Option<&Paths>,
    ) -> Result<Vec<PublicIdentity>> {
        PublicIdentity::list_accounts(paths).await
    }

    /// Find and load a vault.
    pub(crate) async fn load_local_vault(
        paths: &Paths,
        id: &VaultId,
    ) -> Result<(Vault, PathBuf)> {
        PublicIdentity::load_local_vault(paths, id).await
    }

    /// List the folders in an account by inspecting
    /// the vault files in the vaults directory.
    pub(crate) async fn list_local_folders(
        paths: &Paths,
    ) -> Result<Vec<(Summary, PathBuf)>> {
        PublicIdentity::list_local_folders(paths).await
    }

    /// Create a new unauthenticated user.
    pub fn new(paths: Paths) -> Self {
        Self {
            paths: Arc::new(paths),
            identity: None,
            account: None,
        }
    }

    /// Device manager.
    #[cfg(feature = "device")]
    pub fn devices(&self) -> Result<&DeviceManager> {
        self.identity
            .as_ref()
            .ok_or(Error::NotAuthenticated)?
            .devices()
    }

    /// Device manager.
    #[cfg(feature = "device")]
    pub fn devices_mut(&mut self) -> Result<&mut DeviceManager> {
        self.identity
            .as_mut()
            .ok_or(Error::NotAuthenticated)?
            .devices_mut()
    }

    /// Account information.
    pub fn account(&self) -> Result<&PublicIdentity> {
        self.account.as_ref().ok_or(Error::NotAuthenticated)
    }

    fn account_mut(&mut self) -> Result<&mut PublicIdentity> {
        self.account.as_mut().ok_or(Error::NotAuthenticated)
    }

    /// Private identity.
    pub fn identity(&self) -> Result<&IdentityVault> {
        self.identity.as_ref().ok_or(Error::NotAuthenticated)
    }

    fn identity_mut(&mut self) -> Result<&mut IdentityVault> {
        self.identity.as_mut().ok_or(Error::NotAuthenticated)
    }

    /// Verify the access key for this account.
    pub async fn verify(&self, key: &AccessKey) -> bool {
        if let Some(identity) = &self.identity {
            identity.verify(key).await
        } else {
            false
        }
    }

    /// Delete the account for this user.
    pub async fn delete_account(&self, paths: &Paths) -> Result<Event> {
        vfs::remove_file(paths.identity_vault()).await?;
        vfs::remove_dir_all(paths.user_dir()).await?;

        let event = Event::CreateAccount(AuditEvent::new(
            EventKind::DeleteAccount,
            self.identity()?.address().clone(),
            None,
        ));

        Ok(event)
    }

    /// Rename this account by changing the name of the identity vault.
    pub async fn rename_account(
        &mut self,
        account_name: String,
    ) -> Result<()> {
        // Update identity vault
        self.identity_mut()?.rename(account_name.clone()).await?;

        // Update in-memory account information
        self.account_mut()?.set_label(account_name);

        Ok(())
    }

    /// Generate a folder password.
    pub fn generate_folder_password(&self) -> Result<SecretString> {
        self.identity()?.generate_folder_password()
    }

    /// Save a folder password into an identity vault.
    pub async fn save_folder_password(
        &mut self,
        vault_id: &VaultId,
        key: AccessKey,
    ) -> Result<()> {
        self.identity_mut()?
            .save_folder_password(vault_id, key)
            .await?;

        Ok(())
    }

    /// Remove a folder password from an identity vault.
    pub async fn remove_folder_password(
        &mut self,
        vault_id: &VaultId,
    ) -> Result<()> {
        self.identity_mut()?
            .remove_folder_password(vault_id)
            .await?;

        Ok(())
    }

    /// Find a folder password in an identity vault.
    ///
    /// The identity vault must already be unlocked to extract
    /// the secret passphrase.
    pub async fn find_folder_password(
        &self,
        vault_id: &VaultId,
    ) -> Result<AccessKey> {
        self.identity()?.find_folder_password(vault_id).await
    }

    /// Create the file encryption password.
    pub(crate) async fn create_file_encryption_password(
        &mut self,
    ) -> Result<()> {
        self.identity_mut()?.create_file_encryption_password().await
    }

    /// Find the password used for symmetric file encryption (AGE).
    pub(crate) async fn find_file_encryption_password(
        &self,
    ) -> Result<SecretString> {
        self.identity()?.find_file_encryption_password().await
    }

    /// Login to an identity vault.
    pub async fn login<P: AsRef<Path>>(
        &mut self,
        file: P,
        key: &AccessKey,
    ) -> Result<()> {
        self.identity = Some(IdentityVault::login(file, key).await?);
        Ok(())
    }

    /// Login using a buffer.
    pub(crate) async fn login_buffer<B: AsRef<[u8]>>(
        &mut self,
        buffer: B,
        key: &AccessKey,
    ) -> Result<()> {
        self.identity = Some(
            IdentityVault::do_login(Login::Buffer(buffer.as_ref()), key)
                .await?,
        );
        Ok(())
    }

    /// Sign in to a user account.
    pub async fn sign_in(
        &mut self,
        address: &Address,
        key: &AccessKey,
    ) -> Result<()> {
        let span = span!(Level::DEBUG, "login");
        let _enter = span.enter();

        let accounts = Self::list_accounts(Some(&self.paths)).await?;
        let account = accounts
            .into_iter()
            .find(|a| a.address() == address)
            .ok_or_else(|| Error::NoAccount(address.to_string()))?;

        let identity_path = self.paths.identity_vault();

        tracing::debug!(identity_path = ?identity_path);

        self.login(identity_path, key).await?;

        tracing::debug!("identity verified");

        // Lazily create or retrieve a device specific signing key
        #[cfg(feature = "device")]
        {
            let identity = self.identity.as_mut().unwrap();
            identity.ensure_device_vault(&self.paths).await?;
        }

        self.account = Some(account);
        Ok(())
    }

    /// Sign out this user by locking the account identity vault.
    pub async fn sign_out(&mut self) -> Result<()> {
        tracing::debug!("identity vault sign out");

        // Sign out the identity vault
        self.identity_mut()?.sign_out().await?;

        self.account = None;
        self.identity = None;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use secrecy::SecretString;
    use urn::Urn;

    use crate::{
        constants::LOGIN_SIGNING_KEY_URN,
        crypto::AccessKey,
        encode,
        identity::Identity,
        passwd::diceware::generate_passphrase,
        vault::{
            secret::{Secret, SecretId, SecretMeta, SecretRow},
            Gatekeeper, Vault, VaultBuilder, VaultFlags,
        },
        Error, Paths,
    };

    #[tokio::test]
    async fn identity_not_identity_vault() -> Result<()> {
        let (password, _) = generate_passphrase()?;
        let vault =
            VaultBuilder::new().password(password.clone(), None).await?;
        let buffer = encode(&vault).await?;

        let mut identity =
            Identity::new(Paths::new_global(Paths::data_dir()?));
        let key: AccessKey = password.into();
        let result = identity.login_buffer(buffer, &key).await;
        if let Err(Error::NotIdentityVault) = result {
            Ok(())
        } else {
            panic!("expecting identity vault error");
        }
    }

    #[tokio::test]
    async fn no_signing_key() -> Result<()> {
        let (password, _) = generate_passphrase()?;

        let vault = VaultBuilder::new()
            .flags(VaultFlags::IDENTITY)
            .password(password.clone(), None)
            .await?;

        let buffer = encode(&vault).await?;

        let mut identity =
            Identity::new(Paths::new_global(Paths::data_dir()?));
        let key: AccessKey = password.into();
        let result = identity.login_buffer(buffer, &key).await;
        if let Err(Error::NoSigningKey) = result {
            Ok(())
        } else {
            panic!("expecting no identity signer error");
        }
    }

    #[tokio::test]
    async fn no_identity_key() -> Result<()> {
        let (password, _) = generate_passphrase()?;

        let vault = VaultBuilder::new()
            .flags(VaultFlags::IDENTITY)
            .password(password.clone(), None)
            .await?;

        let mut keeper = Gatekeeper::new(vault);
        let key = password.clone().into();
        keeper.unlock(&key).await?;

        // Create a secret using the expected name but of the wrong kind
        let signer_secret = Secret::Note {
            text: SecretString::new("Mock note".to_owned()),
            user_data: Default::default(),
        };

        let urn: Urn = LOGIN_SIGNING_KEY_URN.parse()?;
        let mut signer_meta =
            SecretMeta::new(urn.as_str().to_owned(), signer_secret.kind());
        signer_meta.set_urn(Some(urn));
        let secret_data =
            SecretRow::new(SecretId::new_v4(), signer_meta, signer_secret);
        keeper.create(&secret_data).await?;

        let vault: Vault = keeper.into();
        let buffer = encode(&vault).await?;

        let mut identity =
            Identity::new(Paths::new_global(Paths::data_dir()?));
        let key: AccessKey = password.into();
        let result = identity.login_buffer(buffer, &key).await;
        if let Err(Error::NoIdentityKey) = result {
            Ok(())
        } else {
            panic!("expecting identity signer kind error");
        }
    }
}
