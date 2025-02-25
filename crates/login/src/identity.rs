//! Login identity folder management.
//!
//! Enables user interfaces to protect folder passwords
//! using a single primary password.
//!
//! Provides access to an identity folder containing
//! the delegated passwords used by an account to decrypt
//! the folders for the account.
use crate::{
    device::DeviceManager, DelegatedAccess, Error, IdentityFolder,
    PublicIdentity, Result,
};
use async_trait::async_trait;
use sos_backend::BackendTarget;
use sos_core::{
    crypto::AccessKey, AccountId, AuthenticationError, SecretId, VaultId,
};
use sos_vault::read_public_identity;
use std::{collections::HashMap, path::Path};
use urn::Urn;

#[cfg(feature = "files")]
use secrecy::SecretString;

/// Collection of folder access keys.
pub struct FolderKeys(pub HashMap<VaultId, AccessKey>);

impl FolderKeys {
    /// Find an access key by folder id.
    pub fn find(&self, id: &VaultId) -> Option<&AccessKey> {
        self.0
            .iter()
            .find_map(|(k, v)| if k == id { Some(v) } else { None })
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl DelegatedAccess for FolderKeys {
    type Error = Error;

    async fn find_folder_password(
        &self,
        folder_id: &VaultId,
    ) -> Result<Option<AccessKey>> {
        Ok(self.find(folder_id).cloned())
    }

    async fn remove_folder_password(
        &mut self,
        folder_id: &VaultId,
    ) -> Result<()> {
        self.0.remove(folder_id);
        Ok(())
    }

    async fn save_folder_password(
        &mut self,
        folder_id: &VaultId,
        key: AccessKey,
    ) -> Result<()> {
        self.0.insert(*folder_id, key);
        Ok(())
    }
}

/// Cache of mapping between secret URN
/// and secret identifiers so we can find identity
/// vault secrets quickly.
pub type UrnLookup = HashMap<(VaultId, Urn), SecretId>;

/// Identity manages access to an identity vault
/// and the private keys for a user.
pub struct Identity {
    target: BackendTarget,
    account: Option<PublicIdentity>,
    identity: Option<IdentityFolder>,
}

impl Identity {
    /// Read the public identity from an identity vault file.
    pub async fn read_public_identity(
        path: impl AsRef<Path>,
    ) -> Result<Option<PublicIdentity>> {
        Ok(read_public_identity(path).await?)
    }

    /// Create a new unauthenticated login identity.
    pub fn new(target: BackendTarget) -> Self {
        Self {
            target,
            identity: None,
            account: None,
        }
    }

    /// Device manager.
    pub fn devices(&self) -> Result<&DeviceManager> {
        Ok(self
            .identity
            .as_ref()
            .ok_or(AuthenticationError::NotAuthenticated)?
            .devices()?)
    }

    /// Account information.
    pub fn account(&self) -> Result<&PublicIdentity> {
        Ok(self
            .account
            .as_ref()
            .ok_or(AuthenticationError::NotAuthenticated)?)
    }

    fn account_mut(&mut self) -> Result<&mut PublicIdentity> {
        Ok(self
            .account
            .as_mut()
            .ok_or(AuthenticationError::NotAuthenticated)?)
    }

    /// Private identity.
    pub fn identity(&self) -> Result<&IdentityFolder> {
        Ok(self
            .identity
            .as_ref()
            .ok_or(AuthenticationError::NotAuthenticated)?)
    }

    #[doc(hidden)]
    pub fn identity_mut(&mut self) -> Result<&mut IdentityFolder> {
        Ok(self
            .identity
            .as_mut()
            .ok_or(AuthenticationError::NotAuthenticated)?)
    }

    /// Verify the access key for this account.
    pub async fn verify(&self, key: &AccessKey) -> bool {
        if let Some(identity) = &self.identity {
            identity.verify(key).await
        } else {
            false
        }
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

    /// Create the file encryption password.
    #[cfg(feature = "files")]
    pub async fn create_file_encryption_password(&mut self) -> Result<()> {
        self.identity_mut()?.create_file_encryption_password().await
    }

    /// Find the password used for symmetric file encryption (AGE).
    #[cfg(feature = "files")]
    pub async fn find_file_encryption_password(
        &self,
    ) -> Result<SecretString> {
        self.identity()?.find_file_encryption_password().await
    }

    /// Login to an identity folder.
    pub async fn login(
        &mut self,
        account_id: &AccountId,
        key: &AccessKey,
    ) -> Result<()> {
        let mut identity =
            IdentityFolder::login(&self.target, account_id, key).await?;
        identity
            .ensure_device_vault(&self.target, account_id)
            .await?;
        self.identity = Some(identity);
        Ok(())
    }

    /// Sign in to a user account.
    pub async fn sign_in(
        &mut self,
        account_id: &AccountId,
        key: &AccessKey,
    ) -> Result<()> {
        let accounts = self.target.list_accounts().await?;
        let account = accounts
            .into_iter()
            .find(|a| a.account_id() == account_id)
            .ok_or_else(|| Error::NoAccount(account_id.to_string()))?;

        tracing::debug!("identity::sign_in");
        self.login(account_id, key).await?;
        tracing::debug!("identity::verified");

        self.account = Some(account);
        Ok(())
    }

    /// Sign out this user by locking the account identity vault.
    pub async fn sign_out(&mut self) -> Result<()> {
        tracing::debug!("identity::sign_out");

        // Sign out the identity vault
        self.identity_mut()?.sign_out().await?;

        self.account = None;
        self.identity = None;
        Ok(())
    }
}

impl From<Identity> for BackendTarget {
    fn from(value: Identity) -> Self {
        value.target
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl DelegatedAccess for Identity {
    type Error = Error;

    async fn find_folder_password(
        &self,
        folder_id: &VaultId,
    ) -> Result<Option<AccessKey>> {
        self.identity()?.find_folder_password(folder_id).await
    }

    async fn remove_folder_password(
        &mut self,
        folder_id: &VaultId,
    ) -> Result<()> {
        self.identity_mut()?.remove_folder_password(folder_id).await
    }

    async fn save_folder_password(
        &mut self,
        folder_id: &VaultId,
        key: AccessKey,
    ) -> Result<()> {
        self.identity_mut()?
            .save_folder_password(folder_id, key)
            .await
    }
}
