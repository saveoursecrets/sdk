//! Account storage and search index.
use std::{
    borrow::Cow,
    collections::HashMap,
    path::{Path, PathBuf},
    sync::Arc,
};

use crate::{
    account::{AccountBuilder, PrivateNewAccount, PublicNewAccount},
    commit::{CommitHash, CommitState},
    crypto::AccessKey,
    decode, encode,
    events::{
        AccountEvent, AccountEventLog, AuditData, AuditEvent, Event,
        EventKind, EventReducer, ReadEvent, WriteEvent,
    },
    identity::{FolderKeys, Identity, PublicIdentity},
    signer::ecdsa::Address,
    storage::{
        search::{DocumentCount, SearchIndex},
        AccessOptions, Storage,
    },
    vault::{
        secret::{Secret, SecretId, SecretMeta, SecretRow, SecretType},
        Gatekeeper, Summary, Vault, VaultId,
    },
    vfs, Error, Paths, Result, Timestamp,
};

use tracing::{span, Level};

use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

use async_trait::async_trait;

/// Type alias for a local account without a handler.
pub type LocalAccount = Account<()>;

/// Account handler is notified of account changes.
#[async_trait]
pub trait AccountHandler {
    /// Data associated with this handler.
    type Data;

    /// Called before changes to the account.
    async fn before_change(
        &self,
        storage: Arc<RwLock<Storage>>,
        folder: &Summary,
        commit_state: &CommitState,
    ) -> Option<CommitState>;
}

type Handler<D> = Box<dyn AccountHandler<Data = D> + Send + Sync>;

/// Read-only view created from a specific event log commit.
pub struct DetachedView {
    keeper: Gatekeeper,
    index: Arc<RwLock<SearchIndex>>,
}

impl DetachedView {
    /// Read-only access to the folder.
    pub fn keeper(&self) -> &Gatekeeper {
        &self.keeper
    }

    /// Search index for the detached view.
    pub fn index(&self) -> Arc<RwLock<SearchIndex>> {
        Arc::clone(&self.index)
    }
}

/// Data about an account.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountData {
    /// Main account information.
    #[serde(flatten)]
    pub account: PublicIdentity,
    /// AGE identity public recipient.
    pub identity: String,
    /// Account folders.
    pub folders: Vec<Summary>,
    /*
    #[cfg(feature = "device")]
    /// Address of the device public key.
    pub device_address: String,
    */
}

/// Account information when signed in.
pub(super) struct Authenticated {
    /// Authenticated user.
    pub(super) user: Identity,

    /// Storage provider.
    storage: Arc<RwLock<Storage>>,
}

/// User account backed by the filesystem.
///
/// Many functions require that the account is authenticated and will
/// return [Error::NotAuthenticated] if the account is not authenticated
/// to authenticate a user call [Account::sign_in].
///
/// For functions that return a [CommitState] it represents
/// the state *before* any changes were made. If a `handler`
/// has been assigned the `handler` may alter the [CommitState]
/// by returning a new state after changes from a remote server have
/// been applied.
pub struct Account<D> {
    /// Account address.
    address: Address,

    /// Account information after a successful
    /// sign in.
    pub(super) authenticated: Option<Authenticated>,

    /// Storage paths.
    pub(super) paths: Arc<Paths>,

    /// Hook called before making local changes.
    ///
    /// Allows network aware accounts to sync
    /// before changes are applied to the local
    /// storage.
    handler: Option<Handler<D>>,
}

impl<D> Account<D> {
    /// Prepare an account for sign in.
    ///
    /// After preparing an account call `sign_in`
    /// to authenticate a user.
    pub async fn new_unauthenticated(
        address: Address,
        data_dir: Option<PathBuf>,
        handler: Option<Handler<D>>,
    ) -> Result<Self> {
        let data_dir = if let Some(data_dir) = data_dir {
            data_dir
        } else {
            Paths::data_dir()?
        };

        let paths = Paths::new_global(data_dir);

        Ok(Self {
            address,
            paths: Arc::new(paths),
            authenticated: None,
            handler,
        })
    }

    /// Create a new account with the given
    /// name, passphrase and provider.
    ///
    /// Uses standard flags for the account builder for
    /// more control of the created account use
    /// `new_account_with_builder()`.
    pub async fn new_account(
        account_name: String,
        passphrase: SecretString,
        data_dir: Option<PathBuf>,
        handler: Option<Handler<D>>,
    ) -> Result<(Self, PrivateNewAccount)> {
        Self::new_account_with_builder(
            account_name,
            passphrase,
            |builder| builder.create_file_password(true),
            data_dir,
            handler,
        )
        .await
    }

    /// Create a new account with the given
    /// name, passphrase and provider and modify the
    /// account builder.
    pub async fn new_account_with_builder(
        account_name: String,
        passphrase: SecretString,
        builder: impl Fn(AccountBuilder) -> AccountBuilder,
        data_dir: Option<PathBuf>,
        handler: Option<Handler<D>>,
    ) -> Result<(Self, PrivateNewAccount)> {
        let span = span!(Level::DEBUG, "new_account");
        let _enter = span.enter();

        let account_builder = builder(AccountBuilder::new(
            account_name,
            passphrase.clone(),
            data_dir.clone(),
        ));
        let new_account = account_builder.finish().await?;

        tracing::debug!(address = %new_account.address, "created account");

        // Must import the new account before signing in
        let address = new_account.address().clone();

        let mut storage =
            Storage::new_client(address.clone(), data_dir.clone()).await?;

        tracing::debug!("prepared storage provider");
        
        let public_account: PublicNewAccount = (&new_account).into();
        storage.create_account(public_account).await?;

        tracing::debug!("imported new account");
        
        let owner = Self {
            address,
            paths: storage.paths(),
            authenticated: None,
            handler,
        };

        Ok((owner, new_account))
    }

    /// Authenticated user information.
    pub fn user(&self) -> Result<&Identity> {
        self.authenticated
            .as_ref()
            .map(|a| &a.user)
            .ok_or(Error::NotAuthenticated)
    }

    /// Mutable authenticated user information.
    pub fn user_mut(&mut self) -> Result<&mut Identity> {
        self.authenticated
            .as_mut()
            .map(|a| &mut a.user)
            .ok_or(Error::NotAuthenticated)
    }

    /// Storage provider.
    pub fn storage(&self) -> Result<Arc<RwLock<Storage>>> {
        let auth =
            self.authenticated.as_ref().ok_or(Error::NotAuthenticated)?;
        Ok(Arc::clone(&auth.storage))
    }

    /// Account address.
    pub fn address(&self) -> &Address {
        &self.address
    }

    /// Get access to an account by signing in.
    pub async fn sign_in(&mut self, key: &AccessKey) -> Result<Vec<Summary>> {
        let span = span!(Level::DEBUG, "sign_in");
        let _enter = span.enter();

        let address = &self.address;
        let data_dir = self.paths().documents_dir().clone();

        tracing::debug!(address = %address);

        // Ensure all paths before sign_in
        let paths = Paths::new(&data_dir, address.to_string());
        paths.ensure().await?;

        tracing::debug!(data_dir = ?paths.documents_dir());

        let mut user = Identity::new(paths.clone());
        user.sign_in(self.address(), key).await?;
        tracing::debug!("sign in success");

        // Signing key for the storage provider
        let signer = user.identity()?.signer().clone();

        let mut storage =
            Storage::new_client(signer.address()?, Some(data_dir)).await?;
        self.paths = storage.paths();

        let file_password = user.find_file_encryption_password().await?;
        storage.set_file_password(Some(file_password));

        Self::initialize_account_log(&*self.paths, storage.account_log())
            .await?;

        self.authenticated = Some(Authenticated {
            user,
            storage: Arc::new(RwLock::new(storage)),
        });

        // Load vaults into memory and initialize folder
        // event log commit trees
        Ok(self.load_folders().await?)
    }

    async fn initialize_account_log(
        paths: &Paths,
        account_log: Arc<RwLock<AccountEventLog>>,
    ) -> Result<()> {
        let span = span!(Level::DEBUG, "init_account_log");
        let _enter = span.enter();

        let mut event_log = account_log.write().await;
        let needs_init = event_log.tree().root().is_none();

        tracing::debug!(needs_init = %needs_init);

        // If the account event log does not already exist
        // we initialize it from the current state on disc
        // adding create folder events for every folder that
        // already exists
        if needs_init {
            let folders: Vec<Summary> = Identity::list_local_folders(paths)
                .await?
                .into_iter()
                .map(|(s, _)| s)
                .collect();

            let mut events = Vec::new();

            for folder in folders {
                events.push(AccountEvent::CreateFolder(folder.into()));
            }

            tracing::debug!(init_events_len = %events.len());

            event_log.apply(events.iter().collect()).await?;
        }

        Ok(())
    }

    /// Determine if the account is authenticated.
    pub fn is_authenticated(&self) -> bool {
        self.authenticated.is_some()
    }

    /// User storage paths.
    pub fn paths(&self) -> &Paths {
        &self.paths
    }

    /// Load the buffer of the encrypted vault for this account.
    ///
    /// Used when a client needs to authenticate other devices;
    /// it sends the encrypted identity vault and if the vault
    /// can be unlocked then we have verified that the other
    /// device knows the master password for this account.
    pub async fn identity_vault_buffer(&self) -> Result<Vec<u8>> {
        let storage = self.storage()?;
        let reader = storage.read().await;
        let identity_path = reader.paths().identity_vault();
        Ok(vfs::read(identity_path).await?)
    }

    /// Account data.
    pub async fn account_data(&self) -> Result<AccountData> {
        let storage = self.storage()?;
        let reader = storage.read().await;
        let user = self.user()?;
        Ok(AccountData {
            account: user.account()?.clone(),
            identity: user
                .identity()?
                .private_identity()
                .recipient()
                .to_string(),
            folders: reader.folders().to_vec(),
        })
    }

    /// Verify an access key for this account.
    ///
    /// If the account is not authenticated this returns false.
    pub async fn verify(&self, key: &AccessKey) -> bool {
        if let Some(auth) = &self.authenticated {
            auth.user.verify(key).await
        } else {
            false
        }
    }

    /// Delete the account for this user and sign out.
    pub async fn delete_account(&mut self) -> Result<()> {
        let span = span!(Level::DEBUG, "delete_account");
        let _enter = span.enter();

        let paths = self.paths().clone();
        let event = self.user_mut()?.delete_account(&paths).await?;
        let audit_event: AuditEvent = (self.address(), &event).into();
        self.paths.append_audit_events(vec![audit_event]).await?;
        self.sign_out().await?;
        Ok(())
    }

    /// Rename this account.
    pub async fn rename_account(
        &mut self,
        account_name: String,
    ) -> Result<()> {
        Ok(self.user_mut()?.rename_account(account_name).await?)
    }

    /// Try to find a folder using a predicate.
    pub async fn find<P>(&self, predicate: P) -> Option<Summary>
    where
        P: FnMut(&&Summary) -> bool,
    {
        if let Some(auth) = &self.authenticated {
            let reader = auth.storage.read().await;
            reader.find(predicate).cloned()
        } else {
            None
        }
    }

    /// Find the default folder.
    pub async fn default_folder(&self) -> Option<Summary> {
        self.find(|s| s.flags().is_default()).await
    }

    /// Find the authenticator folder.
    pub async fn authenticator_folder(&self) -> Option<Summary> {
        self.find(|s| s.flags().is_authenticator()).await
    }

    /// Find the contacts folder.
    pub async fn contacts_folder(&self) -> Option<Summary> {
        self.find(|s| s.flags().is_contact()).await
    }

    /// Find the archive folder.
    pub async fn archive_folder(&self) -> Option<Summary> {
        self.find(|s| s.flags().is_archive()).await
    }

    /// Load folders into memory.
    ///
    /// This method is automatically called on sign in to
    /// prepare the in-memory vaults but can be explicitly
    /// called to reload the data from disc.
    pub async fn load_folders(&mut self) -> Result<Vec<Summary>> {
        tracing::debug!("load folders");
        let storage = self.storage()?;
        let mut writer = storage.write().await;
        Ok(writer.load_vaults().await?.to_vec())
    }

    /// List in-memory folders managed by this account.
    pub async fn list_folders(&self) -> Result<Vec<Summary>> {
        let storage = self.storage()?;
        let reader = storage.read().await;
        Ok(reader.folders().to_vec())
    }

    /// Sign out of the account.
    pub async fn sign_out(&mut self) -> Result<()> {
        let span = span!(Level::DEBUG, "sign_out");
        let _enter = span.enter();

        tracing::debug!(address = %self.address());

        tracing::debug!("close current open vault");
        // Close the currently open vaul in the local storage
        let storage = self.storage()?;
        let mut writer = storage.write().await;
        writer.close_vault();

        tracing::debug!("clear search index");
        // Remove the search index
        writer.index_mut()?.clear().await;

        tracing::debug!("sign out user identity");
        // Forget private identity information
        self.user_mut()?.sign_out().await?;

        tracing::debug!("remove authenticated state");
        self.authenticated = None;

        Ok(())
    }

    /// Create a folder.
    pub async fn create_folder(
        &mut self,
        name: String,
    ) -> Result<(Summary, Event, CommitState)> {
        self.authenticated.as_ref().ok_or(Error::NotAuthenticated)?;

        let passphrase = self.user()?.generate_folder_password()?;
        let key: AccessKey = passphrase.into();

        let (buffer, _, summary, account_event) = {
            let storage = self.storage()?;
            let mut writer = storage.write().await;
            writer.create_folder(name, Some(key.clone())).await?
        };

        // Must save the password before getting the secure access key
        self.user_mut()?
            .save_folder_password(summary.id(), key)
            .await?;

        let options = AccessOptions {
            folder: Some(summary),
            ..Default::default()
        };

        let (summary, commit_state) =
            self.compute_folder_state(&options, false).await?;

        let event =
            Event::Folder(account_event, WriteEvent::CreateVault(buffer));
        Ok((summary, event, commit_state))
    }

    /// Delete a folder.
    pub async fn delete_folder(
        &mut self,
        summary: &Summary,
    ) -> Result<(Vec<Event>, CommitState)> {
        let options = AccessOptions {
            folder: Some(summary.clone()),
            ..Default::default()
        };
        let (summary, commit_state) =
            self.compute_folder_state(&options, false).await?;

        let events = {
            let storage = self.storage()?;
            let mut writer = storage.write().await;
            writer.delete_folder(&summary).await?
        };
        self.user_mut()?
            .remove_folder_password(summary.id())
            .await?;

        Ok((events, commit_state))
    }

    /// Rename a folder.
    pub async fn rename_folder(
        &mut self,
        summary: &Summary,
        name: String,
    ) -> Result<(Event, CommitState)> {
        let options = AccessOptions {
            folder: Some(summary.clone()),
            ..Default::default()
        };
        let (summary, commit_state) =
            self.compute_folder_state(&options, false).await?;

        // Update the provider
        let event = {
            let storage = self.storage()?;
            let mut writer = storage.write().await;
            writer.rename_folder(&summary, &name).await?
        };

        Ok((event, commit_state))
    }

    /// Get the description of a folder.
    ///
    /// The target folder will become the currently open folder.
    pub async fn folder_description(
        &mut self,
        folder: &Summary,
    ) -> Result<String> {
        self.authenticated.as_ref().ok_or(Error::NotAuthenticated)?;
        self.open_folder(folder).await?;
        let storage = self.storage()?;
        let reader = storage.read().await;
        Ok(reader.description().await?)
    }

    /// Set the description of a folder.
    ///
    /// The target folder will become the currently open folder.
    pub async fn set_folder_description(
        &mut self,
        folder: &Summary,
        description: impl AsRef<str>,
    ) -> Result<WriteEvent> {
        self.authenticated.as_ref().ok_or(Error::NotAuthenticated)?;
        self.open_folder(folder).await?;
        let event = {
            let storage = self.storage()?;
            let mut writer = storage.write().await;
            writer.set_description(description).await?
        };
        Ok(event)
    }

    /// Export a folder as a vault file.
    pub async fn export_folder<P: AsRef<Path>>(
        &mut self,
        path: P,
        summary: &Summary,
        new_key: AccessKey,
        save_key: bool,
    ) -> Result<()> {
        let buffer = self
            .export_folder_buffer(summary, new_key, save_key)
            .await?;
        vfs::write(path, buffer).await?;
        Ok(())
    }

    /// Export a folder to a buffer.
    pub async fn export_folder_buffer(
        &mut self,
        summary: &Summary,
        new_key: AccessKey,
        save_key: bool,
    ) -> Result<Vec<u8>> {
        self.authenticated.as_ref().ok_or(Error::NotAuthenticated)?;

        let buffer = self
            .change_vault_password(summary.id(), new_key.clone())
            .await?;

        if save_key {
            let default_summary = self
                .default_folder()
                .await
                .ok_or_else(|| Error::NoDefaultFolder)?;

            let _passphrase = self
                .user()?
                .find_folder_password(default_summary.id())
                .await?;

            let timestamp: Timestamp = Default::default();
            let label = format!(
                "Exported folder {}.vault ({})",
                summary.id(),
                timestamp.to_rfc3339()?
            );
            let secret = Secret::Account {
                account: format!("{}.vault", summary.id()),
                url: None,
                password: new_key.into(),
                user_data: Default::default(),
            };
            let meta = SecretMeta::new(label, secret.kind());

            let (vault, _) =
                Identity::load_local_vault(&self.paths, default_summary.id())
                    .await?;

            self.add_secret(
                meta,
                secret,
                vault.summary().clone().into(),
                false,
            )
            .await?;
        }

        let audit_event = AuditEvent::new(
            EventKind::ExportVault,
            self.address().clone(),
            Some(AuditData::Vault(*summary.id())),
        );
        self.paths.append_audit_events(vec![audit_event]).await?;

        Ok(buffer)
    }

    /// Export a vault by changing the vault passphrase and
    /// converting it to a buffer.
    ///
    /// The identity vault must be unlocked so we can retrieve
    /// the passphrase for the target vault.
    async fn change_vault_password(
        &self,
        vault_id: &VaultId,
        new_key: AccessKey,
    ) -> Result<Vec<u8>> {
        use crate::passwd::ChangePassword;
        let paths = self.paths().clone();
        // Get the current vault passphrase from the identity vault
        let current_key = self.user()?.find_folder_password(vault_id).await?;

        // Find the local vault for the account
        let (vault, _) = Identity::load_local_vault(&paths, vault_id).await?;

        // Change the password before exporting
        let (_, vault, _) =
            ChangePassword::new(&vault, current_key, new_key, None)
                .build()
                .await?;

        encode(&vault).await
    }

    /// Import a folder from a vault file.
    pub async fn import_folder<P: AsRef<Path>>(
        &mut self,
        path: P,
        key: AccessKey,
        overwrite: bool,
    ) -> Result<(Summary, Event, CommitState)> {
        self.authenticated.as_ref().ok_or(Error::NotAuthenticated)?;

        let buffer = vfs::read(path.as_ref()).await?;
        self.import_folder_buffer(&buffer, key, overwrite).await
    }

    /// Import a folder from a vault buffer.
    pub async fn import_folder_buffer(
        &mut self,
        buffer: impl AsRef<[u8]>,
        key: AccessKey,
        overwrite: bool,
    ) -> Result<(Summary, Event, CommitState)> {
        let span = span!(Level::DEBUG, "import_folder");
        let _enter = span.enter();

        self.authenticated.as_ref().ok_or(Error::NotAuthenticated)?;

        let mut vault: Vault = decode(buffer.as_ref()).await?;

        // Need to verify permission to access the data
        vault.verify(&key).await?;

        tracing::debug!(id = %vault.id(), name = %vault.name());

        // Check for existing identifier
        //let vaults = Self::list_local_folders(&self.paths, false).await?;
        let existing_id = self.find(|s| s.id() == vault.summary().id()).await;

        let default_vault = self.default_folder().await;

        let remove_default_flag = !overwrite
            && default_vault.is_some()
            && vault.summary().flags().is_default();

        // If we are not overwriting and the identifier already exists
        // then we need to rotate the identifier
        let has_id_changed = if existing_id.is_some() && !overwrite {
            tracing::debug!("rotate identifier");
            vault.rotate_identifier();
            true
        } else {
            false
        };

        let existing_name =
            self.find(|s| s.name() == vault.summary().name()).await;

        let has_name_changed = if existing_name.is_some() && !overwrite {
            let name = format!(
                "{} ({})",
                vault.summary().name(),
                vault.summary().id()
            );
            tracing::debug!("change folder name");
            vault.set_name(name);
            true
        } else {
            false
        };

        if remove_default_flag {
            tracing::debug!("remove default flag");
            vault.set_default_flag(false);
        }

        let buffer: Cow<[u8]> =
            if has_id_changed || has_name_changed || remove_default_flag {
                // Need to update the buffer as we changed the data
                Cow::Owned(encode(&vault).await?)
            } else {
                Cow::Borrowed(buffer.as_ref())
            };

        // Import the vault
        let (event, summary) = {
            let storage = self.storage()?;
            let mut writer = storage.write().await;
            writer.import_folder(buffer.as_ref(), Some(&key)).await?
        };

        // If we are overwriting then we must remove the existing
        // vault passphrase so we can save it using the passphrase
        // assigned when exporting the folder
        if overwrite {
            self.user_mut()?
                .remove_folder_password(summary.id())
                .await?;
        }

        self.user_mut()?
            .save_folder_password(summary.id(), key)
            .await?;

        // If overwriting remove old entries from the index
        if overwrite {
            // If we are overwriting and the current vault
            // is loaded into memory we must close it so
            // the UI does not show stale in-memory data
            {
                let storage = self.storage()?;
                let mut writer = storage.write().await;
                let is_current = if let Some(current) = writer.current() {
                    current.id() == summary.id()
                } else {
                    false
                };

                if is_current {
                    writer.close_vault();
                }
            }
        }

        let options = AccessOptions {
            folder: Some(summary.clone()),
            ..Default::default()
        };
        let (summary, commit_state) =
            self.compute_folder_state(&options, false).await?;

        Ok((summary, event, commit_state))
    }

    /// Open a vault.
    pub async fn open_folder(&mut self, summary: &Summary) -> Result<()> {
        self.open_vault(summary, true).await
    }

    pub(crate) async fn open_vault(
        &mut self,
        summary: &Summary,
        audit: bool,
    ) -> Result<()> {
        // Bail early if the folder is already open
        // as opening a vault is an expensive operation
        {
            let storage = self.storage()?;
            let reader = storage.read().await;
            if let Some(current) = reader.current() {
                if current.id() == summary.id() {
                    return Ok(());
                }
            }
        }

        let passphrase =
            self.user()?.find_folder_password(summary.id()).await?;

        //let index = Arc::clone(&self.index()?.search_index);

        let event = {
            let storage = self.storage()?;
            let mut writer = storage.write().await;
            let key: AccessKey = passphrase.into();
            writer.open_vault(summary, &key).await?
        };

        let event = Event::Read(*summary.id(), event);
        if audit {
            let audit_event: AuditEvent = (self.address(), &event).into();
            self.paths.append_audit_events(vec![audit_event]).await?;
        }

        Ok(())
    }

    /// Helper to get all the state information needed
    /// before calling sync methods.
    ///
    /// Computes the target folder that will be used, the last commit
    /// hash and the proof for the current head of the events log.
    async fn compute_folder_state(
        &self,
        options: &AccessOptions,
        apply_changes: bool,
    ) -> Result<(Summary, CommitState)> {
        let (folder, last_commit, mut commit_proof) = {
            let storage = self.storage()?;
            let reader = storage.read().await;
            let folder = options
                .folder
                .clone()
                .or_else(|| reader.current().map(|g| g.summary().clone()))
                .ok_or(Error::NoOpenFolder)?;

            let event_log = reader
                .cache()
                .get(folder.id())
                .ok_or(Error::CacheNotAvailable(*folder.id()))?;
            let last_commit = event_log.last_commit().await?;
            let commit_proof = event_log.tree().head()?;
            (folder, last_commit, commit_proof)
        };

        let mut last_commit = last_commit.ok_or(Error::NoRootCommit)?;

        if apply_changes {
            let storage = self.storage()?;
            if let Some(handler) = &self.handler {
                let before_result = handler
                    .before_change(
                        storage,
                        &folder,
                        &(last_commit, commit_proof.clone()),
                    )
                    .await;
                if let Some((commit, proof)) = before_result {
                    last_commit = commit;
                    commit_proof = proof;
                }
            }
        }

        Ok((folder, (last_commit, commit_proof)))
    }

    /// Bulk insert secrets into the currently open folder.
    pub async fn insert_secrets(
        &mut self,
        secrets: Vec<(SecretMeta, Secret)>,
    ) -> Result<Vec<(SecretId, Event, CommitState, Summary)>> {
        let mut results = Vec::new();
        for (meta, secret) in secrets {
            results.push(
                self.create_secret(meta, secret, Default::default()).await?,
            );
        }
        Ok(results)
    }

    /// Create a secret in the current open folder or a specific folder.
    pub async fn create_secret(
        &mut self,
        meta: SecretMeta,
        secret: Secret,
        options: AccessOptions,
    ) -> Result<(SecretId, Event, CommitState, Summary)> {
        let (folder, commit_state) =
            self.compute_folder_state(&options, true).await?;

        let (id, event, _) =
            self.add_secret(meta, secret, options, true).await?;

        Ok((id, event, commit_state, folder))
    }

    async fn add_secret(
        &mut self,
        meta: SecretMeta,
        secret: Secret,
        mut options: AccessOptions,
        audit: bool,
    ) -> Result<(SecretId, Event, Summary)> {
        let folder = {
            let storage = self.storage()?;
            let reader = storage.read().await;
            options
                .folder
                .take()
                .or_else(|| reader.current().map(|g| g.summary().clone()))
                .ok_or(Error::NoOpenFolder)?
        };

        self.open_folder(&folder).await?;

        if let Secret::Pem { certificates, .. } = &secret {
            if certificates.is_empty() {
                return Err(Error::PemEncoding);
            }
        }

        let id = SecretId::new_v4();
        let secret_data = SecretRow::new(id, meta, secret);
        let event = {
            let storage = self.storage()?;
            let mut writer = storage.write().await;
            writer.create_secret(secret_data, options).await?
        };

        let event = Event::Write(*folder.id(), event);
        if audit {
            let audit_event: AuditEvent = (self.address(), &event).into();
            self.paths.append_audit_events(vec![audit_event]).await?;
        }

        Ok((id, event, folder))
    }

    /// Read a secret in the current open folder.
    pub async fn read_secret(
        &mut self,
        secret_id: &SecretId,
        folder: Option<Summary>,
    ) -> Result<(SecretRow, ReadEvent)> {
        self.get_secret(secret_id, folder, true).await
    }

    /// Get a secret in the current open folder and
    /// optionally append to the audit log.
    ///
    /// Some internal operations needn't generate extra
    /// audit log records.
    pub(crate) async fn get_secret(
        &mut self,
        secret_id: &SecretId,
        folder: Option<Summary>,
        audit: bool,
    ) -> Result<(SecretRow, ReadEvent)> {
        let folder = {
            let storage = self.storage()?;
            let reader = storage.read().await;
            folder
                .or_else(|| reader.current().map(|g| g.summary().clone()))
                .ok_or(Error::NoOpenFolder)?
        };

        self.open_folder(&folder).await?;

        let (meta, secret, read_event) = {
            let storage = self.storage()?;
            let mut writer = storage.write().await;
            writer.read_secret(secret_id).await?
        };

        if audit {
            let event = Event::Read(*folder.id(), read_event.clone());
            let audit_event: AuditEvent = (self.address(), &event).into();
            self.paths.append_audit_events(vec![audit_event]).await?;
        }

        Ok((SecretRow::new(*secret_id, meta, secret), read_event))
    }

    /// Update a secret in the current open folder or a specific folder.
    pub async fn update_secret(
        &mut self,
        secret_id: &SecretId,
        meta: SecretMeta,
        secret: Option<Secret>,
        options: AccessOptions,
        destination: Option<&Summary>,
    ) -> Result<(SecretId, Event, CommitState, Summary)> {
        let (folder, commit_state) =
            self.compute_folder_state(&options, true).await?;

        self.open_folder(&folder).await?;

        if let Some(Secret::Pem { certificates, .. }) = &secret {
            if certificates.is_empty() {
                return Err(Error::PemEncoding);
            }
        }

        let event = {
            let storage = self.storage()?;
            let mut writer = storage.write().await;
            writer
                .update_secret(secret_id, meta, secret, options.clone())
                .await?
        };

        let event = Event::Write(*folder.id(), event);

        let id = if let Some(to) = destination.as_ref() {
            let (new_id, _) =
                self.mv_secret(secret_id, &folder, to, options).await?;
            new_id
        } else {
            *secret_id
        };

        let audit_event: AuditEvent = (self.address(), &event).into();
        self.paths.append_audit_events(vec![audit_event]).await?;

        Ok((id, event, commit_state, folder))
    }

    /// Move a secret between folders.
    pub async fn move_secret(
        &mut self,
        secret_id: &SecretId,
        from: &Summary,
        to: &Summary,
        options: AccessOptions,
    ) -> Result<(SecretId, Event)> {
        self.mv_secret(secret_id, from, to, options).await
    }

    async fn mv_secret(
        &mut self,
        secret_id: &SecretId,
        from: &Summary,
        to: &Summary,
        mut options: AccessOptions,
    ) -> Result<(SecretId, Event)> {
        self.open_vault(from, false).await?;
        let (secret_data, read_event) =
            self.get_secret(secret_id, None, false).await?;
        let move_secret_data = secret_data.clone();

        self.open_vault(to, false).await?;
        let (new_id, create_event, _) = self
            .add_secret(
                secret_data.meta,
                secret_data.secret,
                Default::default(),
                false,
            )
            .await?;
        self.open_vault(from, false).await?;

        // Note that we call `remove_secret()` and not `delete_secret()`
        // as we need the original external files for the
        // move_files operation.
        let delete_event = {
            let storage = self.storage()?;
            let mut writer = storage.write().await;
            writer.remove_secret(secret_id).await?
        };

        #[cfg(feature = "files")]
        {
            let storage = self.storage()?;
            let mut writer = storage.write().await;

            let events = writer
                .move_files(
                    &move_secret_data,
                    from.id(),
                    to.id(),
                    secret_id,
                    &new_id,
                    None,
                    &mut options.file_progress,
                )
                .await?;
            writer.append_file_mutation_events(&events).await?;
        }

        let (_, create_event) = create_event.try_into()?;
        //let (_, delete_event) = delete_event.try_into()?;

        let event = Event::MoveSecret(read_event, create_event, delete_event);

        let audit_event = AuditEvent::new(
            EventKind::MoveSecret,
            self.address().clone(),
            Some(AuditData::MoveSecret {
                from_vault_id: *from.id(),
                to_vault_id: *to.id(),
                from_secret_id: *secret_id,
                to_secret_id: new_id.clone(),
            }),
        );
        self.paths.append_audit_events(vec![audit_event]).await?;

        Ok((new_id, event))
    }

    /// Delete a secret and remove any external files.
    pub async fn delete_secret(
        &mut self,
        secret_id: &SecretId,
        options: AccessOptions,
    ) -> Result<(Event, CommitState, Summary)> {
        let (folder, commit_state) =
            self.compute_folder_state(&options, true).await?;

        self.open_folder(&folder).await?;

        let event = {
            let storage = self.storage()?;
            let mut writer = storage.write().await;
            writer.delete_secret(secret_id, options).await?
        };

        let event = Event::Write(*folder.id(), event);

        let audit_event: AuditEvent = (self.address(), &event).into();
        self.paths.append_audit_events(vec![audit_event]).await?;

        Ok((event, commit_state, folder))
    }

    /// Change the password for a folder.
    ///
    /// If this folder is part of a recovery pack it is
    /// the caller's responsbility to ensure the recovery
    /// pack is updated with the new folder password.
    pub async fn change_folder_password(
        &mut self,
        folder: &Summary,
        new_key: AccessKey,
    ) -> Result<()> {
        self.authenticated.as_ref().ok_or(Error::NotAuthenticated)?;

        let current_key =
            self.user()?.find_folder_password(folder.id()).await?;

        let vault = {
            let storage = self.storage()?;
            let reader = storage.read().await;
            reader.read_vault(folder.id()).await?
        };

        {
            let storage = self.storage()?;
            let mut writer = storage.write().await;
            writer
                .change_password(&vault, current_key, new_key.clone())
                .await?;
        }

        // Save the new password
        self.user_mut()?
            .save_folder_password(folder.id(), new_key)
            .await?;

        Ok(())
    }

    /// Move a secret to the archive.
    ///
    /// An archive folder must exist.
    pub async fn archive(
        &mut self,
        from: &Summary,
        secret_id: &SecretId,
        options: AccessOptions,
    ) -> Result<(SecretId, Event)> {
        if from.flags().is_archive() {
            return Err(Error::AlreadyArchived);
        }
        self.open_folder(from).await?;
        let to = self
            .archive_folder()
            .await
            .ok_or_else(|| Error::NoArchive)?;
        self.move_secret(secret_id, from, &to, options).await
    }

    /// Move a secret out of the archive.
    ///
    /// The secret must be inside a folder with the archive flag set
    pub async fn unarchive(
        &mut self,
        from: &Summary,
        secret_id: &SecretId,
        secret_meta: &SecretMeta,
        options: AccessOptions,
    ) -> Result<(Summary, SecretId, Event)> {
        if !from.flags().is_archive() {
            return Err(Error::NotArchived);
        }
        self.open_folder(from).await?;
        let mut to = self
            .default_folder()
            .await
            .ok_or_else(|| Error::NoDefaultFolder)?;
        let authenticator = self.authenticator_folder().await;
        let contacts = self.contacts_folder().await;
        if secret_meta.kind() == &SecretType::Totp && authenticator.is_some()
        {
            to = authenticator.unwrap();
        } else if secret_meta.kind() == &SecretType::Contact
            && contacts.is_some()
        {
            to = contacts.unwrap();
        }
        let (id, event) =
            self.move_secret(secret_id, from, &to, options).await?;
        Ok((to, id, event))
    }

    /// Initialize the search index.
    ///
    /// This should be called after a user has signed in to
    /// create the initial search index.
    pub async fn initialize_search_index(
        &mut self,
    ) -> Result<(DocumentCount, Vec<Summary>)> {
        let keys = self.folder_keys().await?;
        let storage = self.storage()?;
        let mut writer = storage.write().await;
        writer.initialize_search_index(&keys).await
    }

    /// Build the search index for all folders.
    pub(crate) async fn build_search_index(
        &mut self,
    ) -> Result<DocumentCount> {
        let keys = self.folder_keys().await?;
        let storage = self.storage()?;
        let mut writer = storage.write().await;
        writer.build_search_index(&keys).await
    }

    /// Get the access keys for all folders.
    async fn folder_keys(&self) -> Result<FolderKeys> {
        let storage = self.storage()?;
        let reader = storage.read().await;
        let folders = reader.folders();
        let mut keys = HashMap::new();
        for folder in folders {
            keys.insert(
                folder.clone(),
                self.user()?.find_folder_password(folder.id()).await?,
            );
        }
        Ok(FolderKeys(keys))
    }

    /// Create a detached view of an event log until a
    /// particular commit.
    ///
    /// This is useful for time travel; browsing the event
    /// history at a particular point in time.
    pub async fn detached_view(
        &self,
        summary: &Summary,
        commit: CommitHash,
    ) -> Result<DetachedView> {
        let search_index = Arc::new(RwLock::new(SearchIndex::new()));

        let storage = self.storage()?;
        let reader = storage.read().await;
        let cache = reader.cache();
        let log_file = cache
            .get(summary.id())
            .ok_or_else(|| Error::CacheNotAvailable(*summary.id()))?;

        let passphrase =
            self.user()?.find_folder_password(summary.id()).await?;

        let vault = EventReducer::new_until_commit(commit)
            .reduce(log_file)
            .await?
            .build()
            .await?;

        let mut keeper = Gatekeeper::new(vault);
        let key: AccessKey = passphrase.into();
        keeper.unlock(&key).await?;

        {
            let mut index = search_index.write().await;
            index.add_folder(&keeper).await?;
        }

        Ok(DetachedView {
            keeper,
            index: search_index,
        })
    }

    /// Get the root commit hash for a folder.
    pub async fn root_commit(&self, summary: &Summary) -> Result<CommitHash> {
        let storage = self.storage()?;
        let reader = storage.read().await;
        let cache = reader.cache();
        let log_file = cache
            .get(summary.id())
            .ok_or_else(|| Error::CacheNotAvailable(*summary.id()))?;
        Ok(log_file
            .tree()
            .root()
            .map(CommitHash)
            .ok_or_else(|| Error::NoRootCommit)?)
    }

    /// Get the commit state for a folder.
    ///
    /// The folder must have at least one commit.
    pub async fn commit_state(
        &self,
        summary: &Summary,
    ) -> Result<CommitState> {
        let storage = self.storage()?;
        let reader = storage.read().await;
        Ok(reader.commit_state(summary).await?)
    }

    /// Compact an event log file.
    pub async fn compact(&mut self, summary: &Summary) -> Result<(u64, u64)> {
        let (old_size, new_size) = {
            let storage = self.storage()?;
            let mut writer = storage.write().await;
            writer.compact(&summary).await?
        };

        Ok((old_size, new_size))
    }
}
