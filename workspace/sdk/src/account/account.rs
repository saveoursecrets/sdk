//! Account storage and search index.
use std::{
    borrow::Cow,
    collections::HashMap,
    path::{Path, PathBuf},
    sync::Arc,
};

use crate::{
    account::AccountBuilder,
    commit::{CommitHash, CommitState},
    crypto::AccessKey,
    decode, encode,
    events::{
        AccountEvent, AccountEventLog, Event, EventKind, EventLogExt,
        FolderReducer, ReadEvent, WriteEvent,
    },
    identity::{AccountRef, FolderKeys, Identity, PublicIdentity},
    signer::ecdsa::Address,
    storage::AccountPack,
    storage::{
        search::{DocumentCount, SearchIndex},
        AccessOptions, ClientStorage,
    },
    vault::{
        secret::{Secret, SecretId, SecretMeta, SecretRow, SecretType},
        Gatekeeper, Header, Summary, Vault, VaultId,
    },
    vfs, Error, Paths, Result, Timestamp,
};

#[cfg(feature = "audit")]
use crate::audit::{AuditData, AuditEvent};

#[cfg(feature = "search")]
use crate::storage::search::*;

#[cfg(feature = "sync")]
use crate::sync::SyncError;

#[cfg(all(feature = "files", feature = "sync"))]
use crate::storage::files::Transfers;

use tracing::{span, Level};

use async_trait::async_trait;
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

/// Result information for a created or updated secret.
pub struct SecretChange<T> {
    /// Secret identifier.
    pub id: SecretId,
    /// Event to be logged.
    pub event: Event,
    /// Commit state of the folder event log before
    /// the secret was created (or updated).
    pub commit_state: CommitState,
    /// Folder containing the secret.
    pub folder: Summary,
    /// Error generated during a sync.
    #[cfg(feature = "sync")]
    pub sync_error: Option<SyncError<T>>,
}

/// Result information for a bulk insert.
pub struct SecretInsert<T> {
    /// Created secrets.
    pub results: Vec<SecretChange<T>>,
    /// Error generated during a sync.
    #[cfg(feature = "sync")]
    pub sync_error: Option<SyncError<T>>,
}

/// Result information for a secret move event.
pub struct SecretMove<T> {
    /// Secret identifier.
    pub id: SecretId,
    /// Event to be logged.
    pub event: Event,
    /// Error generated during a sync.
    #[cfg(feature = "sync")]
    pub sync_error: Option<SyncError<T>>,
}

/// Result information for a deleted secret.
pub struct SecretDelete<T> {
    /// Event to be logged.
    pub event: Event,
    /// Commit state of the folder event log before
    /// the secret was deleted.
    pub commit_state: CommitState,
    /// Folder the secret was deleted from.
    pub folder: Summary,
    /// Error generated during a sync.
    #[cfg(feature = "sync")]
    pub sync_error: Option<SyncError<T>>,
}

/// Trait for account implementations.
#[async_trait]
pub trait Account {
    /// Account to create.
    type Account;

    /// Errors for this account.
    type Error: std::fmt::Debug;

    /// Prepare an account for sign in.
    ///
    /// After preparing an account call `sign_in`
    /// to authenticate a user.
    async fn new_unauthenticated(
        address: Address,
        data_dir: Option<PathBuf>,
    ) -> std::result::Result<Self::Account, Self::Error>;

    /// Create a new account with the given
    /// name, passphrase and provider.
    ///
    /// Uses standard flags for the account builder for
    /// more control of the created account use
    /// `new_account_with_builder()`.
    async fn new_account(
        account_name: String,
        passphrase: SecretString,
        data_dir: Option<PathBuf>,
    ) -> std::result::Result<Self::Account, Self::Error>;

    /// Create a new account with the given
    /// name, passphrase and provider and modify the
    /// account builder.
    async fn new_account_with_builder(
        account_name: String,
        passphrase: SecretString,
        builder: impl Fn(AccountBuilder) -> AccountBuilder + Send,
        data_dir: Option<PathBuf>,
    ) -> std::result::Result<Self::Account, Self::Error>;

    /// Account address.
    fn address(&self) -> &Address;

    /// User storage paths.
    fn paths(&self) -> &Paths;

    /// Public identity information.
    async fn public_identity(
        &self,
    ) -> std::result::Result<PublicIdentity, Self::Error>;

    /// Reference to the identity for this account.
    async fn account_ref(
        &self,
    ) -> std::result::Result<AccountRef, Self::Error>;

    /// Label of this account.
    async fn account_label(&self)
        -> std::result::Result<String, Self::Error>;

    /// Load the buffer of the encrypted vault for this account.
    ///
    /// Used when a client needs to enroll other devices;
    /// it sends the encrypted identity vault and if the vault
    /// can be unlocked then we have verified that the other
    /// device knows the primary password for this account.
    async fn identity_vault_buffer(
        &self,
    ) -> std::result::Result<Vec<u8>, Self::Error>;

    /// Access an account by signing in.
    ///
    /// If a default folder exists for the account it
    /// is opened.
    async fn sign_in(
        &mut self,
        key: &AccessKey,
    ) -> std::result::Result<Vec<Summary>, Self::Error>;

    /// Verify an access key for this account.
    ///
    /// If the account is not authenticated this returns false.
    async fn verify(&self, key: &AccessKey) -> bool;

    /// Open a folder.
    async fn open_folder(
        &mut self,
        summary: &Summary,
    ) -> std::result::Result<(), Self::Error>;

    /// Try to find a folder using a predicate.
    async fn find<P>(&self, predicate: P) -> Option<Summary>
    where
        P: FnMut(&&Summary) -> bool + Send;

    /// Find the default folder.
    async fn default_folder(&self) -> Option<Summary> {
        self.find(|s| s.flags().is_default()).await
    }

    /// Find the authenticator folder.
    async fn authenticator_folder(&self) -> Option<Summary> {
        self.find(|s| s.flags().is_authenticator()).await
    }

    /// Find the contacts folder.
    async fn contacts_folder(&self) -> Option<Summary> {
        self.find(|s| s.flags().is_contact()).await
    }

    /// Find the archive folder.
    async fn archive_folder(&self) -> Option<Summary> {
        self.find(|s| s.flags().is_archive()).await
    }

    /// Sign out of the account.
    async fn sign_out(&mut self) -> std::result::Result<(), Self::Error>;

    /// Rename this account.
    async fn rename_account(
        &mut self,
        account_name: String,
    ) -> std::result::Result<(), Self::Error>;

    /// Delete the account for this user and sign out.
    async fn delete_account(
        &mut self,
    ) -> std::result::Result<(), Self::Error>;

    /// Storage provider.
    async fn storage(
        &self,
    ) -> std::result::Result<Arc<RwLock<ClientStorage>>, Self::Error>;

    /// Read the secret identifiers in a vault.
    async fn secret_ids(
        &self,
        summary: &Summary,
    ) -> std::result::Result<Vec<SecretId>, Self::Error>;

    /// Load folders into memory.
    ///
    /// This method is automatically called on sign in to
    /// prepare the in-memory vaults but can be explicitly
    /// called to reload the data from disc.
    async fn load_folders(
        &mut self,
    ) -> std::result::Result<Vec<Summary>, Self::Error>;

    /// List in-memory folders managed by this account.
    async fn list_folders(
        &self,
    ) -> std::result::Result<Vec<Summary>, Self::Error>;

    /// Account data.
    async fn account_data(
        &self,
    ) -> std::result::Result<AccountData, Self::Error>;

    /// Root commit hash for a folder.
    async fn root_commit(
        &self,
        summary: &Summary,
    ) -> std::result::Result<CommitHash, Self::Error>;

    /// Commit state of the identity vault.
    ///
    /// The folder must have at least one commit.
    async fn identity_state(
        &self,
    ) -> std::result::Result<CommitState, Self::Error>;

    /// Get the commit state for a folder.
    ///
    /// The folder must have at least one commit.
    async fn commit_state(
        &self,
        summary: &Summary,
    ) -> std::result::Result<CommitState, Self::Error>;

    /// Compact the event log file for a folder.
    async fn compact(
        &mut self,
        summary: &Summary,
    ) -> std::result::Result<(u64, u64), Self::Error>;

    /// Create a detached view of an event log until a
    /// particular commit.
    ///
    /// This is useful for time travel; browsing the event
    /// history at a particular point in time.
    async fn detached_view(
        &self,
        summary: &Summary,
        commit: CommitHash,
    ) -> std::result::Result<DetachedView, Self::Error>;

    /// Transfers queue.
    #[cfg(all(feature = "files", feature = "sync"))]
    async fn transfers(
        &self,
    ) -> std::result::Result<Arc<RwLock<Transfers>>, Self::Error>;

    /// Initialize the search index.
    ///
    /// This should be called after a user has signed in to
    /// create the initial search index.
    #[cfg(feature = "search")]
    async fn initialize_search_index(
        &mut self,
    ) -> std::result::Result<(DocumentCount, Vec<Summary>), Self::Error>;

    /// Compute the account statistics.
    ///
    /// If the account is not authenticated returns
    /// a default statistics object (all values will be zero).
    #[cfg(feature = "search")]
    async fn statistics(&self) -> AccountStatistics;

    /// Search index for the account.
    #[cfg(feature = "search")]
    async fn index(
        &self,
    ) -> std::result::Result<Arc<RwLock<SearchIndex>>, Self::Error>;

    /// Query with document views.
    #[cfg(feature = "search")]
    async fn query_view(
        &self,
        views: Vec<DocumentView>,
        archive: Option<ArchiveFilter>,
    ) -> std::result::Result<Vec<Document>, Self::Error>;

    /// Query the search index.
    #[cfg(feature = "search")]
    async fn query_map(
        &self,
        query: &str,
        filter: QueryFilter,
    ) -> std::result::Result<Vec<Document>, Self::Error>;

    /// Get the search index document count statistics.
    #[cfg(feature = "search")]
    async fn document_count(
        &self,
    ) -> std::result::Result<DocumentCount, Self::Error>;

    /// Determine if a document exists in a folder.
    #[cfg(feature = "search")]
    async fn document_exists(
        &self,
        vault_id: &VaultId,
        label: &str,
        id: Option<&SecretId>,
    ) -> std::result::Result<bool, Self::Error>;

    /// Decrypt a file and return the buffer.
    #[cfg(feature = "files")]
    async fn download_file(
        &self,
        vault_id: &VaultId,
        secret_id: &SecretId,
        file_name: &str,
    ) -> std::result::Result<Vec<u8>, Self::Error>;

    /// Create a secret in the current open folder or a specific folder.
    async fn create_secret(
        &mut self,
        meta: SecretMeta,
        secret: Secret,
        options: AccessOptions,
    ) -> std::result::Result<SecretChange<Self::Error>, Self::Error>;

    /// Bulk insert secrets into the currently open folder.
    async fn insert_secrets(
        &mut self,
        secrets: Vec<(SecretMeta, Secret)>,
    ) -> std::result::Result<SecretInsert<Self::Error>, Self::Error>;

    /// Update a secret in the current open folder or a specific folder.
    ///
    /// If a `destination` is given the secret is also moved to the
    /// target folder.
    async fn update_secret(
        &mut self,
        secret_id: &SecretId,
        meta: SecretMeta,
        secret: Option<Secret>,
        options: AccessOptions,
        destination: Option<&Summary>,
    ) -> std::result::Result<SecretChange<Self::Error>, Self::Error>;

    /// Move a secret between folders.
    async fn move_secret(
        &mut self,
        secret_id: &SecretId,
        from: &Summary,
        to: &Summary,
        options: AccessOptions,
    ) -> std::result::Result<SecretMove<Self::Error>, Self::Error>;

    /// Read a secret in the current open folder.
    async fn read_secret(
        &mut self,
        secret_id: &SecretId,
        folder: Option<Summary>,
    ) -> std::result::Result<(SecretRow, ReadEvent), Self::Error>;

    /// Delete a secret and remove any external files.
    async fn delete_secret(
        &mut self,
        secret_id: &SecretId,
        options: AccessOptions,
    ) -> std::result::Result<SecretDelete<Self::Error>, Self::Error>;

    /// Move a secret to the archive.
    ///
    /// An archive folder must exist.
    async fn archive(
        &mut self,
        from: &Summary,
        secret_id: &SecretId,
        options: AccessOptions,
    ) -> std::result::Result<SecretMove<Self::Error>, Self::Error>;

    /// Move a secret out of the archive.
    ///
    /// The secret must be inside a folder with the archive flag set
    async fn unarchive(
        &mut self,
        from: &Summary,
        secret_id: &SecretId,
        secret_meta: &SecretMeta,
        options: AccessOptions,
    ) -> std::result::Result<(SecretMove<Self::Error>, Summary), Self::Error>;
}

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
    storage: Arc<RwLock<ClientStorage>>,
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
pub struct LocalAccount {
    /// Account address.
    address: Address,

    /// Account information after a successful
    /// sign in.
    pub(super) authenticated: Option<Authenticated>,

    /// Storage paths.
    pub paths: Arc<Paths>,
}

impl LocalAccount {
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
                let buffer = vfs::read(paths.vault_path(folder.id())).await?;
                let vault: Vault = decode(&buffer).await?;
                let header: Header = vault.into();
                let head_only: Vault = header.into();
                let buffer = encode(&head_only).await?;
                events
                    .push(AccountEvent::CreateFolder(folder.into(), buffer));
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

    /// Create a folder.
    pub async fn create_folder(
        &mut self,
        name: String,
    ) -> Result<(Summary, Event, CommitState)> {
        self.authenticated.as_ref().ok_or(Error::NotAuthenticated)?;

        let passphrase = self.user()?.generate_folder_password()?;
        let key: AccessKey = passphrase.into();

        let (buffer, _, summary, account_event) = {
            let storage = self.storage().await?;
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
            self.compute_folder_state(&options).await?;

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
            self.compute_folder_state(&options).await?;

        let events = {
            let storage = self.storage().await?;
            let mut writer = storage.write().await;
            writer.delete_folder(&summary, true).await?
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
            self.compute_folder_state(&options).await?;

        // Update the provider
        let event = {
            let storage = self.storage().await?;
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
        let storage = self.storage().await?;
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
            let storage = self.storage().await?;
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
            let storage = self.storage().await?;
            let mut writer = storage.write().await;
            writer
                .import_folder(buffer.as_ref(), Some(&key), true)
                .await?
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
                let storage = self.storage().await?;
                let mut writer = storage.write().await;
                let is_current =
                    if let Some(current) = writer.current_folder() {
                        current.id() == summary.id()
                    } else {
                        false
                    };

                if is_current {
                    writer.close_folder();
                }
            }
        }

        let options = AccessOptions {
            folder: Some(summary.clone()),
            ..Default::default()
        };
        let (summary, commit_state) =
            self.compute_folder_state(&options).await?;

        Ok((summary, event, commit_state))
    }

    pub(crate) async fn open_vault(
        &mut self,
        summary: &Summary,
        audit: bool,
    ) -> Result<()> {
        // Bail early if the folder is already open
        {
            let storage = self.storage().await?;
            let reader = storage.read().await;
            if let Some(current) = reader.current_folder() {
                if current.id() == summary.id() {
                    return Ok(());
                }
            }
        }

        let event = {
            let storage = self.storage().await?;
            let mut writer = storage.write().await;
            writer.open_folder(summary).await?
        };

        if audit {
            let event = Event::Read(*summary.id(), event);
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
    ) -> Result<(Summary, CommitState)> {
        let (folder, commit_state) = {
            let storage = self.storage().await?;
            let reader = storage.read().await;
            let folder = options
                .folder
                .clone()
                .or_else(|| reader.current_folder())
                .ok_or(Error::NoOpenFolder)?;

            let commit_state = reader
                .cache()
                .get(folder.id())
                .ok_or(Error::CacheNotAvailable(*folder.id()))?
                .commit_state()
                .await?;

            (folder, commit_state)
        };
        Ok((folder, commit_state))
    }

    async fn add_secret(
        &mut self,
        meta: SecretMeta,
        secret: Secret,
        mut options: AccessOptions,
        audit: bool,
    ) -> Result<(SecretId, Event, Summary)> {
        let folder = {
            let storage = self.storage().await?;
            let reader = storage.read().await;
            options
                .folder
                .take()
                .or_else(|| reader.current_folder())
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
            let storage = self.storage().await?;
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
            let storage = self.storage().await?;
            let reader = storage.read().await;
            folder
                .or_else(|| reader.current_folder())
                .ok_or(Error::NoOpenFolder)?
        };

        self.open_folder(&folder).await?;

        let (meta, secret, read_event) = {
            let storage = self.storage().await?;
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

    async fn mv_secret(
        &mut self,
        secret_id: &SecretId,
        from: &Summary,
        to: &Summary,
        mut options: AccessOptions,
    ) -> Result<SecretMove<Error>> {
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
            let storage = self.storage().await?;
            let mut writer = storage.write().await;
            writer.remove_secret(secret_id).await?
        };

        #[cfg(feature = "files")]
        {
            let storage = self.storage().await?;
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

        Ok(SecretMove {
            id: new_id,
            event,
            sync_error: None,
        })
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
            let storage = self.storage().await?;
            let reader = storage.read().await;
            reader.read_vault(folder.id()).await?
        };

        {
            let storage = self.storage().await?;
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

    /// Build the search index for all folders.
    #[cfg(feature = "search")]
    pub(crate) async fn build_search_index(
        &mut self,
    ) -> Result<DocumentCount> {
        let keys = self.folder_keys().await?;
        let storage = self.storage().await?;
        let mut writer = storage.write().await;
        writer.build_search_index(&keys).await
    }

    /// Access keys for all folders.
    pub(super) async fn folder_keys(&self) -> Result<FolderKeys> {
        let storage = self.storage().await?;
        let reader = storage.read().await;
        let folders = reader.list_folders();
        let mut keys = HashMap::new();
        for folder in folders {
            keys.insert(
                folder.clone(),
                self.user()?.find_folder_password(folder.id()).await?,
            );
        }
        Ok(FolderKeys(keys))
    }
}

#[async_trait]
impl Account for LocalAccount {
    type Account = LocalAccount;
    type Error = Error;

    async fn new_unauthenticated(
        address: Address,
        data_dir: Option<PathBuf>,
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
        })
    }

    async fn new_account(
        account_name: String,
        passphrase: SecretString,
        data_dir: Option<PathBuf>,
    ) -> Result<Self> {
        Self::new_account_with_builder(
            account_name,
            passphrase,
            |builder| builder.create_file_password(true),
            data_dir,
        )
        .await
    }

    async fn new_account_with_builder(
        account_name: String,
        passphrase: SecretString,
        builder: impl Fn(AccountBuilder) -> AccountBuilder + Send,
        data_dir: Option<PathBuf>,
    ) -> Result<Self> {
        let span = span!(Level::DEBUG, "new_account");
        let _enter = span.enter();

        let account_builder = builder(AccountBuilder::new(
            account_name,
            passphrase.clone(),
            data_dir.clone(),
        ));
        let new_account = account_builder.finish().await?;

        tracing::debug!(address = %new_account.address, "created account");

        let address = new_account.address.clone();
        let identity_log = new_account.user.identity()?.event_log();

        let mut storage = ClientStorage::new(
            address.clone(),
            data_dir.clone(),
            identity_log,
            #[cfg(feature = "device")]
            new_account.user.identity()?.devices()?.current_device(None),
        )
        .await?;

        tracing::debug!("prepared storage provider");

        // Must import the new account before signing in
        let public_account: AccountPack = new_account.into();
        storage.create_account(&public_account).await?;

        tracing::debug!("imported new account");

        let account = Self {
            address,
            paths: storage.paths(),
            authenticated: None,
        };

        //Ok((owner, public_account))

        //let (account, _) = Self::new_account_with_data(
        //account_name,
        //passphrase,
        //builder,
        //data_dir,
        //)
        //.await?;

        Ok(account)
    }

    fn address(&self) -> &Address {
        &self.address
    }

    fn paths(&self) -> &Paths {
        &self.paths
    }

    async fn public_identity(&self) -> Result<PublicIdentity> {
        Ok(self.user()?.account()?.clone())
    }

    async fn account_ref(&self) -> Result<AccountRef> {
        Ok(self.user()?.account().unwrap().into())
    }

    async fn account_label(&self) -> Result<String> {
        Ok(self.user()?.account()?.label().to_owned())
    }

    /// Load the buffer of the encrypted vault for this account.
    ///
    /// Used when a client needs to authenticate other devices;
    /// it sends the encrypted identity vault and if the vault
    /// can be unlocked then we have verified that the other
    /// device knows the primary password for this account.
    async fn identity_vault_buffer(&self) -> Result<Vec<u8>> {
        let storage = self.storage().await?;
        let reader = storage.read().await;
        let identity_path = reader.paths().identity_vault();
        Ok(vfs::read(identity_path).await?)
    }

    async fn sign_in(&mut self, key: &AccessKey) -> Result<Vec<Summary>> {
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

        let identity_log = user.identity().as_ref().unwrap().event_log();

        let mut storage = ClientStorage::new(
            signer.address()?,
            Some(data_dir),
            identity_log,
            #[cfg(feature = "device")]
            user.identity()?.devices()?.current_device(None),
        )
        .await?;
        self.paths = storage.paths();

        let file_password = user.find_file_encryption_password().await?;
        storage.set_file_password(Some(file_password));

        Self::initialize_account_log(
            &*self.paths,
            Arc::clone(&storage.account_log),
        )
        .await?;

        self.authenticated = Some(Authenticated {
            user,
            storage: Arc::new(RwLock::new(storage)),
        });

        // Load vaults into memory and initialize folder
        // event log commit trees
        let folders = self.load_folders().await?;

        // Unlock all the storage vaults
        {
            let folder_keys = self.folder_keys().await?;
            let storage = self.storage().await?;
            let mut storage = storage.write().await;
            storage.unlock(&folder_keys).await?;
        }

        if let Some(default_folder) = self.default_folder().await {
            self.open_folder(&default_folder).await?;
        }

        Ok(folders)
    }

    async fn verify(&self, key: &AccessKey) -> bool {
        if let Some(auth) = &self.authenticated {
            auth.user.verify(key).await
        } else {
            false
        }
    }

    async fn open_folder(&mut self, summary: &Summary) -> Result<()> {
        self.open_vault(summary, true).await
    }

    async fn sign_out(&mut self) -> Result<()> {
        let span = span!(Level::DEBUG, "sign_out");
        let _enter = span.enter();

        tracing::debug!(address = %self.address());

        tracing::debug!("lock storage vaults");
        // Lock all the storage vaults
        let storage = self.storage().await?;
        let mut writer = storage.write().await;
        writer.lock().await;

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

    async fn rename_account(&mut self, account_name: String) -> Result<()> {
        Ok(self.user_mut()?.rename_account(account_name).await?)
    }

    /// Delete the account for this user and sign out.
    async fn delete_account(&mut self) -> Result<()> {
        let span = span!(Level::DEBUG, "delete_account");
        let _enter = span.enter();

        let paths = self.paths().clone();
        let event = self.user_mut()?.delete_account(&paths).await?;
        let audit_event: AuditEvent = (self.address(), &event).into();
        self.paths.append_audit_events(vec![audit_event]).await?;
        self.sign_out().await?;
        Ok(())
    }

    async fn find<P>(&self, predicate: P) -> Option<Summary>
    where
        P: FnMut(&&Summary) -> bool + Send,
    {
        if let Some(auth) = &self.authenticated {
            let reader = auth.storage.read().await;
            reader.find(predicate).cloned()
        } else {
            None
        }
    }

    async fn storage(&self) -> Result<Arc<RwLock<ClientStorage>>> {
        let auth =
            self.authenticated.as_ref().ok_or(Error::NotAuthenticated)?;
        Ok(Arc::clone(&auth.storage))
    }

    async fn secret_ids(&self, summary: &Summary) -> Result<Vec<SecretId>> {
        let storage = self.storage().await?;
        let reader = storage.read().await;
        let vault: Vault = reader.read_vault(summary.id()).await?;
        Ok(vault.keys().cloned().collect())
    }

    async fn load_folders(&mut self) -> Result<Vec<Summary>> {
        tracing::debug!("load folders");
        let storage = self.storage().await?;
        let mut writer = storage.write().await;
        Ok(writer.load_folders().await?.to_vec())
    }

    async fn list_folders(&self) -> Result<Vec<Summary>> {
        let storage = self.storage().await?;
        let reader = storage.read().await;
        Ok(reader.list_folders().to_vec())
    }

    async fn account_data(&self) -> Result<AccountData> {
        let storage = self.storage().await?;
        let reader = storage.read().await;
        let user = self.user()?;
        Ok(AccountData {
            account: user.account()?.clone(),
            identity: user
                .identity()?
                .private_identity()
                .recipient()
                .to_string(),
            folders: reader.list_folders().to_vec(),
        })
    }

    async fn root_commit(&self, summary: &Summary) -> Result<CommitHash> {
        let storage = self.storage().await?;
        let reader = storage.read().await;
        let cache = reader.cache();
        let folder = cache
            .get(summary.id())
            .ok_or_else(|| Error::CacheNotAvailable(*summary.id()))?;
        let event_log = folder.event_log();
        let log_file = event_log.read().await;
        Ok(log_file.tree().root().ok_or_else(|| Error::NoRootCommit)?)
    }

    async fn identity_state(&self) -> Result<CommitState> {
        let storage = self.storage().await?;
        let reader = storage.read().await;
        Ok(reader.identity_state().await?)
    }

    async fn commit_state(&self, summary: &Summary) -> Result<CommitState> {
        let storage = self.storage().await?;
        let reader = storage.read().await;
        Ok(reader.commit_state(summary).await?)
    }

    async fn compact(&mut self, summary: &Summary) -> Result<(u64, u64)> {
        let key = self.user()?.find_folder_password(summary.id()).await?;

        let (old_size, new_size) = {
            let storage = self.storage().await?;
            let mut writer = storage.write().await;
            writer.compact(&summary, &key).await?
        };

        Ok((old_size, new_size))
    }

    /// Create a detached view of an event log until a
    /// particular commit.
    ///
    /// This is useful for time travel; browsing the event
    /// history at a particular point in time.
    async fn detached_view(
        &self,
        summary: &Summary,
        commit: CommitHash,
    ) -> Result<DetachedView> {
        let search_index = Arc::new(RwLock::new(SearchIndex::new()));

        let storage = self.storage().await?;
        let reader = storage.read().await;
        let cache = reader.cache();
        let folder = cache
            .get(summary.id())
            .ok_or_else(|| Error::CacheNotAvailable(*summary.id()))?;

        let passphrase =
            self.user()?.find_folder_password(summary.id()).await?;

        let event_log = folder.event_log();
        let log_file = event_log.read().await;
        let vault = FolderReducer::new_until_commit(commit)
            .reduce(&*log_file)
            .await?
            .build(true)
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

    #[cfg(all(feature = "files", feature = "sync"))]
    async fn transfers(&self) -> Result<Arc<RwLock<Transfers>>> {
        let storage = self.storage().await?;
        let storage = storage.read().await;
        Ok(storage.transfers())
    }

    /// Initialize the search index.
    ///
    /// This should be called after a user has signed in to
    /// create the initial search index.
    #[cfg(feature = "search")]
    async fn initialize_search_index(
        &mut self,
    ) -> Result<(DocumentCount, Vec<Summary>)> {
        let keys = self.folder_keys().await?;
        let storage = self.storage().await?;
        let mut writer = storage.write().await;
        writer.initialize_search_index(&keys).await
    }

    /// Compute the account statistics.
    ///
    /// If the account is not authenticated returns
    /// a default statistics object (all values will be zero).
    #[cfg(feature = "search")]
    async fn statistics(&self) -> AccountStatistics {
        if self.authenticated.is_some() {
            let storage = self.storage().await.unwrap();
            let reader = storage.read().await;
            if let Ok(index) = reader.index() {
                let search_index = index.search();
                let index = search_index.read().await;
                let statistics = index.statistics();
                let count = statistics.count();

                let documents: usize = count.vaults().values().sum();
                let mut folders = Vec::new();
                let mut types = HashMap::new();

                for (id, v) in count.vaults() {
                    if let Some(summary) = self.find(|s| s.id() == id).await {
                        folders.push((summary, *v));
                    }
                }

                for (k, v) in count.kinds() {
                    if let Ok(kind) = SecretType::try_from(*k) {
                        types.insert(kind, *v);
                    }
                }

                AccountStatistics {
                    documents,
                    folders,
                    types,
                    tags: count.tags().clone(),
                    favorites: count.favorites(),
                }
            } else {
                Default::default()
            }
        } else {
            Default::default()
        }
    }

    #[cfg(feature = "search")]
    async fn index(&self) -> Result<Arc<RwLock<SearchIndex>>> {
        let storage = self.storage().await?;
        let reader = storage.read().await;
        Ok(reader.index()?.search())
    }

    #[cfg(feature = "search")]
    async fn query_view(
        &self,
        views: Vec<DocumentView>,
        archive: Option<ArchiveFilter>,
    ) -> Result<Vec<Document>> {
        let storage = self.storage().await?;
        let reader = storage.read().await;
        reader.index()?.query_view(views, archive).await
    }

    #[cfg(feature = "search")]
    async fn query_map(
        &self,
        query: &str,
        filter: QueryFilter,
    ) -> Result<Vec<Document>> {
        let storage = self.storage().await?;
        let reader = storage.read().await;
        reader.index()?.query_map(query, filter).await
    }

    #[cfg(feature = "search")]
    async fn document_count(&self) -> Result<DocumentCount> {
        let storage = self.storage().await?;
        let reader = storage.read().await;
        let search = reader.index()?.search();
        let index = search.read().await;
        Ok(index.statistics().count().clone())
    }

    #[cfg(feature = "search")]
    async fn document_exists(
        &self,
        vault_id: &VaultId,
        label: &str,
        id: Option<&SecretId>,
    ) -> Result<bool> {
        let storage = self.storage().await?;
        let reader = storage.read().await;
        let search = reader.index()?.search();
        let index = search.read().await;
        Ok(index.find_by_label(vault_id, label, id).is_some())
    }

    #[cfg(feature = "files")]
    async fn download_file(
        &self,
        vault_id: &VaultId,
        secret_id: &SecretId,
        file_name: &str,
    ) -> Result<Vec<u8>> {
        let storage = self.storage().await?;
        let reader = storage.read().await;
        reader.download_file(vault_id, secret_id, file_name).await
    }

    async fn create_secret(
        &mut self,
        meta: SecretMeta,
        secret: Secret,
        options: AccessOptions,
    ) -> Result<SecretChange<Self::Error>> {
        let (folder, commit_state) =
            self.compute_folder_state(&options).await?;

        let (id, event, _) =
            self.add_secret(meta, secret, options, true).await?;

        Ok(SecretChange {
            id,
            event,
            commit_state,
            folder,
            sync_error: None,
        })
    }

    async fn insert_secrets(
        &mut self,
        secrets: Vec<(SecretMeta, Secret)>,
    ) -> Result<SecretInsert<Self::Error>> {
        let mut results = Vec::new();
        for (meta, secret) in secrets {
            results.push(
                self.create_secret(meta, secret, Default::default()).await?,
            );
        }
        Ok(SecretInsert {
            results,
            sync_error: None,
        })
    }

    /// Update a secret in the current open folder or a specific folder.
    async fn update_secret(
        &mut self,
        secret_id: &SecretId,
        meta: SecretMeta,
        secret: Option<Secret>,
        options: AccessOptions,
        destination: Option<&Summary>,
    ) -> Result<SecretChange<Self::Error>> {
        let (folder, commit_state) =
            self.compute_folder_state(&options).await?;

        self.open_folder(&folder).await?;

        if let Some(Secret::Pem { certificates, .. }) = &secret {
            if certificates.is_empty() {
                return Err(Error::PemEncoding);
            }
        }

        let event = {
            let storage = self.storage().await?;
            let mut writer = storage.write().await;
            writer
                .update_secret(secret_id, meta, secret, options.clone())
                .await?
        };

        let event = Event::Write(*folder.id(), event);

        let id = if let Some(to) = destination.as_ref() {
            let SecretMove { id, .. } =
                self.mv_secret(secret_id, &folder, to, options).await?;
            id
        } else {
            *secret_id
        };

        let audit_event: AuditEvent = (self.address(), &event).into();
        self.paths.append_audit_events(vec![audit_event]).await?;

        Ok(SecretChange {
            id,
            event,
            commit_state,
            folder,
            sync_error: None,
        })
    }

    async fn move_secret(
        &mut self,
        secret_id: &SecretId,
        from: &Summary,
        to: &Summary,
        options: AccessOptions,
    ) -> Result<SecretMove<Self::Error>> {
        self.mv_secret(secret_id, from, to, options).await
    }

    async fn read_secret(
        &mut self,
        secret_id: &SecretId,
        folder: Option<Summary>,
    ) -> Result<(SecretRow, ReadEvent)> {
        self.get_secret(secret_id, folder, true).await
    }

    async fn delete_secret(
        &mut self,
        secret_id: &SecretId,
        options: AccessOptions,
    ) -> Result<SecretDelete<Self::Error>> {
        let (folder, commit_state) =
            self.compute_folder_state(&options).await?;

        self.open_folder(&folder).await?;

        let event = {
            let storage = self.storage().await?;
            let mut writer = storage.write().await;
            writer.delete_secret(secret_id, options).await?
        };

        let event = Event::Write(*folder.id(), event);

        let audit_event: AuditEvent = (self.address(), &event).into();
        self.paths.append_audit_events(vec![audit_event]).await?;

        Ok(SecretDelete {
            event,
            commit_state,
            folder,
            sync_error: None,
        })
    }

    async fn archive(
        &mut self,
        from: &Summary,
        secret_id: &SecretId,
        options: AccessOptions,
    ) -> Result<SecretMove<Self::Error>> {
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

    async fn unarchive(
        &mut self,
        from: &Summary,
        secret_id: &SecretId,
        secret_meta: &SecretMeta,
        options: AccessOptions,
    ) -> Result<(SecretMove<Self::Error>, Summary)> {
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
        let result = self.move_secret(secret_id, from, &to, options).await?;
        Ok((result, to))
    }
}
