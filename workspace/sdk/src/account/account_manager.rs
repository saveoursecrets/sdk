//! Account storage and search index.
use std::{
    any::Any,
    borrow::Cow,
    collections::HashMap,
    path::{Path, PathBuf},
    pin::Pin,
    sync::Arc,
};

use futures::Future;

use crate::{
    account::{
        archive::Inventory, AccountBackup, AccountBuilder, AccountInfo,
        AuthenticatedUser, DelegatedPassphrase, ExtractFilesLocation,
        ImportedAccount, LocalAccounts, LocalProvider, Login, NewAccount,
        RestoreOptions, UserPaths,
    },
    commit::{CommitHash, CommitProof, CommitState},
    crypto::{AccessKey, SecureAccessKey},
    decode, encode,
    events::{
        AccountEvent, AuditData, AuditEvent, AuditLogFile, AuditProvider,
        Event, EventKind, EventReducer, ReadEvent, WriteEvent,
    },
    mpc::generate_keypair,
    search::{DocumentCount, SearchIndex},
    signer::ecdsa::Address,
    vault::{
        secret::{Secret, SecretData, SecretId, SecretMeta, SecretType},
        Gatekeeper, Summary, Vault, VaultId,
    },
    vfs::{self, File},
    Error, Result, Timestamp,
};

use tracing::{span, Level};

use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use serde_with::{serde_as, DisplayFromStr};
use tokio::{
    io::{AsyncRead, AsyncSeek},
    sync::{mpsc, Mutex, RwLock},
};

use async_trait::async_trait;

use super::{file_manager::FileProgress, search_index::UserIndex};

/// Hook executed before making changes to local storage.
///
/// Network aware accounts can use this hook to
/// synchronize the folder before changes are made.
pub type BeforeHook = Box<
    dyn Fn(
            Arc<RwLock<LocalProvider>>,
            &Summary,
            &CommitState,
        ) -> BeforeHookResult
        + Send
        + Sync,
>;

type BeforeHookResult =
    Pin<Box<dyn Future<Output = Option<CommitState>> + Send + Sync>>;

/// Read-only view of a vault created from a specific
/// event log commit.
pub struct DetachedView {
    keeper: Gatekeeper,
}

impl DetachedView {
    /// Read-only access to the vault.
    pub fn keeper(&self) -> &Gatekeeper {
        &self.keeper
    }
}

/// Options used when creating, deleting and updating
/// secrets.
#[derive(Default)]
pub struct SecretOptions {
    /// Target folder for the secret operation.
    ///
    /// If no target folder is given the current open folder
    /// will be used. When no folder is open and the target
    /// folder is not given an error will be returned.
    pub folder: Option<Summary>,
    /// Channel for file progress operations.
    pub file_progress: Option<mpsc::Sender<FileProgress>>,
}

impl From<Summary> for SecretOptions {
    fn from(value: Summary) -> Self {
        Self {
            folder: Some(value),
            file_progress: None,
        }
    }
}

#[cfg(feature = "contacts")]
/// Progress event when importing contacts.
pub enum ContactImportProgress {
    /// Progress event when the number of contacts is known.
    Ready {
        /// Total number of contacts.
        total: usize,
    },
    /// Progress event when a contact is being imported.
    Item {
        /// Label of the contact.
        label: String,
        /// Index of the contact.
        index: usize,
    },
}

/// Data about an account.
#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountData {
    /// Main account information.
    #[serde(flatten)]
    pub account: AccountInfo,
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

/// User statistics structure derived from the search index.
#[derive(Serialize, Deserialize)]
pub struct UserStatistics {
    /// Number of documents in the search index.
    pub documents: usize,
    /// Folder counts.
    pub folders: Vec<(Summary, usize)>,
    /// Tag counts.
    pub tags: HashMap<String, usize>,
    /// Types.
    pub types: HashMap<SecretType, usize>,
    /// Number of favorites.
    pub favorites: usize,
}

/// Authenticated user with folder manager.
pub struct Account {
    /// Authenticated user.
    user: AuthenticatedUser,

    /// Storage provider.
    storage: Arc<RwLock<LocalProvider>>,

    /// Storage paths.
    pub(super) paths: Arc<UserPaths>,

    /// Search index.
    index: UserIndex,

    /// Audit log for this provider.
    audit_log: Arc<RwLock<AuditLogFile>>,

    /// Hook called before making local changes.
    ///
    /// Allows network aware accounts to sync
    /// before changes are applied to the local
    /// storage.
    before_hook: Option<BeforeHook>,
}

impl Account {
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
        before_hook: Option<BeforeHook>,
    ) -> Result<(Self, ImportedAccount, NewAccount)> {
        Self::new_account_with_builder(
            account_name,
            passphrase,
            |builder| {
                builder
                    .save_passphrase(true)
                    .create_archive(true)
                    .create_authenticator(false)
                    .create_contacts(true)
                    .create_file_password(true)
            },
            data_dir,
            before_hook,
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
        before_hook: Option<BeforeHook>,
    ) -> Result<(Self, ImportedAccount, NewAccount)> {
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
        let signer = new_account.user.signer().clone();
        let mut storage = LocalProvider::new(
            signer.address()?.to_string(),
            data_dir.clone(),
        )
        .await?;

        tracing::debug!("prepared storage provider");

        let (imported_account, events) =
            storage.import_new_account(&new_account).await?;

        tracing::debug!("imported new account");

        let owner = Account::sign_in(
            new_account.user.address(),
            passphrase,
            data_dir,
            before_hook,
        )
        .await?;

        tracing::debug!("signed in new user");

        let mut audit_events = Vec::new();
        for event in events {
            let audit_event: AuditEvent =
                (new_account.user.address(), &event).into();
            audit_events.push(audit_event);
        }
        owner.append_audit_logs(audit_events).await?;

        Ok((owner, imported_account, new_account))
    }

    /// Authenticated user information.
    pub fn user(&self) -> &AuthenticatedUser {
        &self.user
    }

    /// Mutable authenticated user information.
    pub fn user_mut(&mut self) -> &mut AuthenticatedUser {
        &mut self.user
    }

    /// Storage provider.
    pub fn storage(&self) -> Arc<RwLock<LocalProvider>> {
        Arc::clone(&self.storage)
    }

    /// File storage directory.
    pub fn files_dir(&self) -> &PathBuf {
        self.paths.files_dir()
    }

    /// User identity address.
    pub fn address(&self) -> &Address {
        self.user.identity().address()
    }

    /// Get access to an account by signing in.
    pub async fn sign_in(
        address: &Address,
        passphrase: SecretString,
        data_dir: Option<PathBuf>,
        before_hook: Option<BeforeHook>,
    ) -> Result<Self> {
        let span = span!(Level::DEBUG, "sign_in");
        let _enter = span.enter();

        tracing::debug!(address = %address);

        // Ensure all paths before sign_in
        let paths =
            UserPaths::ensure_paths(address.to_string(), data_dir.clone())
                .await?;

        tracing::debug!(data_dir = ?paths.documents_dir());

        let identity_index = Arc::new(RwLock::new(SearchIndex::new()));
        let user =
            Login::sign_in(address, &paths, passphrase, identity_index)
                .await?;
        tracing::debug!("sign in success");

        // Signing key for the storage provider
        let signer = user.identity().signer().clone();
        let storage =
            LocalProvider::new(signer.address()?.to_string(), data_dir)
                .await?;

        let audit_log = Arc::new(RwLock::new(
            AuditLogFile::new(paths.audit_file()).await?,
        ));

        Ok(Self {
            user,
            paths: storage.paths(),
            storage: Arc::new(RwLock::new(storage)),
            index: UserIndex::new(),
            audit_log,
            before_hook,
        })
    }

    /// User storage paths.
    pub fn paths(&self) -> &UserPaths {
        &self.paths
    }

    /// Append to the audit log.
    async fn append_audit_logs(&self, events: Vec<AuditEvent>) -> Result<()> {
        let mut writer = self.audit_log.write().await;
        writer.append_audit_events(events).await?;
        Ok(())
    }

    /// Load the buffer of the encrypted vault for this account.
    ///
    /// Used when a client needs to authenticate other devices;
    /// it sends the encrypted identity vault and if the vault
    /// can be unlocked then we have verified that the other
    /// device knows the master password for this account.
    pub async fn identity_vault_buffer(&self) -> Result<Vec<u8>> {
        let reader = self.storage.read().await;
        let identity_path = reader.paths().identity_vault();
        Ok(vfs::read(identity_path).await?)
    }

    /// Compute the user statistics.
    pub async fn statistics(&self) -> UserStatistics {
        let search_index = self.index.search();
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

        UserStatistics {
            documents,
            folders,
            types,
            tags: count.tags().clone(),
            favorites: count.favorites(),
        }
    }

    /// Account data.
    pub async fn account_data(&self) -> Result<AccountData> {
        let reader = self.storage.read().await;
        Ok(AccountData {
            account: self.user.account().clone(),
            identity: self.user.identity().recipient().to_string(),
            folders: reader.state().summaries().to_vec(),
        })
    }

    /// Verify an access key for this account.
    pub async fn verify(&self, key: &AccessKey) -> bool {
        self.user.verify(key).await
    }

    /// Delete the account for this user and sign out.
    pub async fn delete_account(&mut self) -> Result<()> {
        let event = self.user.delete_account(&self.paths).await?;
        let audit_event: AuditEvent = (self.address(), &event).into();
        self.append_audit_logs(vec![audit_event]).await?;
        self.sign_out().await;
        Ok(())
    }

    /// Rename this account.
    pub async fn rename_account(
        &mut self,
        account_name: String,
    ) -> Result<()> {
        Ok(self.user.rename_account(&self.paths, account_name).await?)
    }

    /// Try to find a folder using a predicate.
    pub async fn find<P>(&self, predicate: P) -> Option<Summary>
    where
        P: FnMut(&&Summary) -> bool,
    {
        let reader = self.storage.read().await;
        reader.state().find(predicate).cloned()
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

    /// List folders.
    pub async fn list_folders(&mut self) -> Result<Vec<Summary>> {
        let mut writer = self.storage.write().await;
        let folders = writer.load_vaults().await?.to_vec();
        Ok(folders)
    }

    /// Sign out of the account.
    pub async fn sign_out(&mut self) {
        let span = span!(Level::DEBUG, "sign_out");
        let _enter = span.enter();

        tracing::debug!(address = %self.address());

        /*
        // Close all the websocket connections
        {
            let mut listeners = self.listeners.lock().await;
            for handle in listeners.drain(..) {
                tracing::debug!("close websocket");
                handle.close();
            }
        }
        */

        // Close the currently open vaul in the local storage
        let mut writer = self.storage.write().await;
        writer.close_vault();

        // Remove the search index
        self.index.clear().await;

        // Forget authenticated user information
        self.user.sign_out().await;
    }

    /// Create a folder.
    pub async fn create_folder(
        &mut self,
        name: String,
    ) -> Result<(Summary, Event)> {
        let passphrase = DelegatedPassphrase::generate_vault_passphrase()?;
        let key = AccessKey::Password(passphrase);
        let (buffer, _, summary) = {
            let mut writer = self.storage.write().await;
            writer.create_vault(name, Some(key.clone())).await?
        };

        let secret_key = self.user.identity().signer().to_bytes();
        let secure_key =
            SecureAccessKey::encrypt(&key, secret_key, None).await?;

        DelegatedPassphrase::save_vault_passphrase(
            self.user.identity().keeper(),
            summary.id(),
            key,
        )
        .await?;

        let event = Event::Account(AccountEvent::CreateFolder(*summary.id()));
        let audit_event: AuditEvent = (self.address(), &event).into();
        self.append_audit_logs(vec![audit_event]).await?;

        let options = SecretOptions {
            folder: Some(summary),
            ..Default::default()
        };

        let (summary, before_last_commit, before_commit_proof) =
            self.compute_folder_state(&options, false).await?;

        let event =
            Event::Write(*summary.id(), WriteEvent::CreateVault(buffer));

        Ok((summary, event))
    }

    /// Delete a folder.
    pub async fn delete_folder(
        &mut self,
        summary: &Summary,
    ) -> Result<Event> {
        let options = SecretOptions {
            folder: Some(summary.clone()),
            ..Default::default()
        };
        let (summary, before_last_commit, before_commit_proof) =
            self.compute_folder_state(&options, false).await?;

        let event = {
            let mut writer = self.storage.write().await;
            writer.remove_vault(&summary).await?
        };
        DelegatedPassphrase::remove_vault_passphrase(
            self.user.identity().keeper(),
            summary.id(),
        )
        .await?;
        self.index
            .remove_folder_from_search_index(summary.id())
            .await;
        self.delete_folder_files(&summary).await?;

        let event = Event::Write(*summary.id(), event);
        let audit_event: AuditEvent = (self.address(), &event).into();
        self.append_audit_logs(vec![audit_event]).await?;

        Ok(event)
    }

    /// Rename a folder.
    pub async fn rename_folder(
        &mut self,
        summary: &Summary,
        name: String,
    ) -> Result<Event> {
        let options = SecretOptions {
            folder: Some(summary.clone()),
            ..Default::default()
        };
        let (summary, before_last_commit, before_commit_proof) =
            self.compute_folder_state(&options, false).await?;

        // Update the provider
        let event = {
            let mut writer = self.storage.write().await;
            writer.set_vault_name(&summary, &name).await?
        };

        let event = Event::Write(*summary.id(), event);
        let audit_event: AuditEvent = (self.address(), &event).into();
        self.append_audit_logs(vec![audit_event]).await?;

        Ok(event)
    }

    /// Export a folder (vault).
    pub async fn export_folder<P: AsRef<Path>>(
        &mut self,
        path: P,
        summary: &Summary,
        new_key: AccessKey,
        save_key: bool,
    ) -> Result<()> {
        let buffer = AccountBackup::export_vault(
            self.address(),
            &self.paths,
            self.user.identity().keeper(),
            summary.id(),
            new_key.clone(),
        )
        .await?;

        let local_accounts = LocalAccounts::new(&self.paths);

        if save_key {
            let default_summary = self
                .default_folder()
                .await
                .ok_or_else(|| Error::NoDefaultFolder)?;

            let _passphrase = DelegatedPassphrase::find_vault_passphrase(
                self.user.identity().keeper(),
                default_summary.id(),
            )
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

            let (vault, _) = local_accounts
                .find_local_vault(default_summary.id(), false)
                .await?;

            self.add_secret(
                meta,
                secret,
                vault.summary().clone().into(),
                false,
            )
            .await?;
        }

        vfs::write(path, buffer).await?;

        let audit_event = AuditEvent::new(
            EventKind::ExportVault,
            self.address().clone(),
            Some(AuditData::Vault(*summary.id())),
        );
        self.append_audit_logs(vec![audit_event]).await?;

        Ok(())
    }

    /// Import a folder (vault) from a file.
    pub async fn import_folder<P: AsRef<Path>>(
        &mut self,
        path: P,
        key: AccessKey,
        overwrite: bool,
    ) -> Result<(Summary, Event)> {
        let buffer = vfs::read(path.as_ref()).await?;
        self.import_folder_buffer(&buffer, key, overwrite).await
    }

    /// Import a folder (vault) from a buffer.
    pub async fn import_folder_buffer(
        &mut self,
        buffer: impl AsRef<[u8]>,
        key: AccessKey,
        overwrite: bool,
    ) -> Result<(Summary, Event)> {
        let mut vault: Vault = decode(buffer.as_ref()).await?;

        // Need to verify the passphrase
        vault.verify(&key).await?;

        let local_accounts = LocalAccounts::new(&self.paths);

        // Check for existing identifier
        let vaults = local_accounts.list_local_vaults(false).await?;
        let existing_id =
            vaults.iter().find(|(s, _)| s.id() == vault.summary().id());

        let default_vault =
            vaults.iter().find(|(s, _)| s.flags().is_default());

        let remove_default_flag = !overwrite
            && default_vault.is_some()
            && vault.summary().flags().is_default();

        // If we are not overwriting and the identifier already exists
        // then we need to rotate the identifier
        let has_id_changed = if existing_id.is_some() && !overwrite {
            vault.rotate_identifier();
            true
        } else {
            false
        };

        let existing_name = vaults
            .iter()
            .find(|(s, _)| s.name() == vault.summary().name());

        let has_name_changed = if existing_name.is_some() && !overwrite {
            let name = format!(
                "{} ({})",
                vault.summary().name(),
                vault.summary().id()
            );
            vault.set_name(name);
            true
        } else {
            false
        };

        if remove_default_flag {
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
            let mut writer = self.storage.write().await;
            writer.import_vault(buffer.as_ref()).await?
        };

        // If we are overwriting then we must remove the existing
        // vault passphrase so we can save it using the passphrase
        // assigned when exporting the folder
        if overwrite {
            DelegatedPassphrase::remove_vault_passphrase(
                self.user.identity().keeper(),
                summary.id(),
            )
            .await?;
        }

        DelegatedPassphrase::save_vault_passphrase(
            self.user.identity().keeper(),
            summary.id(),
            key.clone(),
        )
        .await?;

        // If overwriting remove old entries from the index
        if overwrite {
            // If we are overwriting and the current vault
            // is loaded into memory we must close it so
            // the UI does not show stale in-memory data
            {
                let mut writer = self.storage.write().await;
                let is_current = if let Some(current) = writer.current() {
                    current.id() == summary.id()
                } else {
                    false
                };

                if is_current {
                    writer.close_vault();
                }
            }
            // Clean entries from the search index
            self.index
                .remove_folder_from_search_index(summary.id())
                .await;
        }

        // Ensure the imported secrets are in the search index
        self.index.add_folder_to_search_index(vault, key).await?;

        let event = Event::Write(*summary.id(), event);
        let audit_event: AuditEvent = (self.address(), &event).into();
        self.append_audit_logs(vec![audit_event]).await?;

        let options = SecretOptions {
            folder: Some(summary.clone()),
            ..Default::default()
        };
        let (summary, before_last_commit, before_commit_proof) =
            self.compute_folder_state(&options, false).await?;

        Ok((summary, event))
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
            let reader = self.storage.read().await;
            if let Some(current) = reader.current() {
                if current.id() == summary.id() {
                    return Ok(());
                }
            }
        }

        let passphrase = DelegatedPassphrase::find_vault_passphrase(
            self.user.identity().keeper(),
            summary.id(),
        )
        .await?;

        let index = Arc::clone(&self.index.search_index);

        let event = {
            let mut writer = self.storage.write().await;
            writer
                .open_vault(summary, passphrase.into(), Some(index))
                .await?
        };

        let event = Event::Read(*summary.id(), event);

        if audit {
            let audit_event: AuditEvent = (self.address(), &event).into();
            self.append_audit_logs(vec![audit_event]).await?;
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
        options: &SecretOptions,
        apply_changes: bool,
    ) -> Result<(Summary, CommitHash, CommitProof)> {
        let (folder, last_commit, mut commit_proof) = {
            let reader = self.storage.read().await;
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
            let storage = self.storage();
            if let Some(before_hook) = &self.before_hook {
                let before_result = (before_hook)(
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

        Ok((folder, last_commit, commit_proof))
    }

    /// Create a secret in the current open folder or a specific folder.
    pub async fn create_secret(
        &mut self,
        meta: SecretMeta,
        secret: Secret,
        options: SecretOptions,
    ) -> Result<(SecretId, Event)> {
        let (_folder, before_last_commit, before_commit_proof) =
            self.compute_folder_state(&options, true).await?;

        let (id, event, folder) =
            self.add_secret(meta, secret, options, true).await?;

        Ok((id, event))
    }

    async fn add_secret(
        &mut self,
        meta: SecretMeta,
        secret: Secret,
        mut options: SecretOptions,
        audit: bool,
    ) -> Result<(SecretId, Event, Summary)> {
        let folder = {
            let reader = self.storage.read().await;
            options
                .folder
                .or_else(|| reader.current().map(|g| g.summary().clone()))
                .ok_or(Error::NoOpenFolder)?
        };

        self.open_folder(&folder).await?;

        if let Secret::Pem { certificates, .. } = &secret {
            if certificates.is_empty() {
                return Err(Error::PemEncoding);
            }
        }

        let event = {
            let mut writer = self.storage.write().await;
            writer.create_secret(meta.clone(), secret.clone()).await?
        };

        let id = if let WriteEvent::CreateSecret(id, _) = &event {
            *id
        } else {
            unreachable!();
        };

        let secret_data = SecretData {
            id: Some(id),
            meta,
            secret,
        };

        let current_folder = {
            let reader = self.storage.read().await;
            reader
                .current()
                .as_ref()
                .map(|g| g.summary().clone())
                .ok_or(Error::NoOpenFolder)?
        };

        self.create_files(
            &current_folder,
            secret_data,
            &mut options.file_progress,
        )
        .await?;

        let event = Event::Write(*folder.id(), event);
        if audit {
            let audit_event: AuditEvent = (self.address(), &event).into();
            self.append_audit_logs(vec![audit_event]).await?;
        }

        Ok((id, event, folder))
    }

    /// Read a secret in the current open folder.
    pub async fn read_secret(
        &mut self,
        secret_id: &SecretId,
        folder: Option<Summary>,
    ) -> Result<(SecretData, ReadEvent)> {
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
    ) -> Result<(SecretData, ReadEvent)> {
        let folder = {
            let reader = self.storage.read().await;
            folder
                .or_else(|| reader.current().map(|g| g.summary().clone()))
                .ok_or(Error::NoOpenFolder)?
        };

        self.open_folder(&folder).await?;

        let (meta, secret, read_event) = {
            let mut writer = self.storage.write().await;
            writer.read_secret(secret_id).await?
        };

        if audit {
            let event = Event::Read(*folder.id(), read_event.clone());
            let audit_event: AuditEvent = (self.address(), &event).into();
            self.append_audit_logs(vec![audit_event]).await?;
        }

        Ok((
            SecretData {
                id: Some(*secret_id),
                meta,
                secret,
            },
            read_event,
        ))
    }

    /// Update a file secret.
    ///
    /// If the secret is not the `File` variant that it will be
    /// converted to a `File` variant to ensure this is only called
    /// on file secrets.
    pub async fn update_file<P: AsRef<Path>>(
        &mut self,
        secret_id: &SecretId,
        meta: SecretMeta,
        path: P,
        options: SecretOptions,
        destination: Option<&Summary>,
    ) -> Result<(SecretId, Event)> {
        let path = path.as_ref().to_path_buf();
        let secret: Secret = path.try_into()?;
        self.update_secret(
            secret_id,
            meta,
            Some(secret),
            options,
            destination,
        )
        .await
    }

    /// Update a secret in the current open folder or a specific folder.
    pub async fn update_secret(
        &mut self,
        secret_id: &SecretId,
        meta: SecretMeta,
        secret: Option<Secret>,
        //folder: Option<Summary>,
        mut options: SecretOptions,
        destination: Option<&Summary>,
    ) -> Result<(SecretId, Event)> {
        let (folder, before_last_commit, before_commit_proof) =
            self.compute_folder_state(&options, true).await?;

        self.open_folder(&folder).await?;

        let (old_secret_data, _) =
            self.get_secret(secret_id, None, false).await?;

        let secret_data = if let Some(secret) = secret {
            SecretData {
                id: Some(*secret_id),
                meta,
                secret,
            }
        } else {
            let mut secret_data = old_secret_data.clone();
            secret_data.meta = meta;
            secret_data
        };

        let event = self
            .write_secret(secret_id, secret_data.clone(), None, true)
            .await?;

        // Must update the files before moving so checksums are correct
        self.update_files(
            &folder,
            &folder,
            &old_secret_data,
            secret_data,
            &mut options.file_progress,
        )
        .await?;

        let id = if let Some(to) = destination.as_ref() {
            let (new_id, _) =
                self.mv_secret(secret_id, &folder, to, options).await?;
            new_id
        } else {
            *secret_id
        };

        Ok((id, event))
    }

    /// Write a secret in the current open folder or a specific folder.
    ///
    /// Unlike `update_secret()` this function does not support moving
    /// between folders or managing external files which allows us
    /// to avoid recursion when handling embedded file secrets which
    /// require rewriting the secret once the files have been encrypted.
    pub(crate) async fn write_secret(
        &mut self,
        secret_id: &SecretId,
        secret_data: SecretData,
        folder: Option<Summary>,
        audit: bool,
    ) -> Result<Event> {
        let folder = {
            let reader = self.storage.read().await;
            folder
                .or_else(|| reader.current().map(|g| g.summary().clone()))
                .ok_or(Error::NoOpenFolder)?
        };
        self.open_folder(&folder).await?;

        if let Secret::Pem { certificates, .. } = &secret_data.secret {
            if certificates.is_empty() {
                return Err(Error::PemEncoding);
            }
        }

        let event = {
            let mut writer = self.storage.write().await;
            writer.update_secret(secret_id, secret_data).await?
        };

        let event = Event::Write(*folder.id(), event);
        if audit {
            let audit_event: AuditEvent = (self.address(), &event).into();
            self.append_audit_logs(vec![audit_event]).await?;
        }

        Ok(event)
    }

    /// Move a secret between folders.
    pub async fn move_secret(
        &mut self,
        secret_id: &SecretId,
        from: &Summary,
        to: &Summary,
        options: SecretOptions,
    ) -> Result<(SecretId, Event)> {
        self.mv_secret(secret_id, from, to, options).await
    }

    async fn mv_secret(
        &mut self,
        secret_id: &SecretId,
        from: &Summary,
        to: &Summary,
        mut options: SecretOptions,
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
        let delete_event = self.remove_secret(secret_id, None, false).await?;

        self.move_files(
            &move_secret_data,
            from.id(),
            to.id(),
            secret_id,
            &new_id,
            None,
            &mut options.file_progress,
        )
        .await?;

        let (_, create_event) = create_event.try_into()?;
        let (_, delete_event) = delete_event.try_into()?;

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
        self.append_audit_logs(vec![audit_event]).await?;

        Ok((new_id, event))
    }

    /// Delete a secret and remove any external files.
    pub async fn delete_secret(
        &mut self,
        secret_id: &SecretId,
        mut options: SecretOptions,
    ) -> Result<Event> {
        let (folder, before_last_commit, before_commit_proof) =
            self.compute_folder_state(&options, true).await?;

        self.open_folder(&folder).await?;

        let (secret_data, _) =
            self.get_secret(secret_id, None, false).await?;
        let event = self.remove_secret(secret_id, None, true).await?;

        self.delete_files(
            &folder,
            &secret_data,
            None,
            &mut options.file_progress,
        )
        .await?;

        Ok(event)
    }

    /// Remove a secret.
    ///
    /// Any external files for the secret are left intact.
    pub(crate) async fn remove_secret(
        &mut self,
        secret_id: &SecretId,
        folder: Option<Summary>,
        audit: bool,
    ) -> Result<Event> {
        let folder = {
            let reader = self.storage.read().await;
            folder
                .or_else(|| reader.current().map(|g| g.summary().clone()))
                .ok_or(Error::NoOpenFolder)?
        };

        self.open_folder(&folder).await?;

        let event = {
            let mut writer = self.storage.write().await;
            writer.delete_secret(secret_id).await?
        };

        let event = Event::Write(*folder.id(), event);
        if audit {
            let audit_event: AuditEvent = (self.address(), &event).into();
            self.append_audit_logs(vec![audit_event]).await?;
        }
        Ok(event)
    }

    /// Move a secret to the archive.
    ///
    /// An archive folder must exist.
    pub async fn archive(
        &mut self,
        from: &Summary,
        secret_id: &SecretId,
        options: SecretOptions,
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
    /// The secret must be inside a folder with the archive flag set.
    pub async fn unarchive(
        &mut self,
        from: &Summary,
        secret_id: &SecretId,
        secret_meta: &SecretMeta,
        options: SecretOptions,
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

    /// Search index reference.
    pub fn index(&self) -> &UserIndex {
        &self.index
    }

    /// Mutable search index reference.
    pub fn index_mut(&mut self) -> &mut UserIndex {
        &mut self.index
    }

    /// Initialize the search index.
    ///
    /// This should be called after a user has signed in to
    /// create the initial search index.
    pub async fn initialize_search_index(
        &mut self,
    ) -> Result<(DocumentCount, Vec<Summary>)> {
        // Find the id of an archive folder
        let summaries = {
            let summaries = self.list_folders().await?;
            let mut archive: Option<VaultId> = None;
            for summary in &summaries {
                if summary.flags().is_archive() {
                    archive = Some(*summary.id());
                    break;
                }
            }
            let mut writer = self.index.search_index.write().await;
            writer.set_archive_id(archive);
            summaries
        };
        Ok((self.build_search_index().await?, summaries))
    }

    /// Build the search index for all folders.
    pub async fn build_search_index(&mut self) -> Result<DocumentCount> {
        // Clear search index first
        self.index.clear().await;

        // Build search index from all the vaults
        let summaries = self.list_folders().await?;
        for summary in summaries {
            // Must open the vault so the provider state unlocks
            // the vault
            self.open_vault(&summary, false).await?;

            {
                let mut writer = self.storage.write().await;
                // Add the vault meta data to the search index
                writer.create_search_index().await?;
                // Close the vault as we are done for now
                writer.close_vault();
            }
        }

        Ok(self.index.document_count().await)
    }

    /// Write a zip archive containing all the secrets
    /// for the account unencrypted.
    ///
    /// Used to migrate an account to another provider.
    #[cfg(feature = "migrate")]
    pub async fn export_unsafe_archive<P: AsRef<Path>>(
        &self,
        path: P,
    ) -> Result<()> {
        use sos_migrate::export::PublicExport;
        use std::io::Cursor;

        let local_accounts = LocalAccounts::new(&self.paths);

        let mut archive = Vec::new();
        let mut migration = PublicExport::new(Cursor::new(&mut archive));
        let vaults = local_accounts.list_local_vaults(false).await?;

        for (summary, _) in vaults {
            let (vault, _) =
                local_accounts.find_local_vault(summary.id(), false).await?;
            let vault_passphrase =
                DelegatedPassphrase::find_vault_passphrase(
                    self.user.identity().keeper(),
                    summary.id(),
                )
                .await?;

            let mut keeper = Gatekeeper::new(vault, None);
            keeper.unlock(vault_passphrase.into()).await?;

            // Add the secrets for the vault to the migration
            migration.add(&keeper).await?;

            keeper.lock();
        }

        let mut files = HashMap::new();
        let buffer = serde_json::to_vec_pretty(self.user.account())?;
        files.insert("account.json", buffer.as_slice());
        migration.append_files(files).await?;
        migration.finish().await?;

        vfs::write(path.as_ref(), &archive).await?;

        let audit_event = AuditEvent::new(
            EventKind::ExportUnsafe,
            self.address().clone(),
            None,
        );
        self.append_audit_logs(vec![audit_event]).await?;

        Ok(())
    }

    /// Import secrets from another app.
    #[cfg(feature = "migrate")]
    pub async fn import_file(
        &mut self,
        target: ImportTarget,
    ) -> Result<Summary> {
        use sos_migrate::import::csv::{
            bitwarden::BitwardenCsv, chrome::ChromePasswordCsv,
            dashlane::DashlaneCsvZip, firefox::FirefoxPasswordCsv,
            macos::MacPasswordCsv, one_password::OnePasswordCsv,
        };

        let (event, summary) = match target.format {
            ImportFormat::OnePasswordCsv => {
                self.import_csv(
                    target.path,
                    target.folder_name,
                    OnePasswordCsv,
                )
                .await?
            }
            ImportFormat::DashlaneZip => {
                self.import_csv(
                    target.path,
                    target.folder_name,
                    DashlaneCsvZip,
                )
                .await?
            }
            ImportFormat::BitwardenCsv => {
                self.import_csv(target.path, target.folder_name, BitwardenCsv)
                    .await?
            }
            ImportFormat::ChromeCsv => {
                self.import_csv(
                    target.path,
                    target.folder_name,
                    ChromePasswordCsv,
                )
                .await?
            }
            ImportFormat::FirefoxCsv => {
                self.import_csv(
                    target.path,
                    target.folder_name,
                    FirefoxPasswordCsv,
                )
                .await?
            }
            ImportFormat::MacosCsv => {
                self.import_csv(
                    target.path,
                    target.folder_name,
                    MacPasswordCsv,
                )
                .await?
            }
        };

        let audit_event = AuditEvent::new(
            EventKind::ImportUnsafe,
            self.address().clone(),
            None,
        );
        let create_event: AuditEvent = (self.address(), &event).into();
        self.append_audit_logs(vec![audit_event, create_event])
            .await?;

        Ok(summary)
    }

    /*
    /// Generic CSV import implementation.
    #[cfg(feature = "migrate")]
    async fn import_csv<P: AsRef<Path>>(
        &mut self,
        path: P,
        folder_name: String,
        converter: impl Convert<Input = PathBuf>,
    ) -> Result<(Event, Summary)> {
        use sos_sdk::vault::VaultBuilder;

        let local_accounts = LocalAccounts::new(&self.paths);

        let vaults = local_accounts.list_local_vaults(false).await?;
        let existing_name =
            vaults.iter().find(|(s, _)| s.name() == folder_name);

        let vault_passphrase =
            DelegatedPassphrase::generate_vault_passphrase()?;

        let vault_id = VaultId::new_v4();
        let name = if existing_name.is_some() {
            format!("{} ({})", folder_name, vault_id)
        } else {
            folder_name
        };

        let vault = VaultBuilder::new()
            .id(vault_id)
            .public_name(name)
            .password(vault_passphrase.clone(), None)
            .await?;

        // Parse the CSV records into the vault
        let vault = converter
            .convert(
                path.as_ref().to_path_buf(),
                vault,
                vault_passphrase.clone().into(),
            )
            .await?;

        let buffer = encode(&vault).await?;
        let (event, summary) = {
            let mut writer = self.storage.write().await;
            writer.import_vault(buffer).await?
        };

        DelegatedPassphrase::save_vault_passphrase(
            self.user.identity().keeper(),
            vault.id(),
            vault_passphrase.clone().into(),
        )
        .await?;

        // Ensure the imported secrets are in the search index
        self.index_mut()
            .add_folder_to_search_index(vault, vault_passphrase.into())
            .await?;

        let event = Event::Write(*summary.id(), event);
        Ok((event, summary))
    }
    */

    /// Get an avatar JPEG image for a contact in the current
    /// open folder.
    #[cfg(feature = "contacts")]
    pub async fn load_avatar(
        &mut self,
        secret_id: &SecretId,
        folder: Option<Summary>,
    ) -> Result<Option<Vec<u8>>> {
        let (data, _) = self.read_secret(secret_id, folder).await?;
        if let Secret::Contact { vcard, .. } = &data.secret {
            let jpeg = if let Ok(mut jpegs) = vcard.parse_photo_jpeg() {
                if !jpegs.is_empty() {
                    Some(jpegs.remove(0))
                } else {
                    None
                }
            } else {
                None
            };
            return Ok(jpeg);
        }
        Ok(None)
    }

    /// Export a contact secret to vCard file.
    #[cfg(feature = "contacts")]
    pub async fn export_vcard_file<P: AsRef<Path>>(
        &mut self,
        path: P,
        secret_id: &SecretId,
        folder: Option<Summary>,
    ) -> Result<()> {
        let current_folder = {
            let reader = self.storage.read().await;
            folder
                .as_ref()
                .or_else(|| reader.current().map(|g| g.summary()))
                .ok_or(Error::NoOpenFolder)?
                .clone()
        };

        let (data, _) = self.get_secret(secret_id, folder, false).await?;
        if let Secret::Contact { vcard, .. } = &data.secret {
            let content = vcard.to_string();
            vfs::write(&path, content).await?;
        } else {
            return Err(Error::NotContact);
        }

        let audit_event = AuditEvent::new(
            EventKind::ExportContacts,
            self.address().clone(),
            Some(AuditData::Secret(*current_folder.id(), *secret_id)),
        );
        self.append_audit_logs(vec![audit_event]).await?;

        Ok(())
    }

    /// Export all contacts to a single vCard.
    #[cfg(feature = "contacts")]
    pub async fn export_all_vcards<P: AsRef<Path>>(
        &mut self,
        path: P,
    ) -> Result<()> {
        let local_accounts = LocalAccounts::new(&self.paths);

        let contacts = self
            .contacts_folder()
            .await
            .ok_or_else(|| Error::NoContactsFolder)?;

        let contacts_passphrase = DelegatedPassphrase::find_vault_passphrase(
            self.user.identity().keeper(),
            contacts.id(),
        )
        .await?;
        let (vault, _) = local_accounts
            .find_local_vault(contacts.id(), false)
            .await?;
        let mut keeper = Gatekeeper::new(vault, None);
        keeper.unlock(contacts_passphrase.into()).await?;

        let mut vcf = String::new();
        let keys: Vec<&SecretId> = keeper.vault().keys().collect();
        for key in keys {
            if let Some((_, Secret::Contact { vcard, .. }, _)) =
                keeper.read(key).await?
            {
                vcf.push_str(&vcard.to_string());
            }
        }
        vfs::write(path, vcf.as_bytes()).await?;

        let audit_event = AuditEvent::new(
            EventKind::ExportContacts,
            self.address().clone(),
            None,
        );
        self.append_audit_logs(vec![audit_event]).await?;

        Ok(())
    }

    /// Import vCards from a string buffer.
    #[cfg(feature = "contacts")]
    pub async fn import_vcard(
        &mut self,
        content: &str,
        progress: impl Fn(ContactImportProgress),
    ) -> Result<()> {
        use crate::vcard4::parse;

        let current = {
            let reader = self.storage.read().await;
            reader.current().map(|g| g.summary().clone())
        };

        let contacts = self
            .contacts_folder()
            .await
            .ok_or_else(|| Error::NoContactsFolder)?;
        self.open_vault(&contacts, false).await?;

        let cards = parse(content)?;

        progress(ContactImportProgress::Ready { total: cards.len() });

        for (index, vcard) in cards.into_iter().enumerate() {
            let label = vcard
                .formatted_name
                .get(0)
                .as_ref()
                .map(|s| s.to_string())
                .unwrap_or_default();
            let secret = Secret::Contact {
                vcard: Box::new(vcard),
                user_data: Default::default(),
            };

            progress(ContactImportProgress::Item {
                label: label.clone(),
                index,
            });

            let meta = SecretMeta::new(label, secret.kind());
            self.create_secret(meta, secret, Default::default()).await?;
        }

        if let Some(folder) = current {
            self.open_vault(&folder, false).await?;
        }

        let audit_event = AuditEvent::new(
            EventKind::ImportContacts,
            self.address().clone(),
            None,
        );
        self.append_audit_logs(vec![audit_event]).await?;

        Ok(())
    }

    /// Create a backup archive containing the
    /// encrypted data for the account.
    pub async fn export_backup_archive<P: AsRef<Path>>(
        &self,
        path: P,
    ) -> Result<()> {
        AccountBackup::export_archive_file(path, self.address(), &self.paths)
            .await?;

        let audit_event = AuditEvent::new(
            EventKind::ExportBackupArchive,
            self.address().clone(),
            None,
        );
        self.append_audit_logs(vec![audit_event]).await?;

        Ok(())
    }

    /// Read the inventory from an archive.
    pub async fn restore_archive_inventory<
        R: AsyncRead + AsyncSeek + Unpin,
    >(
        buffer: R,
    ) -> Result<Inventory> {
        let mut inventory =
            AccountBackup::restore_archive_inventory(buffer).await?;
        let accounts = LocalAccounts::list_accounts(None).await?;
        let exists_local = accounts
            .iter()
            .any(|account| account.address() == &inventory.manifest.address);
        inventory.exists_local = exists_local;
        Ok(inventory)
    }

    /// Import from an archive file.
    pub async fn restore_backup_archive<P: AsRef<Path>>(
        owner: Option<&mut Account>,
        path: P,
        options: RestoreOptions,
        data_dir: Option<PathBuf>,
    ) -> Result<AccountInfo> {
        let file = File::open(path).await?;
        let (account, owner) =
            Self::restore_archive_reader(owner, file, options, data_dir)
                .await?;

        if let Some(owner) = owner {
            let audit_event = AuditEvent::new(
                EventKind::ImportBackupArchive,
                owner.address().clone(),
                None,
            );
            owner.append_audit_logs(vec![audit_event]).await?;
        }

        Ok(account)
    }

    /// Import from an archive buffer.
    async fn restore_archive_reader<R: AsyncRead + AsyncSeek + Unpin>(
        mut owner: Option<&mut Account>,
        buffer: R,
        mut options: RestoreOptions,
        data_dir: Option<PathBuf>,
    ) -> Result<(AccountInfo, Option<&mut Account>)> {
        let files_dir = if let Some(owner) = owner.as_ref() {
            ExtractFilesLocation::Path(owner.files_dir().clone())
        } else {
            ExtractFilesLocation::Builder(Box::new(|address| {
                let data_dir = UserPaths::data_dir().unwrap();
                let paths = UserPaths::new(data_dir, address);
                Some(paths.files_dir().to_owned())
            }))
        };

        options.files_dir = Some(files_dir);

        let (targets, account) = AccountBackup::restore_archive_buffer(
            buffer,
            options,
            owner.is_some(),
            data_dir,
        )
        .await?;

        if let Some(owner) = owner.as_mut() {
            {
                let mut writer = owner.storage.write().await;
                writer.restore_archive(&targets).await?;
            }
            owner.build_search_index().await?;
        }

        Ok((account, owner))
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
        let reader = self.storage.read().await;
        let cache = reader.cache();
        let log_file = cache
            .get(summary.id())
            .ok_or_else(|| Error::CacheNotAvailable(*summary.id()))?;

        let passphrase = DelegatedPassphrase::find_vault_passphrase(
            self.user.identity().keeper(),
            summary.id(),
        )
        .await?;

        let vault = EventReducer::new_until_commit(commit)
            .reduce(log_file)
            .await?
            .build()
            .await?;

        let mut keeper = Gatekeeper::new(
            vault,
            Some(Arc::new(RwLock::new(SearchIndex::new()))),
        );
        keeper.unlock(passphrase).await?;
        keeper.create_search_index().await?;
        Ok(DetachedView { keeper })
    }

    /// Get the root commit hash for a folder.
    pub async fn root_commit(&self, summary: &Summary) -> Result<CommitHash> {
        let reader = self.storage.read().await;
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
}

impl From<Account> for Arc<RwLock<LocalProvider>> {
    fn from(value: Account) -> Self {
        value.storage
    }
}
