//! Local account storage and search index.
use crate::{
    convert::CipherComparison, Account, AccountBuilder, AccountChange,
    AccountData, Error, FolderChange, FolderCreate, FolderDelete, Result,
    SecretChange, SecretDelete, SecretInsert, SecretMove,
};
use async_trait::async_trait;
use indexmap::IndexSet;
use secrecy::SecretString;
use sos_backend::{
    compact::compact_folder, AccessPoint, BackendTarget, Folder, StorageError,
};
use sos_client_storage::{
    AccessOptions, ClientAccountStorage, ClientBaseStorage,
    ClientDeviceStorage, ClientFolderStorage, ClientSecretStorage,
    ClientStorage, NewFolderOptions,
};
use sos_core::{
    commit::{CommitHash, CommitState},
    crypto::{AccessKey, Cipher, KeyDerivation},
    decode,
    device::{DevicePublicKey, TrustedDevice},
    encode,
    events::{
        changes_feed, AccountEvent, DeviceEvent, Event, EventKind, EventLog,
        EventRecord, LocalChangeEvent, ReadEvent, WriteEvent,
    },
    AccountId, AccountRef, AuthenticationError, FolderRef, Paths, SecretId,
    UtcDateTime, VaultCommit, VaultFlags, VaultId,
};
use sos_filesystem::write_exclusive;
use sos_login::{
    device::{DeviceManager, DeviceSigner},
    DelegatedAccess, FolderKeys, Identity, PublicIdentity,
};
use sos_reducers::FolderReducer;
use sos_sync::{CreateSet, StorageEventLogs};
use sos_vault::{
    secret::{Secret, SecretMeta, SecretPath, SecretRow, SecretType},
    BuilderCredentials, Header, SecretAccess, Summary, Vault, VaultBuilder,
};
use sos_vfs as vfs;
use std::{
    borrow::Cow,
    collections::HashMap,
    path::{Path, PathBuf},
    sync::Arc,
};
use tokio::sync::RwLock;

#[cfg(feature = "search")]
use {
    crate::DetachedView,
    sos_search::{
        AccountStatistics, ArchiveFilter, Document, DocumentCount,
        DocumentView, QueryFilter, SearchIndex,
    },
};

#[cfg(feature = "audit")]
use {
    sos_audit::{AuditData, AuditEvent},
    sos_backend::audit::append_audit_events,
};

#[cfg(feature = "files")]
use sos_external_files::FileMutationEvent;

#[cfg(feature = "contacts")]
use crate::ContactImportProgress;

#[cfg(feature = "migrate")]
use sos_migrate::{
    export::PublicExport,
    import::{
        csv::{
            bitwarden::BitwardenCsv, chrome::ChromePasswordCsv,
            dashlane::DashlaneCsvZip, firefox::FirefoxPasswordCsv,
            macos::MacPasswordCsv, one_password::OnePasswordCsv,
        },
        ImportFormat, ImportTarget,
    },
    Convert,
};

#[cfg(feature = "clipboard")]
use {
    crate::{ClipboardCopyRequest, ClipboardTextFormat},
    xclipboard::Clipboard,
};

/// User account backed by a backend target for storage.
///
/// Many functions require that the account is authenticated and will
/// error if the account is not authenticated; to authenticate a
/// user call [Account::sign_in].
pub struct LocalAccount {
    /// Account identifier.
    account_id: AccountId,

    /// Storage paths.
    paths: Arc<Paths>,

    /// Storage provider.
    pub(super) storage: ClientStorage,

    /// Backend target for the storage provider.
    target: BackendTarget,
}

impl LocalAccount {
    /// Prepare an account for sign in.
    ///
    /// After preparing an account call `sign_in`
    /// to authenticate a user.
    pub async fn new_unauthenticated(
        account_id: AccountId,
        mut target: BackendTarget,
    ) -> Result<Self> {
        target = target.with_account_id(&account_id);

        let storage =
            ClientStorage::new_unauthenticated(target.clone(), &account_id)
                .await?;

        Ok(Self {
            account_id,
            storage,
            paths: target.paths(),
            target,
        })
    }

    /// Create a new account with the given
    /// name, password and backend target.
    ///
    /// Uses standard flags for the account builder for
    /// more control of the created account use
    /// [LocalAccount::new_account_with_builder].
    pub async fn new_account(
        account_name: String,
        password: SecretString,
        target: BackendTarget,
    ) -> Result<Self> {
        Self::new_account_with_builder(
            account_name,
            password,
            target,
            |builder| builder.create_file_password(true),
        )
        .await
    }

    /// Create a new account with the given
    /// name, password and backend target modifying the
    /// account builder.
    pub async fn new_account_with_builder(
        account_name: String,
        password: SecretString,
        mut target: BackendTarget,
        builder: impl Fn(AccountBuilder) -> AccountBuilder + Send,
    ) -> Result<Self> {
        tracing::debug!(
            account_name = %account_name,
            "new_account",
        );

        let account_builder = builder(AccountBuilder::new(
            account_name,
            password.clone(),
            target.clone(),
        ));
        let new_account = account_builder.finish().await?;

        target = target.with_account_id(&new_account.account_id);

        tracing::debug!(
          account_id = %new_account.account_id,
          "new_account::prepared",
        );

        let account_id = new_account.account_id;
        let (_authenticated_user, public_account) = new_account.into();
        let mut storage =
            ClientStorage::new_unauthenticated(target.clone(), &account_id)
                .await?;
        // storage.authenticate(authenticated_user).await?;

        tracing::debug!("new_account::storage_provider");
        storage.create_account(&public_account).await?;
        tracing::debug!("new_account::created");

        changes_feed()
            .send_replace(LocalChangeEvent::AccountCreated(account_id));

        Ok(Self {
            account_id,
            paths: target.paths(),
            storage,
            target,
        })
    }

    fn ensure_authenticated(&self) -> Result<()> {
        let is_authenticated = self.storage.is_authenticated();
        if !is_authenticated {
            return Err(AuthenticationError::NotAuthenticated.into());
        }
        Ok(())
    }

    async fn initialize_account_log(&self) -> Result<()> {
        let account_log = self.storage.account_log().await?;
        let mut event_log = account_log.write().await;
        let needs_init = event_log.tree().root().is_none();
        tracing::debug!(
            needs_init = %needs_init,
            "account_log::init");

        // If the account event log does not already exist
        // we initialize it from the current state on disc
        // adding create folder events for every folder that
        // already exists
        if needs_init {
            let folders: Vec<Summary> =
                self.target.list_folders(&self.account_id).await?;

            let mut events = Vec::new();
            for folder in folders {
                let vault = self.storage.read_vault(folder.id()).await?;
                let header: Header = vault.into();
                let head_only: Vault = header.into();
                let buffer = encode(&head_only).await?;
                events
                    .push(AccountEvent::CreateFolder(folder.into(), buffer));
            }
            tracing::debug!(
                events_len = %events.len(),
                "account_log::init");
            event_log.apply(events.as_slice()).await?;
        }

        Ok(())
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
        use sos_vault::ChangePassword;
        // Get the current vault passphrase from the identity vault
        let current_key = self
            .find_folder_password(vault_id)
            .await?
            .ok_or(Error::NoFolderPassword(*vault_id))?;

        // Find the vault for the account
        let vault = self.storage.read_vault(vault_id).await?;

        // Change the password before exporting
        let (_, vault, _) =
            ChangePassword::new(&vault, current_key, new_key, None)
                .build()
                .await?;

        Ok(encode(&vault).await?)
    }

    pub(crate) async fn open_vault(
        &self,
        folder_id: &VaultId,
        audit: bool,
    ) -> Result<()> {
        // Bail early if the folder is already open
        {
            if let Some(current) = self.storage.current_folder() {
                if current.id() == folder_id {
                    return Ok(());
                }
            }
        }

        let event = self.storage.open_folder(folder_id)?;

        #[cfg(feature = "audit")]
        if audit {
            let event = Event::Read(*folder_id, event);
            let audit_event: AuditEvent = (self.account_id(), &event).into();
            append_audit_events(&[audit_event]).await?;
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
        let folder = if let Some(folder_id) = &options.folder {
            self.storage
                .find(|f| f.id() == folder_id)
                .cloned()
                .ok_or(StorageError::FolderNotFound(*folder_id))?
        } else {
            self.storage.current_folder().ok_or(Error::NoOpenFolder)?
        };

        let commit_state = self
            .storage
            .folders()
            .get(folder.id())
            .ok_or(StorageError::FolderNotFound(*folder.id()))?
            .commit_state()
            .await?;

        Ok((folder, commit_state))
    }

    /// Import an identity vault and generate the event but
    /// do not write the event to the account event log.
    ///
    /// This is used when merging account event logs to ensure
    /// the `AccountEvent::UpdateIdentity` event is not duplicated.
    ///
    /// Typically the handlers that update storage but don't append log
    /// events are declared in the storage implementation but the
    /// identity log is managed by the account so this must exist here.
    #[doc(hidden)]
    pub async fn import_identity_vault(
        &mut self,
        vault: Vault,
    ) -> Result<AccountEvent> {
        Ok(self.storage.import_login_vault(vault).await?)
    }

    async fn add_secret(
        &mut self,
        meta: SecretMeta,
        secret: Secret,
        options: AccessOptions,
        audit: bool,
        #[cfg(feature = "files")] file_events: &mut Vec<FileMutationEvent>,
    ) -> Result<(SecretId, Event, Summary)> {
        let (folder, _) = self.compute_folder_state(&options).await?;

        self.open_folder(folder.id()).await?;

        if let Secret::Pem { certificates, .. } = &secret {
            if certificates.is_empty() {
                return Err(Error::PemEncoding);
            }
        }

        let id = SecretId::new_v4();
        let secret_data = SecretRow::new(id, meta, secret);

        #[allow(unused_mut)]
        let mut result =
            self.storage.create_secret(secret_data, options).await?;

        #[cfg(feature = "files")]
        file_events.append(&mut result.file_events);

        let event = Event::Write(*folder.id(), result.event);

        #[cfg(feature = "audit")]
        if audit {
            let audit_event: AuditEvent = (self.account_id(), &event).into();
            append_audit_events(&[audit_event]).await?;
        }

        Ok((id, event, folder))
    }

    /// Get a secret in the current open folder and
    /// optionally append to the audit log.
    ///
    /// Some internal operations needn't generate extra
    /// audit log records.
    pub(crate) async fn get_secret(
        &self,
        secret_id: &SecretId,
        options: &AccessOptions,
        audit: bool,
    ) -> Result<(Summary, SecretRow, ReadEvent)> {
        let (folder, meta, secret, read_event) =
            self.storage.read_secret(secret_id, options).await?;

        #[cfg(feature = "audit")]
        if audit {
            let event = Event::Read(*folder.id(), read_event.clone());
            let audit_event: AuditEvent = (self.account_id(), &event).into();
            append_audit_events(&[audit_event]).await?;
        }

        Ok((folder, SecretRow::new(*secret_id, meta, secret), read_event))
    }

    async fn mv_secret(
        &mut self,
        secret_id: &SecretId,
        from: &VaultId,
        to: &VaultId,
        #[allow(unused_mut, unused_variables)] mut options: AccessOptions,
    ) -> Result<SecretMove<<LocalAccount as Account>::NetworkResult>> {
        self.open_vault(from, false).await?;

        options.folder = Some(*from);
        options.destination = Some(*to);

        let (_, secret_data, read_event) =
            self.get_secret(secret_id, &options, false).await?;

        #[cfg(feature = "files")]
        let move_secret_data = secret_data.clone();

        #[cfg(feature = "files")]
        let mut file_events = Vec::new();

        self.open_vault(to, false).await?;
        let (_, meta, secret) = secret_data.into();
        let (new_id, create_event, _) = self
            .add_secret(
                meta,
                secret,
                Default::default(),
                false,
                #[cfg(feature = "files")]
                &mut file_events,
            )
            .await?;

        self.open_vault(from, false).await?;

        // Note that we call `remove_secret()` and not `delete_secret()`
        // as we need the original external files for the
        // move_files operation.
        let delete_event =
            self.storage.remove_secret(secret_id, &options).await?;

        #[cfg(feature = "files")]
        {
            let mut move_file_events = self
                .storage
                .external_file_manager_mut()
                .ok_or(AuthenticationError::NotAuthenticated)?
                .move_files(
                    &move_secret_data,
                    from,
                    to,
                    secret_id,
                    &new_id,
                    None,
                    &mut options.file_progress,
                )
                .await?;
            self.storage
                .external_file_manager_mut()
                .ok_or(AuthenticationError::NotAuthenticated)?
                .append_file_mutation_events(&move_file_events)
                .await?;
            file_events.append(&mut move_file_events);
        }

        let (_, create_event) = create_event.try_into()?;
        //let (_, delete_event) = delete_event.try_into()?;

        let event = Event::MoveSecret(read_event, create_event, delete_event);

        #[cfg(feature = "audit")]
        {
            let audit_event = AuditEvent::new(
                Default::default(),
                EventKind::MoveSecret,
                *self.account_id(),
                Some(AuditData::MoveSecret {
                    from_vault_id: *from,
                    to_vault_id: *to,
                    from_secret_id: *secret_id,
                    to_secret_id: new_id,
                }),
            );
            append_audit_events(&[audit_event]).await?;
        }

        Ok(SecretMove {
            id: new_id,
            event,
            sync_result: (),
            #[cfg(feature = "files")]
            file_events,
        })
    }

    /// Build the search index for all folders.
    #[cfg(feature = "search")]
    #[allow(dead_code)]
    pub(crate) async fn build_search_index(
        &mut self,
    ) -> Result<DocumentCount> {
        let keys = self.folder_keys().await?;
        Ok(self.storage.build_search_index(&keys).await?)
    }

    /// Access keys for all folders.
    pub(super) async fn folder_keys(&self) -> Result<FolderKeys> {
        let folders = self.storage.list_folders();
        let mut keys = HashMap::new();
        for folder in folders {
            if let Some(key) = self.find_folder_password(folder.id()).await? {
                keys.insert(*folder.id(), key);
            } else {
                tracing::warn!(
                    folder_id = %folder.id(),
                    "folder_keys::no_folder_key");
            }
        }
        Ok(FolderKeys(keys))
    }

    /// Generic CSV import implementation.
    #[cfg(feature = "migrate")]
    async fn import_csv<P: AsRef<Path>>(
        &mut self,
        path: P,
        folder_name: String,
        converter: impl Convert<Input = PathBuf>,
    ) -> Result<FolderCreate<()>> {
        #[cfg(feature = "audit")]
        {
            let audit_event = AuditEvent::new(
                Default::default(),
                EventKind::ImportUnsafe,
                *self.account_id(),
                None,
            );
            append_audit_events(&[audit_event]).await?;
        }

        let vaults = self.target.list_folders(&self.account_id).await?;
        let existing_name = vaults.iter().find(|s| s.name() == folder_name);

        let vault_passphrase = self.generate_folder_password()?;

        let vault_id = VaultId::new_v4();
        let name = if existing_name.is_some() {
            format!("{} ({})", folder_name, vault_id)
        } else {
            folder_name
        };

        let vault = VaultBuilder::new()
            .id(vault_id)
            .public_name(name)
            .build(BuilderCredentials::Password(
                vault_passphrase.clone(),
                None,
            ))
            .await?;

        // Parse the CSV records into the vault
        let key = vault_passphrase.clone().into();
        let vault = converter
            .convert(path.as_ref().to_path_buf(), vault, &key)
            .await?;

        let buffer = encode(&vault).await?;
        let key: AccessKey = vault_passphrase.clone().into();
        let result = self.import_folder_buffer(&buffer, key, false).await?;

        self.save_folder_password(
            vault.id(),
            vault_passphrase.clone().into(),
        )
        .await?;

        Ok(result)
    }
}

impl From<&LocalAccount> for AccountRef {
    fn from(value: &LocalAccount) -> Self {
        Self::Id(*value.account_id())
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl Account for LocalAccount {
    type Error = Error;
    type NetworkResult = ();

    fn account_id(&self) -> &AccountId {
        &self.account_id
    }

    fn paths(&self) -> Arc<Paths> {
        self.paths.clone()
    }

    async fn backend_target(&self) -> BackendTarget {
        self.target.clone()
    }

    async fn folder(&self, folder_id: &VaultId) -> Result<Folder> {
        Ok(self
            .storage
            .folders()
            .get(folder_id)
            .ok_or(StorageError::FolderNotFound(*folder_id))?
            .clone())
    }

    async fn is_authenticated(&self) -> bool {
        self.storage.is_authenticated()
    }

    async fn device_signer(&self) -> Result<DeviceSigner> {
        let authenticated_user = self
            .storage
            .authenticated_user()
            .ok_or(AuthenticationError::NotAuthenticated)?;
        Ok(authenticated_user.identity()?.device().clone())
    }

    async fn import_account_events(
        &mut self,
        events: CreateSet,
    ) -> Result<()> {
        let account_id = *self.account_id();
        let mut storage = ClientStorage::new_unauthenticated(
            self.target.clone(),
            &account_id,
        )
        .await?;

        {
            let identity_log = storage.identity_log().await?;
            let mut identity_log = identity_log.write().await;
            let records: Vec<EventRecord> = events.identity.into();
            identity_log.apply_records(records).await?;
            let vault = FolderReducer::new()
                .reduce(&*identity_log)
                .await?
                .build(true)
                .await?;
            storage.import_login_vault(vault).await?;

            tracing::info!(
              root = ?identity_log.tree().root().map(|c| c.to_string()),
              "import_account_events::identity");
        }

        {
            let account_log = storage.account_log().await?;
            let mut account_log = account_log.write().await;
            let records: Vec<EventRecord> = events.account.into();
            account_log.apply_records(records).await?;

            tracing::info!(
              root = ?account_log.tree().root().map(|c| c.to_string()),
              "import_account_events::account");
        }

        {
            let device_log = storage.device_log().await?;
            let mut device_log = device_log.write().await;
            let records: Vec<EventRecord> = events.device.into();
            device_log.apply_records(records).await?;
            tracing::info!(
              root = ?device_log.tree().root().map(|c| c.to_string()),
              "import_account_events::device");
        }

        storage.import_folder_patches(events.folders).await?;

        #[cfg(feature = "files")]
        {
            tracing::info!("import_account_events::files");
            let file_log = storage.file_log().await?;
            let mut file_log = file_log.write().await;
            let records: Vec<EventRecord> = events.files.into();
            file_log.apply_records(records).await?;
            tracing::info!(
              root = ?file_log.tree().root().map(|c| c.to_string()),
              "import_account_events::files");
        }

        self.storage = storage;

        Ok(())
    }

    async fn new_device_vault(
        &mut self,
    ) -> Result<(DeviceSigner, DeviceManager)> {
        let authenticated_user = self
            .storage
            .authenticated_user_mut()
            .ok_or(AuthenticationError::NotAuthenticated)?;

        let signer = DeviceSigner::random();
        let target = self.target.clone();
        let manager = authenticated_user
            .identity_mut()?
            .new_device_manager(&target, signer.clone())
            .await?;

        Ok((signer, manager))
    }

    async fn device_public_key(&self) -> Result<DevicePublicKey> {
        let authenticated_user = self
            .storage
            .authenticated_user()
            .ok_or(AuthenticationError::NotAuthenticated)?;
        Ok(authenticated_user.identity()?.device().public_key())
    }

    async fn patch_devices_unchecked(
        &mut self,
        events: &[DeviceEvent],
    ) -> Result<()> {
        Ok(self.storage.patch_devices_unchecked(events).await?)
    }

    async fn revoke_device(
        &mut self,
        device_key: &DevicePublicKey,
    ) -> Result<()> {
        Ok(self.storage.revoke_device(device_key).await?)
    }

    async fn current_device(&self) -> Result<TrustedDevice> {
        let authenticated_user = self
            .storage
            .authenticated_user()
            .ok_or(AuthenticationError::NotAuthenticated)?;
        Ok(authenticated_user.devices()?.current_device(None))
    }

    async fn trusted_devices(&self) -> Result<IndexSet<TrustedDevice>> {
        self.ensure_authenticated()?;
        Ok(self.storage.devices().clone())
    }

    async fn public_identity(&self) -> Result<PublicIdentity> {
        let authenticated_user = self
            .storage
            .authenticated_user()
            .ok_or(AuthenticationError::NotAuthenticated)?;
        Ok(authenticated_user.account()?.clone())
    }

    async fn account_name(&self) -> Result<String> {
        let authenticated_user = self
            .storage
            .authenticated_user()
            .ok_or(AuthenticationError::NotAuthenticated)?;
        Ok(authenticated_user.account()?.label().to_owned())
    }

    async fn folder_description(
        &mut self,
        folder_id: &VaultId,
    ) -> Result<String> {
        self.ensure_authenticated()?;

        // self.open_folder(folder.id()).await?;
        Ok(self.storage.description(folder_id).await?)
    }

    async fn set_folder_description(
        &mut self,
        folder_id: &VaultId,
        description: impl AsRef<str> + Send + Sync,
    ) -> Result<FolderChange<Self::NetworkResult>> {
        self.ensure_authenticated()?;

        let options = AccessOptions {
            folder: Some(*folder_id),
            ..Default::default()
        };
        let (_, commit_state) = self.compute_folder_state(&options).await?;

        let event =
            self.storage.set_description(folder_id, description).await?;
        let event = Event::Write(*folder_id, event);

        Ok(FolderChange {
            event,
            commit_state,
            sync_result: (),
        })
    }

    async fn login_folder_summary(&self) -> Result<Summary> {
        let authenticated_user = self
            .storage
            .authenticated_user()
            .ok_or(AuthenticationError::NotAuthenticated)?;
        Ok(authenticated_user.identity()?.summary().await)
    }

    async fn reload_login_folder(&mut self) -> Result<()> {
        let authenticated_user = self
            .storage
            .authenticated_user_mut()
            .ok_or(AuthenticationError::NotAuthenticated)?;

        // Reload the vault on disc
        let path = self.paths.identity_vault();

        let folder = authenticated_user.identity()?.folder();
        let access_point = folder.access_point();
        let mut access_point = access_point.lock().await;
        access_point.reload_vault(path).await?;

        // Reload the event log merkle tree
        let event_log = authenticated_user.identity_mut()?.folder.event_log();
        let mut event_log = event_log.write().await;
        event_log.load_tree().await?;

        // Rebuild the folder password lookup index
        authenticated_user
            .identity_mut()?
            .rebuild_lookup_index()
            .await?;

        Ok(())
    }

    async fn change_cipher(
        &mut self,
        account_key: &AccessKey,
        cipher: &Cipher,
        kdf: Option<KeyDerivation>,
    ) -> Result<CipherComparison> {
        self.ensure_authenticated()?;

        let account_id = *self.account_id();
        let conversion = self.compare_cipher(cipher, kdf).await?;

        // Short circuit if there is nothing to do
        if conversion.is_empty() {
            return Ok(conversion);
        }

        self.convert_cipher(&conversion, account_key).await?;

        // Login again so in-memory data is up to date
        {
            let authenticated_user = self
                .storage
                .authenticated_user_mut()
                .ok_or(AuthenticationError::NotAuthenticated)?;
            authenticated_user.login(&account_id, account_key).await?;
        }

        Ok(conversion)
    }

    async fn change_account_password(
        &mut self,
        password: SecretString,
    ) -> Result<()> {
        self.ensure_authenticated()?;

        let account_id = *self.account_id();
        let (meta, seed, keys) = {
            let authenticated_user = self
                .storage
                .authenticated_user()
                .ok_or(AuthenticationError::NotAuthenticated)?;
            let identity = authenticated_user.identity()?;
            let folder = identity.folder();
            let access_point = folder.access_point();
            let access_point = access_point.lock().await;
            let seed = access_point.vault().seed().cloned();
            let meta = access_point.vault_meta().await?;
            let keys =
                access_point.vault().keys().cloned().collect::<Vec<_>>();
            (meta, seed, keys)
        };

        let summary = self.login_folder_summary().await?;
        let vault = VaultBuilder::new()
            .id(*summary.id())
            .public_name(summary.name().to_owned())
            .description(meta.description().to_owned())
            .flags(summary.flags().clone())
            .kdf(*summary.kdf())
            .cipher(*summary.cipher())
            .build(BuilderCredentials::Password(password.clone(), seed))
            .await?;

        let account_key: AccessKey = password.into();
        let mut output = AccessPoint::from_vault(vault);
        output.unlock(&account_key).await?;

        {
            let authenticated_user = self
                .storage
                .authenticated_user()
                .ok_or(AuthenticationError::NotAuthenticated)?;
            let identity = authenticated_user.identity()?;
            let folder = identity.folder();
            let access_point = folder.access_point();
            let access_point = access_point.lock().await;

            for key in keys {
                let (meta, secret, _) =
                    access_point.read_secret(&key).await?.unwrap();
                let secret_data = SecretRow::new(key, meta, secret);
                output.create_secret(&secret_data).await?;
            }
        }

        self.import_login_folder(output.into()).await?;

        // Login again so in-memory data is up to date
        {
            let authenticated_user = self
                .storage
                .authenticated_user_mut()
                .ok_or(AuthenticationError::NotAuthenticated)?;
            authenticated_user.login(&account_id, &account_key).await?;
        }

        Ok(())
    }

    async fn sign_in(&mut self, key: &AccessKey) -> Result<Vec<Summary>> {
        let account_id = &self.account_id;

        // Ensure all paths before sign_in
        let paths = self.paths().with_account_id(account_id);

        tracing::debug!(
            account_id = %account_id,
            data_dir = ?paths.documents_dir(),
            "sign_in",
        );

        let mut user = Identity::new(self.target.clone());
        user.sign_in(self.account_id(), key).await?;
        tracing::debug!("sign_in::success");

        self.storage.authenticate(user).await?;

        self.paths = self.storage.paths();

        self.initialize_account_log().await?;

        // Load vaults into memory and initialize folder
        // event log commit trees
        let folders = self.load_folders().await?;

        // Unlock all the storage vaults
        {
            let folder_keys = self.folder_keys().await?;
            self.storage.unlock(&folder_keys).await?;
        }

        if let Some(default_folder) = self.default_folder().await {
            self.open_folder(default_folder.id()).await?;
        }

        Ok(folders)
    }

    async fn verify(&self, key: &AccessKey) -> bool {
        if let Some(auth) = self.storage.authenticated_user() {
            auth.verify(key).await
        } else {
            false
        }
    }

    async fn open_folder(&self, folder_id: &VaultId) -> Result<()> {
        self.ensure_authenticated()?;
        self.open_vault(folder_id, true).await
    }

    async fn current_folder(&self) -> Result<Option<Summary>> {
        self.ensure_authenticated()?;
        Ok(self.storage.current_folder())
    }

    async fn history(
        &self,
        folder_id: &VaultId,
    ) -> Result<Vec<(CommitHash, UtcDateTime, WriteEvent)>> {
        self.ensure_authenticated()?;
        Ok(self.storage.history(folder_id).await?)
    }

    async fn sign_out(&mut self) -> Result<()> {
        tracing::debug!(account_id = %self.account_id(), "sign_out");

        // Lock all the storage vaults
        {
            tracing::debug!("sign_out::lock_storage");
            self.storage.lock().await;

            #[cfg(feature = "search")]
            {
                tracing::debug!("sign_out::clear_search_index");
                // Remove the search index
                self.storage
                    .search_index_mut()
                    .ok_or_else(|| AuthenticationError::NotAuthenticated)?
                    .clear()
                    .await;
            }
        }

        self.storage.sign_out().await?;

        Ok(())
    }

    async fn rename_account(
        &mut self,
        account_name: String,
    ) -> Result<AccountChange<Self::NetworkResult>> {
        // Rename the local identity folder
        self.set_account_name(account_name.clone()).await?;

        // Generate and append the rename event
        let event = {
            let event = AccountEvent::RenameAccount(account_name);
            let log = self.account_log().await?;
            let mut log = log.write().await;
            log.apply(std::slice::from_ref(&event)).await?;
            event
        };

        Ok(AccountChange {
            event: Event::Account(event),
            sync_result: (),
        })
    }

    async fn set_account_name(&mut self, account_name: String) -> Result<()> {
        Ok(self.storage.rename_account(account_name).await?)
    }

    async fn delete_account(&mut self) -> Result<()> {
        self.ensure_authenticated()?;

        let paths = self.paths().clone();
        tracing::info!(
          account_id = %self.account_id,
          directory = %paths.documents_dir().display(),
          "delete_account");

        let event = self.storage.delete_account().await?;

        #[cfg(feature = "audit")]
        {
            let audit_event: AuditEvent = (self.account_id(), &event).into();
            append_audit_events(&[audit_event]).await?;
        }

        self.sign_out().await?;

        changes_feed().send_replace(LocalChangeEvent::AccountDeleted(
            *self.account_id(),
        ));

        Ok(())
    }

    async fn find<P>(&self, predicate: P) -> Option<Summary>
    where
        P: FnMut(&&Summary) -> bool + Send,
    {
        self.storage.find(predicate).cloned()
    }

    async fn find_folder(&self, vault: &FolderRef) -> Option<Summary> {
        self.storage.find_folder(vault).cloned()
    }

    async fn list_secret_ids(
        &self,
        folder_id: &VaultId,
    ) -> Result<Vec<SecretId>> {
        self.ensure_authenticated()?;
        Ok(self.storage.list_secret_ids(folder_id).await?)
    }

    async fn load_folders(&mut self) -> Result<Vec<Summary>> {
        self.ensure_authenticated()?;
        let mut folders = self.storage.load_folders().await?.to_vec();
        folders.sort_by(|a, b| a.name().cmp(b.name()));
        Ok(folders)
    }

    async fn list_folders(&self) -> Result<Vec<Summary>> {
        self.ensure_authenticated()?;
        let mut folders = self.storage.list_folders().to_vec();
        folders.sort_by(|a, b| a.name().cmp(b.name()));
        Ok(folders)
    }

    async fn account_data(&self) -> Result<AccountData> {
        let user = self
            .storage
            .authenticated_user()
            .ok_or(AuthenticationError::NotAuthenticated)?;
        Ok(AccountData {
            account: user.account()?.clone(),
            identity: user
                .identity()?
                .private_identity()
                .recipient()
                .to_string(),
            folders: self.storage.list_folders().to_vec(),
            device_id: self.device_public_key().await?.to_string(),
        })
    }

    async fn root_hash(&self, folder_id: &VaultId) -> Result<CommitHash> {
        let folder = self
            .storage
            .folders()
            .get(folder_id)
            .ok_or_else(|| StorageError::FolderNotFound(*folder_id))?;
        let event_log = folder.event_log();
        let log_file = event_log.read().await;
        Ok(log_file
            .tree()
            .root()
            .ok_or_else(|| sos_core::Error::NoRootCommit)?)
    }

    async fn identity_state(&self) -> Result<CommitState> {
        Ok(self.storage.identity_state().await?)
    }

    async fn commit_state(&self, folder_id: &VaultId) -> Result<CommitState> {
        Ok(self.storage.commit_state(folder_id).await?)
    }

    async fn compact_account(
        &mut self,
    ) -> Result<HashMap<Summary, AccountEvent>> {
        let folders = self.list_folders().await?;
        let mut output = HashMap::new();

        for folder in folders {
            let result = self.compact_folder(folder.id()).await?;
            output.insert(folder, result);
        }

        let identity = self.login_folder_summary().await?;
        let vault = {
            let event_log = self.identity_log().await?;
            let mut log_file = event_log.write().await;
            compact_folder(self.account_id(), identity.id(), &mut log_file)
                .await?;

            let vault = FolderReducer::new()
                .reduce(&*log_file)
                .await?
                .build(true)
                .await?;

            vault
        };

        let event = {
            let event = AccountEvent::UpdateIdentity(encode(&vault).await?);
            let log = self.account_log().await?;
            let mut log = log.write().await;
            log.apply(std::slice::from_ref(&event)).await?;
            event
        };

        output.insert(identity, event);
        Ok(output)
    }

    async fn compact_folder(
        &mut self,
        folder_id: &VaultId,
    ) -> Result<AccountEvent> {
        let key = self
            .find_folder_password(folder_id)
            .await?
            .ok_or(Error::NoFolderPassword(*folder_id))?;

        Ok(self.storage.compact_folder(folder_id, &key).await?)
    }

    async fn restore_folder(
        &mut self,
        folder_id: &VaultId,
        records: Vec<EventRecord>,
    ) -> Result<Summary> {
        let key = self
            .find_folder_password(folder_id)
            .await?
            .ok_or(Error::NoFolderPassword(*folder_id))?;

        Ok(self.storage.restore_folder(records, &key).await?)
    }

    async fn change_folder_password(
        &mut self,
        folder_id: &VaultId,
        new_key: AccessKey,
    ) -> Result<()> {
        let current_key = self
            .find_folder_password(folder_id)
            .await?
            .ok_or(Error::NoFolderPassword(*folder_id))?;

        let vault = self.storage.read_vault(folder_id).await?;

        self.storage
            .change_password(&vault, current_key, new_key.clone())
            .await?;

        Ok(())
    }

    #[cfg(feature = "search")]
    async fn detached_view(
        &self,
        folder_id: &VaultId,
        commit: CommitHash,
    ) -> Result<DetachedView> {
        let key = self
            .find_folder_password(folder_id)
            .await?
            .ok_or(Error::NoFolderPassword(*folder_id))?;

        let folder = self
            .storage
            .folders()
            .get(folder_id)
            .ok_or_else(|| StorageError::FolderNotFound(*folder_id))?;

        let event_log = folder.event_log();
        let log_file = event_log.read().await;
        let vault = FolderReducer::new_until_commit(commit)
            .reduce(&*log_file)
            .await?
            .build(true)
            .await?;

        let mut keeper = AccessPoint::from_vault(vault);
        keeper.unlock(&key).await?;

        let mut search_index = SearchIndex::new();
        search_index.add_folder(&keeper).await?;

        Ok(DetachedView {
            keeper,
            index: Arc::new(RwLock::new(search_index)),
        })
    }

    #[cfg(feature = "search")]
    async fn initialize_search_index(
        &mut self,
    ) -> Result<(DocumentCount, Vec<Summary>)> {
        let keys = self.folder_keys().await?;
        let (count, mut folders) =
            self.storage.initialize_search_index(&keys).await?;
        folders.sort_by(|a, b| a.name().cmp(b.name()));
        Ok((count, folders))
    }

    #[cfg(feature = "search")]
    async fn statistics(&self) -> AccountStatistics {
        if self.storage.is_authenticated() {
            if let Some(index) = self.storage.search_index() {
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
    async fn search_index(&self) -> Result<Arc<RwLock<SearchIndex>>> {
        Ok(self
            .storage
            .search_index()
            .ok_or_else(|| AuthenticationError::NotAuthenticated)?
            .search())
    }

    #[cfg(feature = "search")]
    async fn query_view(
        &self,
        views: &[DocumentView],
        archive: Option<&ArchiveFilter>,
    ) -> Result<Vec<Document>> {
        Ok(self
            .storage
            .search_index()
            .ok_or_else(|| AuthenticationError::NotAuthenticated)?
            .query_view(views, archive)
            .await?)
    }

    #[cfg(feature = "search")]
    async fn query_map(
        &self,
        query: &str,
        filter: QueryFilter,
    ) -> Result<Vec<Document>> {
        Ok(self
            .storage
            .search_index()
            .ok_or_else(|| AuthenticationError::NotAuthenticated)?
            .query_map(query, filter)
            .await?)
    }

    #[cfg(feature = "search")]
    async fn document_count(&self) -> Result<DocumentCount> {
        let search = self
            .storage
            .search_index()
            .ok_or_else(|| AuthenticationError::NotAuthenticated)?
            .search();
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
        let search = self
            .storage
            .search_index()
            .ok_or_else(|| AuthenticationError::NotAuthenticated)?
            .search();
        let index = search.read().await;
        Ok(index.find_by_label(vault_id, label, id).is_some())
    }

    #[cfg(feature = "files")]
    async fn download_file(
        &self,
        vault_id: &VaultId,
        secret_id: &SecretId,
        file_name: &sos_core::ExternalFileName,
    ) -> Result<Vec<u8>> {
        let buffer = self
            .storage
            .external_file_manager()
            .ok_or_else(|| AuthenticationError::NotAuthenticated)?
            .download_file(vault_id, secret_id, file_name)
            .await?;

        #[cfg(feature = "audit")]
        {
            let audit_event = AuditEvent::new(
                Default::default(),
                EventKind::DownloadFile,
                *self.account_id(),
                Some(AuditData::Secret(*vault_id, *secret_id)),
            );
            append_audit_events(&[audit_event]).await?;
        }

        Ok(buffer)
    }

    async fn create_secret(
        &mut self,
        meta: SecretMeta,
        secret: Secret,
        options: AccessOptions,
    ) -> Result<SecretChange<Self::NetworkResult>> {
        self.ensure_authenticated()?;

        let (folder, commit_state) =
            self.compute_folder_state(&options).await?;

        #[cfg(feature = "files")]
        let mut file_events = Vec::new();

        let (id, event, _) = self
            .add_secret(
                meta,
                secret,
                options,
                true,
                #[cfg(feature = "files")]
                &mut file_events,
            )
            .await?;

        Ok(SecretChange {
            id,
            event,
            commit_state,
            folder,
            sync_result: (),
            #[cfg(feature = "files")]
            file_events,
        })
    }

    async fn insert_secrets(
        &mut self,
        secrets: Vec<(SecretMeta, Secret)>,
    ) -> Result<SecretInsert<Self::NetworkResult>> {
        self.ensure_authenticated()?;

        let mut results = Vec::new();
        for (meta, secret) in secrets {
            results.push(
                self.create_secret(meta, secret, AccessOptions::default())
                    .await?,
            );
        }
        Ok(SecretInsert {
            results,
            sync_result: (),
        })
    }

    async fn update_secret(
        &mut self,
        secret_id: &SecretId,
        meta: SecretMeta,
        secret: Option<Secret>,
        options: AccessOptions,
    ) -> Result<SecretChange<()>> {
        self.ensure_authenticated()?;

        let (folder, commit_state) =
            self.compute_folder_state(&options).await?;

        self.open_folder(folder.id()).await?;

        if let Some(Secret::Pem { certificates, .. }) = &secret {
            if certificates.is_empty() {
                return Err(Error::PemEncoding);
            }
        }

        let result = self
            .storage
            .update_secret(secret_id, meta, secret, options.clone())
            .await?;

        let event = Event::Write(*folder.id(), result.event);

        #[cfg(feature = "files")]
        let mut file_events = result.file_events;

        let id = if let Some(destination_id) = options.destination.as_ref() {
            let destination_id = *destination_id;

            let SecretMove {
                id,
                #[cfg(feature = "files")]
                    file_events: mut move_file_events,
                ..
            } = self
                .mv_secret(secret_id, folder.id(), &destination_id, options)
                .await?;

            #[cfg(feature = "files")]
            file_events.append(&mut move_file_events);
            id
        } else {
            *secret_id
        };

        #[cfg(feature = "audit")]
        {
            let audit_event: AuditEvent = (self.account_id(), &event).into();
            append_audit_events(&[audit_event]).await?;
        }

        Ok(SecretChange {
            id,
            event,
            commit_state,
            folder,
            sync_result: (),
            #[cfg(feature = "files")]
            file_events,
        })
    }

    async fn move_secret(
        &mut self,
        secret_id: &SecretId,
        from: &VaultId,
        to: &VaultId,
        options: AccessOptions,
    ) -> Result<SecretMove<Self::NetworkResult>> {
        self.ensure_authenticated()?;
        self.mv_secret(secret_id, from, to, options).await
    }

    async fn read_secret(
        &self,
        secret_id: &SecretId,
        folder: Option<&VaultId>,
    ) -> Result<(SecretRow, ReadEvent)> {
        self.ensure_authenticated()?;
        let options = folder.into();
        let (_, row, event) =
            self.get_secret(secret_id, &options, true).await?;
        Ok((row, event))
    }

    async fn raw_secret(
        &self,
        folder_id: &VaultId,
        secret_id: &SecretId,
    ) -> Result<Option<(VaultCommit, ReadEvent)>> {
        self.ensure_authenticated()?;
        Ok(self.storage.raw_secret(folder_id, secret_id).await?)
    }

    async fn delete_secret(
        &mut self,
        secret_id: &SecretId,
        options: AccessOptions,
    ) -> Result<SecretDelete<Self::NetworkResult>> {
        self.ensure_authenticated()?;
        let (folder, commit_state) =
            self.compute_folder_state(&options).await?;

        self.open_folder(folder.id()).await?;

        let result = self.storage.delete_secret(secret_id, options).await?;
        let event = Event::Write(*folder.id(), result.event);

        #[cfg(feature = "audit")]
        {
            let audit_event: AuditEvent = (self.account_id(), &event).into();
            append_audit_events(&[audit_event]).await?;
        }

        Ok(SecretDelete {
            event,
            commit_state,
            folder,
            sync_result: (),
            #[cfg(feature = "files")]
            file_events: result.file_events,
        })
    }

    async fn archive(
        &mut self,
        folder_id: &VaultId,
        secret_id: &SecretId,
        options: AccessOptions,
    ) -> Result<SecretMove<Self::NetworkResult>> {
        self.ensure_authenticated()?;

        let from = self
            .storage
            .find(|s| s.id() == folder_id)
            .cloned()
            .ok_or_else(|| StorageError::FolderNotFound(*folder_id))?;

        if from.flags().is_archive() {
            return Err(Error::AlreadyArchived);
        }
        self.open_folder(from.id()).await?;
        let to = self
            .archive_folder()
            .await
            .ok_or_else(|| Error::NoArchive)?;
        self.move_secret(secret_id, from.id(), to.id(), options)
            .await
    }

    async fn unarchive(
        &mut self,
        secret_id: &SecretId,
        secret_kind: &SecretType,
        options: AccessOptions,
    ) -> Result<(SecretMove<Self::NetworkResult>, Summary)> {
        self.ensure_authenticated()?;
        let from = self
            .archive_folder()
            .await
            .ok_or_else(|| Error::NoArchive)?;
        if !from.flags().is_archive() {
            return Err(Error::NotArchived);
        }
        self.open_folder(from.id()).await?;
        let to = match secret_kind {
            SecretType::Totp => self.authenticator_folder().await,
            SecretType::Contact => self.contacts_folder().await,
            _ => Some(
                self.default_folder()
                    .await
                    .ok_or_else(|| Error::NoDefaultFolder)?,
            ),
        };

        let to = if let Some(to) = to {
            to
        } else {
            self.default_folder()
                .await
                .ok_or_else(|| Error::NoDefaultFolder)?
        };

        let result = self
            .move_secret(secret_id, from.id(), to.id(), options)
            .await?;
        Ok((result, to))
    }

    #[cfg(feature = "files")]
    async fn update_file(
        &mut self,
        secret_id: &SecretId,
        meta: SecretMeta,
        path: impl AsRef<Path> + Send + Sync,
        options: AccessOptions,
    ) -> Result<SecretChange<Self::NetworkResult>> {
        let path = path.as_ref().to_path_buf();
        let secret: Secret = path.try_into()?;
        self.update_secret(secret_id, meta, Some(secret), options)
            .await
    }

    async fn create_folder(
        &mut self,
        mut options: NewFolderOptions,
    ) -> Result<FolderCreate<Self::NetworkResult>> {
        self.ensure_authenticated()?;

        let key: AccessKey = if let Some(key) = options.key.take() {
            key
        } else {
            let passphrase = self.generate_folder_password()?;
            passphrase.into()
        };

        let identity_folder = self.login_folder_summary().await?;
        let cipher = options
            .cipher
            .take()
            .unwrap_or_else(|| *identity_folder.cipher());
        let kdf =
            options.kdf.take().unwrap_or_else(|| *identity_folder.kdf());

        options.key = Some(key.clone());
        options.cipher = Some(cipher);
        options.kdf = Some(kdf);

        let (buffer, _, summary, account_event) =
            self.storage.create_folder(options).await?;

        let options = AccessOptions {
            folder: Some(*summary.id()),
            ..Default::default()
        };

        let (folder, commit_state) =
            self.compute_folder_state(&options).await?;

        let event =
            Event::Folder(account_event, WriteEvent::CreateVault(buffer));
        Ok(FolderCreate {
            folder,
            event,
            commit_state,
            sync_result: (),
        })
    }

    async fn create_shared_folder(
        &mut self,
        mut options: NewFolderOptions,
    ) -> Result<FolderCreate<Self::NetworkResult>> {
        let authenticated_user = self
            .storage
            .authenticated_user()
            .ok_or(AuthenticationError::NotAuthenticated)?;
        let shared_private_key =
            authenticated_user.shared_folder_private_access_key()?;
        options.key = Some(shared_private_key);
        options.cipher = Some(Cipher::X25519);
        self.create_folder(options).await
    }

    async fn rename_folder(
        &mut self,
        folder_id: &VaultId,
        name: String,
    ) -> Result<FolderChange<Self::NetworkResult>> {
        self.ensure_authenticated()?;
        let options = AccessOptions {
            folder: Some(*folder_id),
            ..Default::default()
        };
        let (_, commit_state) = self.compute_folder_state(&options).await?;

        // Update the provider
        let event = self.storage.rename_folder(folder_id, &name).await?;

        Ok(FolderChange {
            event,
            commit_state,
            sync_result: (),
        })
    }

    async fn update_folder_flags(
        &mut self,
        folder_id: &VaultId,
        flags: VaultFlags,
    ) -> Result<FolderChange<Self::NetworkResult>> {
        self.ensure_authenticated()?;
        let options = AccessOptions {
            folder: Some(*folder_id),
            ..Default::default()
        };
        let (_, commit_state) = self.compute_folder_state(&options).await?;

        // Update the provider
        let event =
            self.storage.update_folder_flags(folder_id, flags).await?;

        Ok(FolderChange {
            event,
            commit_state,
            sync_result: (),
        })
    }

    async fn import_folder(
        &mut self,
        path: impl AsRef<Path> + Send + Sync,
        key: AccessKey,
        overwrite: bool,
    ) -> Result<FolderCreate<Self::NetworkResult>> {
        self.ensure_authenticated()?;
        let buffer = vfs::read(path.as_ref()).await?;
        self.import_folder_buffer(&buffer, key, overwrite).await
    }

    async fn import_folder_buffer(
        &mut self,
        buffer: impl AsRef<[u8]> + Send + Sync,
        key: AccessKey,
        overwrite: bool,
    ) -> Result<FolderCreate<Self::NetworkResult>> {
        self.ensure_authenticated()?;

        let mut vault: Vault = decode(buffer.as_ref()).await?;

        // Need to verify permission to access the data
        vault.verify(&key).await?;

        tracing::debug!(
          folder_id = %vault.id(),
          name = %vault.name(),
          "import_folder");

        // Check for existing identifier
        let existing_id = self.find(|s| s.id() == vault.summary().id()).await;

        let default_vault = self.default_folder().await;

        let remove_default_flag = !overwrite
            && default_vault.is_some()
            && vault.summary().flags().is_default();

        // If we are not overwriting and the identifier already exists
        // then we need to rotate the identifier
        let has_id_changed = if existing_id.is_some() && !overwrite {
            tracing::debug!("import_folder::rotate_identifier");
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
            tracing::debug!("import_folder::change_folder_name");
            vault.set_name(name);
            true
        } else {
            false
        };

        if remove_default_flag {
            tracing::debug!("import_folder::remove_default_flag");
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
        let (event, summary) = self
            .storage
            .import_folder(buffer.as_ref(), Some(&key), true, None)
            .await?;

        // If we are overwriting then we must remove the existing
        // vault passphrase so we can save it using the passphrase
        // assigned when exporting the folder
        if overwrite {
            self.remove_folder_password(summary.id()).await?;
        }

        self.save_folder_password(summary.id(), key).await?;

        // If overwriting remove old entries from the index
        if overwrite {
            // If we are overwriting and the current vault
            // is loaded into memory we must close it so
            // the UI does not show stale in-memory data
            {
                let is_current =
                    if let Some(current) = self.storage.current_folder() {
                        current.id() == summary.id()
                    } else {
                        false
                    };

                if is_current {
                    self.storage.close_folder();
                }
            }
        }

        let options = AccessOptions {
            folder: Some(*summary.id()),
            ..Default::default()
        };
        let (summary, commit_state) =
            self.compute_folder_state(&options).await?;

        Ok(FolderCreate {
            folder: summary,
            event,
            commit_state,
            sync_result: (),
        })
    }

    async fn import_login_folder(
        &mut self,
        vault: Vault,
    ) -> Result<AccountEvent> {
        self.ensure_authenticated()?;
        let event = self.import_identity_vault(vault).await?;
        let event_log = self.account_log().await?;
        let mut event_log = event_log.write().await;
        event_log.apply(std::slice::from_ref(&event)).await?;
        Ok(event)
    }

    async fn export_folder(
        &mut self,
        path: impl AsRef<Path> + Send + Sync,
        folder_id: &VaultId,
        new_key: AccessKey,
        save_key: bool,
    ) -> Result<()> {
        self.ensure_authenticated()?;
        let buffer = self
            .export_folder_buffer(folder_id, new_key, save_key)
            .await?;
        write_exclusive(path, buffer).await?;
        Ok(())
    }

    async fn export_folder_buffer(
        &mut self,
        folder_id: &VaultId,
        new_key: AccessKey,
        save_key: bool,
    ) -> Result<Vec<u8>> {
        self.ensure_authenticated()?;

        let buffer = self
            .change_vault_password(folder_id, new_key.clone())
            .await?;

        if save_key {
            let default_summary = self
                .default_folder()
                .await
                .ok_or_else(|| Error::NoDefaultFolder)?;

            let _passphrase =
                self.find_folder_password(default_summary.id()).await?;

            let timestamp: UtcDateTime = Default::default();
            let label = format!(
                "Exported folder {}.vault ({})",
                folder_id,
                timestamp.to_rfc3339()?
            );
            let secret = Secret::Account {
                account: format!("{}.vault", folder_id),
                url: Default::default(),
                password: new_key.into(),
                user_data: Default::default(),
            };
            let meta = SecretMeta::new(label, secret.kind());

            let vault = self.storage.read_vault(default_summary.id()).await?;

            self.add_secret(
                meta,
                secret,
                vault.id().into(),
                false,
                #[cfg(feature = "files")]
                &mut vec![],
            )
            .await?;
        }

        #[cfg(feature = "audit")]
        {
            let audit_event = AuditEvent::new(
                Default::default(),
                EventKind::ExportVault,
                *self.account_id(),
                Some(AuditData::Vault(*folder_id)),
            );
            append_audit_events(&[audit_event]).await?;
        }

        Ok(buffer)
    }

    async fn delete_folder(
        &mut self,
        folder_id: &VaultId,
    ) -> Result<FolderDelete<Self::NetworkResult>> {
        self.ensure_authenticated()?;
        let options = AccessOptions {
            folder: Some(*folder_id),
            ..Default::default()
        };
        let (_, commit_state) = self.compute_folder_state(&options).await?;

        let events = self.storage.delete_folder(folder_id, true).await?;

        Ok(FolderDelete {
            events,
            commit_state,
            sync_result: (),
        })
    }

    async fn forget_folder(&mut self, folder_id: &VaultId) -> Result<bool> {
        self.ensure_authenticated()?;
        Ok(self.storage.remove_folder(folder_id).await?)
    }

    #[cfg(feature = "contacts")]
    async fn load_avatar(
        &self,
        secret_id: &SecretId,
        folder: Option<&VaultId>,
    ) -> Result<Option<Vec<u8>>> {
        let (data, _) = self.read_secret(secret_id, folder).await?;
        if let Secret::Contact { vcard, .. } = data.secret() {
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

    #[cfg(feature = "contacts")]
    async fn export_contact(
        &self,
        path: impl AsRef<Path> + Send + Sync,
        secret_id: &SecretId,
        folder: Option<&VaultId>,
    ) -> Result<()> {
        self.ensure_authenticated()?;

        let options = folder.into();

        let (folder, data, _) =
            self.get_secret(secret_id, &options, false).await?;
        if let Secret::Contact { vcard, .. } = data.secret() {
            let content = vcard.to_string();
            write_exclusive(&path, content).await?;
        } else {
            return Err(Error::NotContact);
        }

        #[cfg(feature = "audit")]
        {
            let audit_event = AuditEvent::new(
                Default::default(),
                EventKind::ExportContacts,
                *self.account_id(),
                Some(AuditData::Secret(*folder.id(), *secret_id)),
            );
            append_audit_events(&[audit_event]).await?;
        }

        Ok(())
    }

    #[cfg(feature = "contacts")]
    async fn export_all_contacts(
        &self,
        path: impl AsRef<Path> + Send + Sync,
    ) -> Result<()> {
        self.ensure_authenticated()?;

        let contacts = self
            .contacts_folder()
            .await
            .ok_or_else(|| Error::NoContactsFolder)?;

        let contacts_passphrase = self
            .find_folder_password(contacts.id())
            .await?
            .ok_or(Error::NoFolderPassword(*contacts.id()))?;
        let vault = self.storage.read_vault(contacts.id()).await?;
        let mut keeper = AccessPoint::from_vault(vault);
        let key: AccessKey = contacts_passphrase;
        keeper.unlock(&key).await?;

        let mut vcf = String::new();
        let keys: Vec<&SecretId> = keeper.vault().keys().collect();
        for key in keys {
            if let Some((_, Secret::Contact { vcard, .. }, _)) =
                keeper.read_secret(key).await?
            {
                vcf.push_str(&vcard.to_string());
            }
        }
        write_exclusive(path, vcf.as_bytes()).await?;

        #[cfg(feature = "audit")]
        {
            let audit_event = AuditEvent::new(
                Default::default(),
                EventKind::ExportContacts,
                *self.account_id(),
                None,
            );
            append_audit_events(&[audit_event]).await?;
        }

        Ok(())
    }

    #[cfg(feature = "contacts")]
    async fn import_contacts(
        &mut self,
        content: &str,
        progress: impl Fn(ContactImportProgress) + Send + Sync,
    ) -> Result<Vec<SecretId>> {
        self.ensure_authenticated()?;

        use vcard4::parse;

        let mut ids = Vec::new();
        let current = self.storage.current_folder();

        let contacts = self
            .contacts_folder()
            .await
            .ok_or_else(|| Error::NoContactsFolder)?;
        self.open_vault(contacts.id(), false).await?;

        let cards = parse(content)?;

        progress(ContactImportProgress::Ready { total: cards.len() });

        for (index, vcard) in cards.into_iter().enumerate() {
            let label = vcard
                .formatted_name
                .first()
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
            let result =
                self.create_secret(meta, secret, Default::default()).await?;
            ids.push(result.id);
        }

        if let Some(folder) = current {
            self.open_vault(folder.id(), false).await?;
        }

        #[cfg(feature = "audit")]
        {
            let audit_event = AuditEvent::new(
                Default::default(),
                EventKind::ImportContacts,
                *self.account_id(),
                None,
            );
            append_audit_events(&[audit_event]).await?;
        }

        Ok(ids)
    }

    #[cfg(feature = "migrate")]
    async fn export_unsafe_archive(
        &self,
        path: impl AsRef<Path> + Send + Sync,
    ) -> crate::Result<()> {
        self.ensure_authenticated()?;

        use std::io::Cursor;

        let account_identity = self.public_identity().await?;

        let mut archive = Vec::new();
        let mut migration = PublicExport::new(Cursor::new(&mut archive));
        let vaults = self.target.list_folders(&self.account_id).await?;

        for summary in vaults {
            let vault = self.storage.read_vault(summary.id()).await?;
            let vault_passphrase = self
                .find_folder_password(summary.id())
                .await?
                .ok_or(Error::NoFolderPassword(*summary.id()))?;

            let mut keeper = AccessPoint::from_vault(vault);
            keeper.unlock(&vault_passphrase).await?;

            // Add the secrets for the vault to the migration
            migration.add(&keeper).await?;

            keeper.lock();
        }

        let mut files = HashMap::new();
        let buffer = serde_json::to_vec_pretty(&account_identity)?;
        // FIXME: constant for file name
        files.insert("account.json", buffer.as_slice());
        migration.append_files(files).await?;
        migration.finish().await?;

        write_exclusive(path.as_ref(), &archive).await?;

        #[cfg(feature = "audit")]
        {
            let audit_event = AuditEvent::new(
                Default::default(),
                EventKind::ExportUnsafe,
                *self.account_id(),
                None,
            );
            append_audit_events(&[audit_event]).await?;
        }

        Ok(())
    }

    #[cfg(feature = "migrate")]
    async fn import_file(
        &mut self,
        target: ImportTarget,
    ) -> Result<FolderCreate<Self::NetworkResult>> {
        self.ensure_authenticated()?;

        let result = match target.format {
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

        Ok(result)
    }

    #[cfg(feature = "archive")]
    async fn export_backup_archive(
        &self,
        path: impl AsRef<Path> + Send + Sync,
    ) -> Result<()> {
        sos_backend::archive::export_backup_archive(
            path.as_ref(),
            &self.target,
            &self.account_id,
        )
        .await?;

        #[cfg(feature = "audit")]
        {
            let audit_event = AuditEvent::new(
                Default::default(),
                EventKind::ExportBackupArchive,
                *self.account_id(),
                None,
            );
            append_audit_events(&[audit_event]).await?;
        }

        Ok(())
    }

    /// Restore from a backup archive file.
    #[cfg(feature = "archive")]
    async fn import_backup_archive(
        path: impl AsRef<Path> + Send + Sync,
        target: &BackendTarget,
    ) -> Result<Vec<PublicIdentity>> {
        let accounts =
            sos_backend::archive::import_backup_archive(path, target).await?;

        #[cfg(feature = "audit")]
        {
            let mut audit_events = Vec::new();
            for account in &accounts {
                audit_events.push(AuditEvent::new(
                    Default::default(),
                    EventKind::ImportBackupArchive,
                    *account.account_id(),
                    None,
                ));
            }
            append_audit_events(&audit_events).await?;
        }

        Ok(accounts)
    }

    /// Copy a secret to the clipboard.
    #[cfg(feature = "clipboard")]
    async fn copy_clipboard(
        &self,
        clipboard: &Clipboard,
        target: &SecretPath,
        request: &ClipboardCopyRequest,
    ) -> Result<bool> {
        self.ensure_authenticated()?;

        use serde_json::Value;
        let target_folder = self.find(|f| f.id() == target.folder_id()).await;
        if let Some(folder) = target_folder {
            let current_folder = self.current_folder().await?;
            let (data, _) = self
                .read_secret(target.secret_id(), Some(folder.id()))
                .await?;
            if let Some(current) = &current_folder {
                self.open_folder(current.id()).await?;
            }
            let secret = data.secret();
            let text = if let Some(paths) = &request.paths {
                fn value_to_string(node: &Value) -> String {
                    match node {
                        Value::Null => node.to_string(),
                        Value::Bool(val) => val.to_string(),
                        Value::Number(num) => num.to_string(),
                        Value::String(s) => s.to_string(),
                        Value::Array(list) => {
                            let mut s = String::new();
                            for node in list {
                                s.push_str(&value_to_string(node));
                            }
                            s
                        }
                        Value::Object(map) => {
                            let mut s = String::new();
                            for (k, v) in map {
                                s.push_str(k);
                                s.push('=');
                                s.push_str(&value_to_string(v));
                            }
                            s
                        }
                    }
                }

                let value: Value = serde_json::to_value(secret)?;
                let mut s = String::new();
                let mut nodes = Vec::new();
                for path in paths {
                    let mut matches = path.query(&value).all();
                    nodes.append(&mut matches);
                }

                if nodes.is_empty() {
                    return Err(Error::JsonPathQueryEmpty(
                        paths.iter().map(|p| p.to_string()).collect(),
                    ));
                }

                let len = nodes.len();
                for (index, node) in nodes.into_iter().enumerate() {
                    s.push_str(&value_to_string(node));
                    if index < len - 1 {
                        s.push('\n');
                    }
                }
                s
            } else {
                secret.copy_value_unsafe().unwrap_or_default()
            };

            let text = if let Some(format) = &request.format {
                match format {
                    ClipboardTextFormat::Date { format_description } => {
                        let dt = UtcDateTime::parse_rfc3339(&text)?;
                        let tz = time_tz::system::get_timezone()?;
                        let dt = dt.to_timezone(tz);
                        dt.format(format_description)?
                    }
                }
            } else {
                text
            };

            clipboard.set_text_timeout(text).await?;
            return Ok(true);
        }
        Ok(false)
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl DelegatedAccess for LocalAccount {
    type Error = Error;

    async fn find_folder_password(
        &self,
        folder_id: &VaultId,
    ) -> Result<Option<AccessKey>> {
        let authenticated_user = self
            .storage
            .authenticated_user()
            .ok_or(AuthenticationError::NotAuthenticated)?;
        Ok(authenticated_user.find_folder_password(folder_id).await?)
    }

    async fn remove_folder_password(
        &mut self,
        folder_id: &VaultId,
    ) -> Result<()> {
        let authenticated_user = self
            .storage
            .authenticated_user_mut()
            .ok_or(AuthenticationError::NotAuthenticated)?;
        Ok(authenticated_user.remove_folder_password(folder_id).await?)
    }

    async fn save_folder_password(
        &mut self,
        folder_id: &VaultId,
        key: AccessKey,
    ) -> Result<()> {
        let authenticated_user = self
            .storage
            .authenticated_user_mut()
            .ok_or(AuthenticationError::NotAuthenticated)?;
        Ok(authenticated_user
            .save_folder_password(folder_id, key)
            .await?)
    }
}
