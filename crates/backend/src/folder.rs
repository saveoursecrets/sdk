//! Folder combines an access point with an event log.
use crate::{AccessPoint, BackendTarget, Error, FolderEventLog, Result};
use sos_core::{
    commit::{CommitHash, CommitState},
    crypto::AccessKey,
    encode,
    events::{EventLog, EventLogType, EventRecord, ReadEvent, WriteEvent},
    AccountId, VaultFlags, VaultId,
};
use sos_core::{constants::EVENT_LOG_EXT, decode, VaultCommit};
use sos_database::{
    entity::{FolderEntity, FolderRecord, SecretRecord},
    VaultDatabaseWriter,
};
use sos_filesystem::VaultFileWriter;
use sos_reducers::FolderReducer;
use sos_vault::{
    secret::{Secret, SecretId, SecretMeta, SecretRow},
    AccessPoint as VaultAccessPoint, EncryptedEntry, SecretAccess, Vault,
    VaultMeta,
};
use sos_vfs as vfs;
use std::{path::Path, sync::Arc};
use tokio::sync::{Mutex, RwLock};

/// Folder is a combined vault and event log.
#[derive(Clone)]
pub struct Folder {
    access_point: Arc<Mutex<AccessPoint>>,
    events: Arc<RwLock<FolderEventLog>>,
}

impl Folder {
    /// Create a new folder.
    ///
    /// Changes to the in-memory vault are mirrored to storage.
    pub async fn new(
        target: BackendTarget,
        account_id: &AccountId,
        folder_id: &VaultId,
    ) -> Result<Self> {
        match target {
            BackendTarget::FileSystem(paths) => {
                Self::from_path(
                    paths.with_account_id(account_id).vault_path(folder_id),
                    account_id,
                    EventLogType::Folder(*folder_id),
                )
                .await
            }
            BackendTarget::Database(paths, client) => {
                let folder_id = *folder_id;
                let folder_row = client
                    .conn(move |conn| {
                        let folder = FolderEntity::new(&conn);
                        Ok(folder.find_one(&folder_id)?)
                    })
                    .await
                    .map_err(sos_database::Error::from)?;
                let folder_record =
                    FolderRecord::from_row(folder_row).await?;
                let mut vault = folder_record.into_vault()?;

                let secrets = client
                    .conn_and_then(move |conn| {
                        let folder = FolderEntity::new(&conn);
                        let secrets =
                            folder.load_secrets(folder_record.row_id)?;
                        Ok::<_, sos_database::Error>(secrets)
                    })
                    .await?;

                for secret in secrets {
                    let record = SecretRecord::from_row(secret).await?;
                    let VaultCommit(commit, entry) = record.commit;
                    vault
                        .insert_secret(record.secret_id, commit, entry)
                        .await?;
                }

                let mut event_log = FolderEventLog::new_folder(
                    BackendTarget::Database(paths, client.clone()),
                    &account_id,
                    &folder_id,
                )
                .await?;

                event_log.load_tree().await?;

                if event_log.tree().len() == 0 {
                    let buffer = encode(&vault).await?;
                    let event = WriteEvent::CreateVault(buffer);
                    event_log.apply(&[event]).await?;
                }

                let mirror =
                    VaultDatabaseWriter::<Error>::new(client, folder_id);
                let access_point = VaultAccessPoint::<Error>::new_mirror(
                    vault,
                    Box::new(mirror),
                );

                Ok(Self::init(AccessPoint::wrap(access_point), event_log))
            }
        }
    }

    /// Create a new folder using a vault and events.
    pub async fn from_vault_event_log(
        target: &BackendTarget,
        vault: Vault,
        event_log: FolderEventLog,
    ) -> Result<Self> {
        let access_point = match target {
            BackendTarget::FileSystem(paths) => {
                let path = paths.vault_path(vault.id());
                let mirror = VaultFileWriter::<Error>::new(path);
                VaultAccessPoint::<Error>::new_mirror(vault, Box::new(mirror))
            }
            BackendTarget::Database(_, client) => {
                let mirror = VaultDatabaseWriter::<Error>::new(
                    client.clone(),
                    *vault.id(),
                );
                VaultAccessPoint::<Error>::new_mirror(vault, Box::new(mirror))
            }
        };
        Ok(Self::init(AccessPoint::wrap(access_point), event_log))
    }

    /// Create a new folder from a vault on disc.
    ///
    /// Changes to the in-memory vault are mirrored to disc and
    /// and if an event log does not exist it is created.
    ///
    /// If an event log exists the commit tree is loaded into memory.
    pub async fn from_path(
        path: impl AsRef<Path>,
        account_id: &AccountId,
        log_type: EventLogType,
    ) -> Result<Self> {
        let mut events_path = path.as_ref().to_owned();
        events_path.set_extension(EVENT_LOG_EXT);

        let mut event_log =
            sos_filesystem::FolderEventLog::<Error>::new_folder(
                events_path,
                *account_id,
                log_type,
            )
            .await?;
        event_log.load_tree().await?;
        let needs_init = event_log.tree().root().is_none();

        let vault = if needs_init {
            let vault = if vfs::try_exists(path.as_ref()).await? {
                // For the client-side we must split the events
                // out but keep the existing vault data (not the head-only)
                // version so that the event log here will match what the
                // server will have when an account is first synced
                let buffer = vfs::read(path.as_ref()).await?;
                let vault: Vault = decode(&buffer).await?;
                vault
            } else {
                // If it doesn't exist on disc use a default vault
                Default::default()
            };

            let (_, events) =
                FolderReducer::split::<Error>(vault.clone()).await?;
            event_log.apply(events.as_slice()).await?;

            vault
        } else {
            let buffer = vfs::read(path.as_ref()).await?;
            let vault: Vault = decode(&buffer).await?;
            vault
        };

        let mirror = VaultFileWriter::<Error>::new(path.as_ref());
        let access_point =
            VaultAccessPoint::<Error>::new_mirror(vault, Box::new(mirror));

        Ok(Self::init(
            AccessPoint::wrap(access_point),
            FolderEventLog::FileSystem(event_log),
        ))
    }

    /// Create a new folder.
    fn init(access_point: AccessPoint, events: FolderEventLog) -> Self {
        Self {
            access_point: Arc::new(Mutex::new(access_point)),
            events: Arc::new(RwLock::new(events)),
        }
    }

    /// Folder identifier.
    pub async fn id(&self) -> VaultId {
        let access_point = self.access_point.lock().await;
        *access_point.id()
    }

    /// Access point for this folder.
    pub fn access_point(&self) -> Arc<Mutex<AccessPoint>> {
        self.access_point.clone()
    }

    /// Clone of the event log.
    pub fn event_log(&self) -> Arc<RwLock<FolderEventLog>> {
        Arc::clone(&self.events)
    }

    /// Unlock using the folder access key.
    pub async fn unlock(
        &mut self,
        key: &AccessKey,
    ) -> crate::Result<VaultMeta> {
        let mut access_point = self.access_point.lock().await;
        Ok(access_point.unlock(key).await?)
    }

    /// Lock the folder.
    pub async fn lock(&mut self) {
        let mut access_point = self.access_point.lock().await;
        access_point.lock();
    }

    /// Create a secret.
    pub async fn create_secret(
        &mut self,
        secret_data: &SecretRow,
    ) -> crate::Result<WriteEvent> {
        let mut access_point = self.access_point.lock().await;
        let event = access_point.create_secret(secret_data).await?;
        let mut events = self.events.write().await;
        events.apply(&[event.clone()]).await?;
        Ok(event)
    }

    /// Get a secret and it's meta data.
    pub async fn read_secret(
        &self,
        id: &SecretId,
    ) -> crate::Result<Option<(SecretMeta, Secret, ReadEvent)>> {
        let access_point = self.access_point.lock().await;
        Ok(access_point.read_secret(id).await?)
    }

    /// Read the encrypted contents of a secret.
    pub async fn raw_secret(
        &self,
        id: &SecretId,
    ) -> crate::Result<Option<(VaultCommit, ReadEvent)>> {
        let access_point = self.access_point.lock().await;
        Ok(access_point.raw_secret(id).await?)
    }

    /// Update a secret.
    pub async fn update_secret(
        &mut self,
        id: &SecretId,
        secret_meta: SecretMeta,
        secret: Secret,
    ) -> crate::Result<Option<WriteEvent>> {
        let mut access_point = self.access_point.lock().await;
        if let Some(event) =
            access_point.update_secret(id, secret_meta, secret).await?
        {
            let mut events = self.events.write().await;
            events.apply(&[event.clone()]).await?;
            Ok(Some(event))
        } else {
            Ok(None)
        }
    }

    /// Delete a secret and it's meta data.
    pub async fn delete_secret(
        &mut self,
        id: &SecretId,
    ) -> Result<Option<WriteEvent>> {
        let mut access_point = self.access_point.lock().await;
        if let Some(event) = access_point.delete_secret(id).await? {
            let mut events = self.events.write().await;
            events.apply(&[event.clone()]).await?;
            Ok(Some(event))
        } else {
            Ok(None)
        }
    }

    /// Set the name of the folder.
    pub async fn rename_folder(
        &mut self,
        name: impl AsRef<str>,
    ) -> Result<WriteEvent> {
        let mut access_point = self.access_point.lock().await;
        access_point
            .set_vault_name(name.as_ref().to_owned())
            .await?;
        let event = WriteEvent::SetVaultName(name.as_ref().to_owned());
        let mut events = self.events.write().await;
        events.apply(&[event.clone()]).await?;
        Ok(event)
    }

    /// Set the folder flags.
    pub async fn update_folder_flags(
        &mut self,
        flags: VaultFlags,
    ) -> Result<WriteEvent> {
        let mut access_point = self.access_point.lock().await;
        access_point.set_vault_flags(flags.clone()).await?;
        let event = WriteEvent::SetVaultFlags(flags);
        let mut events = self.events.write().await;
        events.apply(&[event.clone()]).await?;
        Ok(event)
    }

    /// Description of this folder.
    pub async fn description(&self) -> Result<String> {
        let access_point = self.access_point.lock().await;
        let meta = access_point.vault_meta().await?;
        Ok(meta.description().to_owned())
    }

    /// Set the description of this folder.
    pub async fn set_description(
        &mut self,
        description: impl AsRef<str>,
    ) -> Result<WriteEvent> {
        let mut meta = {
            let access_point = self.access_point.lock().await;
            access_point.vault_meta().await?
        };
        meta.set_description(description.as_ref().to_owned());
        self.set_meta(&meta).await
    }

    /// Set the folder meta data.
    pub async fn set_meta(&mut self, meta: &VaultMeta) -> Result<WriteEvent> {
        let mut access_point = self.access_point.lock().await;
        let event = access_point.set_vault_meta(meta).await?;
        let mut events = self.events.write().await;
        events.apply(&[event.clone()]).await?;
        Ok(event)
    }

    /// Folder commit state.
    pub async fn commit_state(&self) -> Result<CommitState> {
        let event_log = self.events.read().await;
        Ok(event_log.tree().commit_state()?)
    }

    /// Folder root commit hash.
    pub async fn root_hash(&self) -> Result<CommitHash> {
        let event_log = self.events.read().await;
        Ok(event_log
            .tree()
            .root()
            .ok_or(sos_core::Error::NoRootCommit)?)
    }

    /// Apply events to the event log.
    pub async fn apply(&mut self, events: &[WriteEvent]) -> Result<()> {
        let mut event_log = self.events.write().await;
        event_log.apply(events).await?;
        Ok(())
    }

    /// Apply event records to the event log.
    pub async fn apply_records(
        &mut self,
        records: Vec<EventRecord>,
    ) -> Result<()> {
        let mut event_log = self.events.write().await;
        event_log.apply_records(records).await?;
        Ok(())
    }

    /// Clear events from the event log.
    pub async fn clear(&mut self) -> Result<()> {
        let mut event_log = self.events.write().await;
        event_log.clear().await?;
        Ok(())
    }
}

impl From<Folder> for Vault {
    fn from(value: Folder) -> Self {
        let mutex = Arc::into_inner(value.access_point).unwrap();
        let access_point = mutex.into_inner();
        access_point.into()
    }
}
