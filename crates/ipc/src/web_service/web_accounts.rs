use crate::{Error, FileEventError, Result};
use notify::{
    recommended_watcher, Event, RecommendedWatcher, RecursiveMode, Watcher,
};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use sos_account::{Account, AccountSwitcher};
use sos_backend::BackendTarget;
use sos_core::{
    events::{AccountEvent, EventLog, WriteEvent},
    AccountId, ErrorExt, Paths, VaultId,
};
use sos_login::DelegatedAccess;
use sos_sync::SyncStorage;
use sos_vault::SecretAccess;
use std::{collections::HashMap, sync::Arc};
use tokio::sync::{broadcast, RwLock};

/// Event broadcast when an account changes on disc.
#[typeshare::typeshare]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountChangeEvent {
    /// Account identifier.
    pub account_id: AccountId,
    /// Event records with information about the changes.
    pub records: ChangeRecords,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ChangeRecords {
    /// Account level events.
    Account(Vec<AccountEvent>),
    /// Folder level events.
    Folder(VaultId, Vec<WriteEvent>),
}

impl ChangeRecords {
    /// Determine if the records are empty.
    pub fn is_empty(&self) -> bool {
        match self {
            Self::Account(records) => records.is_empty(),
            Self::Folder(_, records) => records.is_empty(),
        }
    }
}

/// User accounts for the web service.
pub struct WebAccounts<A, R, E>
where
    A: Account<Error = E, NetworkResult = R> + SyncStorage,
    R: 'static,
    E: std::fmt::Debug
        + std::error::Error
        + ErrorExt
        + From<sos_core::Error>
        + From<sos_database::Error>
        + From<sos_account::Error>
        + From<sos_backend::Error>
        + From<sos_vault::Error>
        + From<sos_search::Error>
        + From<std::io::Error>
        + Send
        + Sync
        + 'static,
{
    accounts: Arc<RwLock<AccountSwitcher<A, R, E>>>,
    watchers: Arc<Mutex<HashMap<AccountId, RecommendedWatcher>>>,
    channel: broadcast::Sender<AccountChangeEvent>,
}

impl<A, R, E> Clone for WebAccounts<A, R, E>
where
    A: Account<Error = E, NetworkResult = R> + SyncStorage,
    R: 'static,
    E: std::fmt::Debug
        + std::error::Error
        + ErrorExt
        + From<sos_core::Error>
        + From<sos_database::Error>
        + From<sos_account::Error>
        + From<sos_backend::Error>
        + From<sos_vault::Error>
        + From<sos_search::Error>
        + From<std::io::Error>
        + Send
        + Sync
        + 'static,
{
    fn clone(&self) -> Self {
        Self {
            accounts: self.accounts.clone(),
            watchers: self.watchers.clone(),
            channel: self.channel.clone(),
        }
    }
}

impl<A, R, E> WebAccounts<A, R, E>
where
    A: Account<Error = E, NetworkResult = R>
        + SyncStorage
        + DelegatedAccess<Error = E>,
    R: 'static,
    E: std::fmt::Debug
        + std::error::Error
        + ErrorExt
        + From<sos_core::Error>
        + From<sos_database::Error>
        + From<sos_account::Error>
        + From<sos_backend::Error>
        + From<sos_vault::Error>
        + From<sos_search::Error>
        + From<std::io::Error>
        + Send
        + Sync
        + 'static,
{
    /// Create new accounts.
    pub fn new(accounts: Arc<RwLock<AccountSwitcher<A, R, E>>>) -> Self {
        let (tx, _) = broadcast::channel::<AccountChangeEvent>(64);
        Self {
            accounts,
            watchers: Arc::new(Mutex::new(HashMap::new())),
            channel: tx,
        }
    }

    /// Create a backend target for the accounts.
    pub async fn backend_target(&self) -> Result<BackendTarget> {
        let accounts = self.accounts.read().await;
        let paths = if let Some(paths) = accounts.paths() {
            paths
        } else {
            Paths::new_client(Paths::data_dir().unwrap())
        };
        Ok(BackendTarget::from_paths(&paths).await?)
    }

    /// Subscribe to change events.
    pub fn subscribe(&self) -> broadcast::Receiver<AccountChangeEvent> {
        self.channel.subscribe()
    }

    /// Start watching an account for changes.
    pub fn watch(
        &self,
        account_id: AccountId,
        paths: Arc<Paths>,
        folder_ids: Vec<VaultId>,
    ) -> Result<()> {
        let has_watcher = {
            let watchers = self.watchers.lock();
            watchers.get(&account_id).is_some()
        };

        if !has_watcher {
            let (tx, rx) = broadcast::channel::<Event>(32);
            let channel = self.channel.clone();
            let task_id = account_id.clone();
            let task_paths = paths.clone();
            let task_accounts = self.accounts.clone();
            let task_watchers = self.watchers.clone();
            tokio::task::spawn(async move {
                if let Err(e) = notify_listener(
                    task_id,
                    task_paths,
                    task_accounts,
                    task_watchers,
                    rx,
                    channel,
                )
                .await
                {
                    tracing::error!(error = %e, "notify_listener");
                }
            });

            let mut watcher = recommended_watcher(
                move |res: notify::Result<Event>| match res {
                    Ok(event) => {
                        if let Err(e) = tx.send(event) {
                            tracing::error!(error = %e, "file_system_notify_channel::send");
                        }
                    }
                    Err(e) => {
                        tracing::error!(error = %e, "notify::error");
                    }
                },
            )?;

            watcher.watch(
                &paths.identity_events(),
                RecursiveMode::NonRecursive,
            )?;

            for id in &folder_ids {
                watch_folder(id, &*paths, &mut watcher)?;
            }

            let mut watchers = self.watchers.lock();
            watchers.insert(account_id, watcher);
        }
        Ok(())
    }

    /// Stop watching an account for changes.
    pub fn unwatch(
        &self,
        account_id: &AccountId,
        paths: Arc<Paths>,
        folder_ids: Vec<VaultId>,
    ) -> Result<bool> {
        let mut watchers = self.watchers.lock();
        if let Some(mut watcher) = watchers.remove(account_id) {
            watcher.watch(
                &paths.identity_events(),
                RecursiveMode::NonRecursive,
            )?;
            for id in &folder_ids {
                unwatch_folder(id, &*paths, &mut watcher)?;
            }
            Ok(true)
        } else {
            Ok(false)
        }
    }
}

impl<A, R, E> AsRef<Arc<RwLock<AccountSwitcher<A, R, E>>>>
    for WebAccounts<A, R, E>
where
    A: Account<Error = E, NetworkResult = R> + SyncStorage,
    R: 'static,
    E: std::fmt::Debug
        + std::error::Error
        + ErrorExt
        + From<sos_core::Error>
        + From<sos_database::Error>
        + From<sos_account::Error>
        + From<sos_backend::Error>
        + From<sos_vault::Error>
        + From<sos_search::Error>
        + From<std::io::Error>
        + Send
        + Sync
        + 'static,
{
    fn as_ref(&self) -> &Arc<RwLock<AccountSwitcher<A, R, E>>> {
        &self.accounts
    }
}

/// Update the search index for an account.
async fn update_account_search_index<A, R, E>(
    account: &mut A,
    records: &ChangeRecords,
) -> std::result::Result<(), E>
where
    A: Account<Error = E, NetworkResult = R>
        + SyncStorage
        + DelegatedAccess<Error = E>,
    R: 'static,
    E: std::fmt::Debug
        + std::error::Error
        + ErrorExt
        + From<sos_core::Error>
        + From<sos_account::Error>
        + From<sos_database::Error>
        + From<sos_backend::Error>
        + From<sos_vault::Error>
        + From<sos_search::Error>
        + From<std::io::Error>
        + Send
        + Sync
        + 'static,
{
    let paths = account.paths();
    let index = account.search_index().await?;

    let folder_ids = match records {
        ChangeRecords::Account(events) => {
            let mut folder_ids = Vec::new();
            for event in events {
                match event {
                    AccountEvent::CreateFolder(folder_id, _) => {
                        folder_ids.push(*folder_id);
                    }
                    AccountEvent::DeleteFolder(folder_id) => {
                        folder_ids.push(*folder_id)
                    }
                    _ => {}
                }
            }
            folder_ids
        }
        ChangeRecords::Folder(folder_id, _) => vec![*folder_id],
    };

    for folder_id in folder_ids {
        match records {
            ChangeRecords::Account(events) => {
                for event in events {
                    match event {
                        AccountEvent::CreateFolder(_, _) => {
                            // Find the folder password which should be available
                            // as the identity folder has been reloaded already
                            let key = account
                                .find_folder_password(&folder_id)
                                .await?
                                .ok_or(
                                    sos_account::Error::NoFolderPassword(
                                        folder_id,
                                    ),
                                )?;
                            // Import the vault into the account
                            account
                                .import_folder(
                                    paths.vault_path(&folder_id),
                                    key,
                                    true,
                                )
                                .await?;

                            // Now the storage should have the folder so
                            // we can access the access point and add it to
                            // the search index
                            if let Some(folder) =
                                account.folder(&folder_id).await.ok()
                            {
                                let access_point = folder.access_point();
                                let access_point = access_point.lock().await;
                                let mut index = index.write().await;
                                index.add_folder(&*access_point).await?;
                            }
                        }
                        AccountEvent::DeleteFolder(_) => {
                            let mut index = index.write().await;
                            index.remove_vault(&folder_id);
                        }
                        _ => {}
                    }
                }
            }
            ChangeRecords::Folder(folder_id, events) => {
                if let Some(folder) = account.folder(&folder_id).await.ok() {
                    let access_point = folder.access_point();
                    let mut access_point = access_point.lock().await;

                    // Must reload the vault before updating the
                    // search index
                    let path = paths.vault_path(folder_id);
                    access_point.reload_vault(path).await?;

                    for event in events {
                        match event {
                            WriteEvent::CreateSecret(secret_id, _) => {
                                if let Some((meta, secret, _)) = access_point
                                    .read_secret(secret_id)
                                    .await?
                                {
                                    let mut index = index.write().await;
                                    index.add(
                                        folder_id, secret_id, &meta, &secret,
                                    );
                                }
                            }
                            WriteEvent::UpdateSecret(secret_id, _) => {
                                if let Some((meta, secret, _)) = access_point
                                    .read_secret(secret_id)
                                    .await?
                                {
                                    let mut index = index.write().await;
                                    index.update(
                                        folder_id, secret_id, &meta, &secret,
                                    );
                                }
                            }
                            WriteEvent::DeleteSecret(secret_id) => {
                                let mut index = index.write().await;
                                index.remove(folder_id, secret_id);
                            }
                            _ => {}
                        }
                    }
                }
            }
        }
    }

    Ok(())
}

async fn notify_listener<A, R, E>(
    account_id: AccountId,
    paths: Arc<Paths>,
    accounts: Arc<RwLock<AccountSwitcher<A, R, E>>>,
    watchers: Arc<Mutex<HashMap<AccountId, RecommendedWatcher>>>,
    mut rx: broadcast::Receiver<notify::Event>,
    channel: broadcast::Sender<AccountChangeEvent>,
) -> Result<()>
where
    A: Account<Error = E, NetworkResult = R>
        + SyncStorage
        + DelegatedAccess<Error = E>
        + Sync
        + Send
        + 'static,
    R: 'static,
    E: std::fmt::Debug
        + std::error::Error
        + ErrorExt
        + From<sos_core::Error>
        + From<sos_database::Error>
        + From<sos_account::Error>
        + From<sos_backend::Error>
        + From<sos_vault::Error>
        + From<sos_search::Error>
        + From<std::io::Error>
        + Send
        + Sync
        + 'static,
{
    let account_name = account_id.to_string();

    while let Ok(event) = rx.recv().await {
        let path = event.paths.get(0).ok_or(FileEventError::NoEventPath)?;
        let name = path
            .file_stem()
            .ok_or(FileEventError::EventPathStem(path.to_owned()))?
            .to_string_lossy()
            .into_owned();

        tracing::debug!(
          file_stem = %name,
          account_name = %account_name,
          "notify_listener::change_event");

        // Identity folder event log changes
        let records = if name == account_name {
            let mut accounts = accounts.write().await;
            let account = accounts
                .iter_mut()
                .find(|a| a.account_id() == &account_id)
                .ok_or(FileEventError::NoAccount(account_id))?;

            // Reload the login folder
            {
                account.reload_login_folder().await.map_err(|e| {
                    FileEventError::ReloadIdentityFolder(e.to_string())
                })?;
            }

            let records = load_account_records(account).await?;

            // Check for folder create events and start watching new
            // folder as they are created.
            {
                let mut watchers = watchers.lock();
                for record in &records {
                    if let (
                        AccountEvent::CreateFolder(folder_id, _),
                        Some(watcher),
                    ) = (record, watchers.get_mut(&account_id))
                    {
                        watch_folder(&folder_id, &*paths, watcher)?;
                    }
                }
            }

            // Update folders in memory
            {
                tracing::debug!("account_change::load_folders");
                if let Err(e) = account.load_folders().await {
                    tracing::error!(error = %e);
                }
            }

            ChangeRecords::Account(records)
        } else {
            let folder_id: VaultId = name.parse()?;

            // Event log was removed so we can treat
            // as a folder delete event, we should
            // stop watching the folder.
            if event.kind.is_remove() {
                {
                    let mut watchers = watchers.lock();
                    if let Some(watcher) = watchers.get_mut(&account_id) {
                        unwatch_folder(&folder_id, &*paths, watcher)?;
                    }
                }

                {
                    let mut accounts = accounts.write().await;
                    let account = accounts
                        .iter_mut()
                        .find(|a| a.account_id() == &account_id)
                        .ok_or(FileEventError::NoAccount(account_id))?;

                    account.forget_folder(&folder_id).await.ok();
                }
                ChangeRecords::Folder(folder_id, vec![])
            } else {
                let accounts = accounts.read().await;
                let account = accounts
                    .iter()
                    .find(|a| a.account_id() == &account_id)
                    .ok_or(FileEventError::NoAccount(account_id))?;

                let folder = account
                    .folder(&folder_id)
                    .await
                    .ok()
                    .ok_or(FileEventError::NoFolder(folder_id))?;

                let event_log = folder.event_log();
                let mut event_log = event_log.write().await;
                let commit = event_log.tree().last_commit();
                let patch = event_log.diff_events(commit.as_ref()).await?;
                let records = patch.into_events::<WriteEvent>().await?;

                event_log.load_tree().await?;

                ChangeRecords::Folder(folder_id, records)
            }
        };

        // Update the search index
        {
            let mut accounts = accounts.write().await;

            if let Some(account) =
                accounts.iter_mut().find(|a| a.account_id() == &account_id)
            {
                update_account_search_index(account, &records)
                    .await
                    .map_err(|e| {
                        FileEventError::UpdateSearchIndex(e.to_string())
                    })?;
            }
        }

        if !records.is_empty() {
            // Dispatch the event
            let evt = AccountChangeEvent {
                account_id,
                records,
            };
            if let Err(e) = channel.send(evt) {
                tracing::error!(
                error = ?e,
                "account_channel::send");
            }
        }
    }

    Ok::<_, Error>(())
}

async fn load_account_records<A, R, E>(
    account: &A,
) -> Result<Vec<AccountEvent>>
where
    A: Account<Error = E, NetworkResult = R>
        + SyncStorage
        + Sync
        + Send
        + 'static,
    R: 'static,
    E: std::fmt::Debug
        + std::error::Error
        + ErrorExt
        + From<sos_core::Error>
        + From<sos_account::Error>
        + From<sos_database::Error>
        + From<sos_backend::Error>
        + From<sos_vault::Error>
        + From<sos_search::Error>
        + From<std::io::Error>
        + Send
        + Sync
        + 'static,
{
    // FIXME: update the error handling to avoid the unwrap
    let account_log = account.account_log().await.unwrap();
    let mut event_log = account_log.write().await;
    let commit = event_log.tree().last_commit();

    let patch = event_log.diff_events(commit.as_ref()).await?;
    let records = patch.into_events::<AccountEvent>().await?;

    event_log.load_tree().await?;
    Ok(records)
}

/// Start watching folder event log.
fn watch_folder(
    folder_id: &VaultId,
    paths: &Paths,
    watcher: &mut RecommendedWatcher,
) -> Result<()> {
    tracing::debug!(folder_id = %folder_id, "watch::folder");
    watcher.watch(
        &paths.event_log_path(folder_id),
        RecursiveMode::NonRecursive,
    )?;
    Ok(())
}

/// Stop watching folder event log.
fn unwatch_folder(
    folder_id: &VaultId,
    paths: &Paths,
    watcher: &mut RecommendedWatcher,
) -> Result<()> {
    tracing::debug!(folder_id = %folder_id, "unwatch::folder");
    watcher.unwatch(&paths.event_log_path(folder_id))?;
    Ok(())
}
