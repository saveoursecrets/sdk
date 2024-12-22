use notify::{
    recommended_watcher, Event, RecommendedWatcher, RecursiveMode, Watcher,
};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use sos_protocol::{Merge, SyncStorage};
use sos_sdk::{
    events::{AccountEvent, EventLogExt, WriteEvent},
    prelude::{
        Account, AccountSwitcher, Address, Error as SdkError, ErrorExt, Paths,
    },
    vault::VaultId,
};
use std::{collections::HashMap, sync::Arc};
use tokio::sync::{broadcast, RwLock};

use crate::{Error, FileEventError, Result};

/// Event broadcast when an account changes on disc.
#[typeshare::typeshare]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountChangeEvent {
    /// Account identifier.
    pub account_id: Address,
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
    A: Account<Error = E, NetworkResult = R>
        + SyncStorage
        + Merge
        + Sync
        + Send
        + 'static,
    R: 'static,
    E: std::fmt::Debug
        + std::error::Error
        + ErrorExt
        + From<sos_sdk::Error>
        + From<std::io::Error>
        + 'static,
{
    accounts: Arc<RwLock<AccountSwitcher<A, R, E>>>,
    watchers: Arc<Mutex<HashMap<Address, RecommendedWatcher>>>,
    channel: broadcast::Sender<AccountChangeEvent>,
}

impl<A, R, E> Clone for WebAccounts<A, R, E>
where
    A: Account<Error = E, NetworkResult = R>
        + SyncStorage
        + Merge
        + Sync
        + Send
        + 'static,
    R: 'static,
    E: std::fmt::Debug
        + std::error::Error
        + ErrorExt
        + From<sos_sdk::Error>
        + From<std::io::Error>
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
        + Merge
        + Sync
        + Send
        + 'static,
    R: 'static,
    E: std::fmt::Debug
        + std::error::Error
        + ErrorExt
        + From<sos_sdk::Error>
        + From<std::io::Error>
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

    /// Subscribe to change events.
    pub fn subscribe(&self) -> broadcast::Receiver<AccountChangeEvent> {
        self.channel.subscribe()
    }

    /// Start watching an account for changes.
    pub fn watch(
        &self,
        account_id: Address,
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
                &paths.account_events(),
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
        account_id: &Address,
        paths: Arc<Paths>,
        folder_ids: Vec<VaultId>,
    ) -> Result<bool> {
        let mut watchers = self.watchers.lock();
        if let Some(mut watcher) = watchers.remove(account_id) {
            watcher.unwatch(&paths.account_events())?;
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
    A: Account<Error = E, NetworkResult = R>
        + SyncStorage
        + Merge
        + Sync
        + Send
        + 'static,
    R: 'static,
    E: std::fmt::Debug
        + std::error::Error
        + ErrorExt
        + From<sos_sdk::Error>
        + From<std::io::Error>
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
        + Merge
        + Sync
        + Send
        + 'static,
    R: 'static,
    E: std::fmt::Debug
        + std::error::Error
        + ErrorExt
        + From<sos_sdk::Error>
        + From<std::io::Error>
        + 'static,
{
    let paths = account.paths();
    let index = account.index().await?;
    let mut index = index.write().await;

    // {"timestamp":"2024-12-22T02:27:25.999834Z","level":"ERROR","fields":{"message":"notify_listener","error":"failed to update search index, reason: vault must be unlocked"},"target":"sos_ipc::web_service::web_accounts"}

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
        let storage = account.storage().await.unwrap();
        let mut storage = storage.write().await;
        if let Some(folder) = storage.cache_mut().get_mut(&folder_id) {
            let keeper = folder.keeper_mut();
            match records {
                ChangeRecords::Account(events) => {
                    for event in events {
                        match event {
                            AccountEvent::CreateFolder(_, _) => {
                                let path = paths.vault_path(&folder_id);
                                keeper.reload_vault(path).await?;

                                index.add_folder(keeper).await?;
                            }
                            AccountEvent::DeleteFolder(_) => {
                                index.remove_folder(keeper).await?;
                            }
                            _ => {}
                        }
                    }
                }
                ChangeRecords::Folder(folder_id, events) => {
                    // Must reload the vault before updating the
                    // search index
                    let path = paths.vault_path(folder_id);
                    keeper.reload_vault(path).await?;

                    for event in events {
                        match event {
                            WriteEvent::CreateSecret(secret_id, _) => {
                                if let Some((meta, secret, _)) =
                                    keeper.read_secret(secret_id).await?
                                {
                                    index.add(
                                        folder_id, secret_id, &meta, &secret,
                                    );
                                }
                            }
                            WriteEvent::UpdateSecret(secret_id, _) => {
                                if let Some((meta, secret, _)) =
                                    keeper.read_secret(secret_id).await?
                                {
                                    index.update(
                                        folder_id, secret_id, &meta, &secret,
                                    );
                                }
                            }
                            WriteEvent::DeleteSecret(secret_id) => {
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
    account_id: Address,
    paths: Arc<Paths>,
    accounts: Arc<RwLock<AccountSwitcher<A, R, E>>>,
    watchers: Arc<Mutex<HashMap<Address, RecommendedWatcher>>>,
    mut rx: broadcast::Receiver<notify::Event>,
    channel: broadcast::Sender<AccountChangeEvent>,
) -> Result<()>
where
    A: Account<Error = E, NetworkResult = R>
        + SyncStorage
        + Merge
        + Sync
        + Send
        + 'static,
    R: 'static,
    E: std::fmt::Debug
        + std::error::Error
        + ErrorExt
        + From<sos_sdk::Error>
        + From<std::io::Error>
        + 'static,
{
    while let Ok(event) = rx.recv().await {
        let path = event.paths.get(0).ok_or(FileEventError::NoEventPath)?;
        let name = path
            .file_stem()
            .ok_or(FileEventError::EventPathStem(path.to_owned()))?;

        // Get a diff of the events either for the
        // account log or for a specific folder
        let records = if name == "account" {
            tracing::debug!(
              account_id = %account_id,
              "account_change");

            let records = {
                let accounts = accounts.read().await;
                let account = accounts
                    .iter()
                    .find(|a| a.address() == &account_id)
                    .ok_or(FileEventError::NoAccount(account_id))?;

                let storage = account.storage().await.unwrap();
                let storage = storage.read().await;

                let mut event_log = storage.account_log.write().await;
                let commit = event_log.tree().last_commit();

                let patch = event_log.diff_events(commit.as_ref()).await?;
                let records = patch.into_events::<AccountEvent>().await?;

                event_log.load_tree().await?;
                records
            };

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
                let mut accounts = accounts.write().await;
                let account = accounts
                    .iter_mut()
                    .find(|a| a.address() == &account_id)
                    .ok_or(FileEventError::NoAccount(account_id))?;
                tracing::debug!("account_change::load_folders");
                if let Err(e) = account.load_folders().await {
                    tracing::error!(error = %e);
                }
            }

            ChangeRecords::Account(records)
        } else {
            let folder_id: VaultId = name
                .to_string_lossy()
                .into_owned()
                .parse()
                .map_err(SdkError::from)?;

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
                    let accounts = accounts.read().await;
                    let account = accounts
                        .iter()
                        .find(|a| a.address() == &account_id)
                        .ok_or(FileEventError::NoAccount(account_id))?;

                    let storage = account.storage().await.unwrap();
                    let mut storage = storage.write().await;
                    storage.remove_folder(&folder_id).await?;
                }
                ChangeRecords::Folder(folder_id, vec![])
            } else {
                let accounts = accounts.read().await;
                let account = accounts
                    .iter()
                    .find(|a| a.address() == &account_id)
                    .ok_or(FileEventError::NoAccount(account_id))?;

                let storage = account.storage().await.unwrap();
                let storage = storage.read().await;
                let folder = storage
                    .cache()
                    .get(&folder_id)
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
                accounts.iter_mut().find(|a| a.address() == &account_id)
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
