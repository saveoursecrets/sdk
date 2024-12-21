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
        let mut watchers = self.watchers.lock();
        let has_watcher = watchers.get(&account_id).is_some();
        if !has_watcher {
            let (tx, mut rx) = broadcast::channel::<Event>(32);
            let channel = self.channel.clone();
            let id = account_id.clone();
            let task_accounts = self.accounts.clone();
            tokio::task::spawn(async move {
                while let Ok(event) = rx.recv().await {
                    let path = event
                        .paths
                        .get(0)
                        .ok_or(FileEventError::NoEventPath)?;
                    let name = path.file_stem().ok_or(
                        FileEventError::EventPathStem(path.to_owned()),
                    )?;

                    // Get a diff of the events either for the
                    // account log or for a specific folder
                    let records = if name == "account" {
                        let accounts = task_accounts.read().await;
                        let account = accounts
                            .iter()
                            .find(|a| a.address() == &id)
                            .ok_or(FileEventError::NoAccount(id))?;

                        let storage = account.storage().await.unwrap();
                        let storage = storage.read().await;

                        let mut event_log = storage.account_log.write().await;
                        let commit = event_log.tree().last_commit();

                        let patch =
                            event_log.diff_events(commit.as_ref()).await?;
                        let records =
                            patch.into_events::<AccountEvent>().await?;

                        event_log.load_tree().await?;

                        ChangeRecords::Account(records)
                    } else {
                        let folder_id: VaultId = name
                            .to_string_lossy()
                            .into_owned()
                            .parse()
                            .map_err(SdkError::from)?;

                        let accounts = task_accounts.read().await;
                        let account = accounts
                            .iter()
                            .find(|a| a.address() == &id)
                            .ok_or(FileEventError::NoAccount(id))?;

                        let storage = account.storage().await.unwrap();
                        let storage = storage.read().await;
                        let folder = storage
                            .cache()
                            .get(&folder_id)
                            .ok_or(FileEventError::NoFolder(folder_id))?;

                        let event_log = folder.event_log();
                        let mut event_log = event_log.write().await;
                        let commit = event_log.tree().last_commit();
                        let patch =
                            event_log.diff_events(commit.as_ref()).await?;
                        let records =
                            patch.into_events::<WriteEvent>().await?;

                        event_log.load_tree().await?;

                        ChangeRecords::Folder(folder_id, records)
                    };

                    {
                        let mut accounts = task_accounts.write().await;
                        if let Some(account) =
                            accounts.iter_mut().find(|a| a.address() == &id)
                        {
                            update_account_search_index(account, &records)
                                .await
                                .map_err(|e| {
                                    FileEventError::UpdateSearchIndex(
                                        e.to_string(),
                                    )
                                })?;
                        }
                    }

                    let evt = AccountChangeEvent {
                        account_id: id.clone(),
                        records,
                    };

                    if let Err(e) = channel.send(evt) {
                        tracing::error!(error = ?e);
                    }
                }

                Ok::<_, Error>(())
            });

            let mut watcher =
                recommended_watcher(move |res: notify::Result<Event>| {
                    match res {
                        Ok(event) => {
                            if let Err(e) = tx.send(event) {
                                tracing::error!(error = %e);
                            }
                        }
                        Err(e) => {
                            tracing::error!(error = %e);
                        }
                    }
                })?;

            watcher.watch(
                &paths.account_events(),
                RecursiveMode::NonRecursive,
            )?;

            for id in &folder_ids {
                watcher.watch(
                    &paths.event_log_path(id),
                    RecursiveMode::NonRecursive,
                )?;
            }
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
                watcher.unwatch(&paths.event_log_path(id))?;
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
    let index = account.index().await?;
    let mut index = index.write().await;

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
        let storage = storage.read().await;
        if let Some(folder) = storage.cache().get(&folder_id) {
            let keeper = folder.keeper();
            match records {
                ChangeRecords::Account(events) => {
                    for event in events {
                        match event {
                            AccountEvent::CreateFolder(_, _) => {
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
