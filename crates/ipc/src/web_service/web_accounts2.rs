use crate::{Error, FileEventError, Result};
use serde::{Deserialize, Serialize};
use sos_account::{Account, AccountSwitcher};
use sos_backend::BackendTarget;
use sos_changes::consumer::ConsumerHandle;
use sos_core::{
    events::{
        AccountEvent, EventLog, EventLogType, LocalChangeEvent, WriteEvent,
    },
    AccountId, ErrorExt, Paths, VaultId,
};
use sos_login::DelegatedAccess;
use sos_sync::SyncStorage;
use sos_vault::SecretAccess;
use std::{collections::HashSet, sync::Arc};
use tokio::sync::{broadcast, RwLock};

/// Event broadcast when an account changes.
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
    watched_accounts: HashSet<AccountId>,
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
            watched_accounts: self.watched_accounts.clone(),
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
            watched_accounts: HashSet::new(),
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

    /// Start listening for changes.
    pub fn listen_changes(
        &self,
        mut changes_consumer: ConsumerHandle,
        paths: Arc<Paths>,
        change_handler: impl Fn(LocalChangeEvent) + Send + Sync + 'static,
    ) -> Result<()> {
        // Start a background task to listen for change events
        let channel = self.channel.clone();
        let task_accounts = self.accounts.clone();

        tokio::task::spawn(async move {
            let receiver = changes_consumer.changes();

            while let Some(event) = receiver.recv().await {
                tracing::debug!(
                    event = ?event,
                    "change_consumer::event_received"
                );

                if let Err(e) = process_change_event(
                    &event,
                    AccountId::default(),
                    paths.clone(),
                    task_accounts.clone(),
                    channel.clone(),
                )
                .await
                {
                    tracing::error!(error = %e, "process_change_event");
                }

                change_handler(event);
            }

            tracing::debug!("consumer_task_completed");
        });

        Ok(())
    }

    /// Start watching an account for changes.
    pub fn watch(&mut self, account_id: AccountId) {
        self.watched_accounts.insert(account_id);
    }

    /// Stop watching for changes.
    pub fn unwatch(&mut self, account_id: &AccountId) {
        self.watched_accounts.remove(account_id);
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

/// Process change events and update the system state accordingly
async fn process_change_event<A, R, E>(
    event: &LocalChangeEvent,
    _account_id: AccountId,
    _paths: Arc<Paths>,
    accounts: Arc<RwLock<AccountSwitcher<A, R, E>>>,
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
    match event {
        LocalChangeEvent::Init => {
            // Just initialization, nothing to do
            Ok(())
        }
        LocalChangeEvent::AccountCreated(account_id) => {
            // New account created
            // NOTE: This would need implementation if we want to handle new accounts
            tracing::debug!(account_id = %account_id, "account_created_event");
            // TODO: Implement account creation handling if needed
            Ok(())
        }
        LocalChangeEvent::AccountDeleted(account_id) => {
            // Account deleted
            tracing::debug!(account_id = %account_id, "account_deleted_event");
            // TODO: Implement account deletion handling if needed
            Ok(())
        }
        LocalChangeEvent::AccountModified {
            account_id,
            log_type,
            commit_span: _,
        } => {
            // Account was modified - process changes based on log_type
            tracing::debug!(account_id = %account_id, log_type = ?log_type, "account_modified_event");

            match log_type {
                EventLogType::Identity
                | EventLogType::Account
                | EventLogType::Device => {
                    // Account-level changes
                    let mut accounts_lock = accounts.write().await;
                    let account = accounts_lock
                        .iter_mut()
                        .find(|a| a.account_id() == account_id)
                        .ok_or(Error::from(FileEventError::NoAccount(
                            account_id.clone(),
                        )))?;

                    // Reload the identity folder for account-level changes
                    account.reload_login_folder().await.map_err(|e| {
                        Error::from(FileEventError::ReloadIdentityFolder(
                            e.to_string(),
                        ))
                    })?;

                    // Load account events
                    let records = load_account_records(account).await?;

                    // Update folders in memory
                    tracing::debug!("account_change::load_folders");
                    if let Err(e) = account.load_folders().await {
                        tracing::error!(error = %e, "load_folders_error");
                    }

                    // Update search index
                    let records_clone =
                        ChangeRecords::Account(records.clone());
                    update_account_search_index(account, &records_clone)
                        .await
                        .map_err(|e| {
                            Error::from(FileEventError::UpdateSearchIndex(
                                e.to_string(),
                            ))
                        })?;

                    // Send event if there are records
                    if !records.is_empty() {
                        let evt = AccountChangeEvent {
                            account_id: account_id.clone(),
                            records: ChangeRecords::Account(records),
                        };
                        if let Err(e) = channel.send(evt) {
                            tracing::error!(error = ?e, "account_channel::send");
                        }
                    }
                    Ok(())
                }
                EventLogType::Folder(folder_id) => {
                    // Folder-level changes
                    let accounts_lock = accounts.read().await;
                    let account = accounts_lock
                        .iter()
                        .find(|a| a.account_id() == account_id)
                        .ok_or(Error::from(FileEventError::NoAccount(
                            account_id.clone(),
                        )))?;

                    let folder =
                        account.folder(&folder_id).await.ok().ok_or(
                            Error::from(FileEventError::NoFolder(*folder_id)),
                        )?;

                    let event_log = folder.event_log();
                    let mut event_log = event_log.write().await;
                    let commit = event_log.tree().last_commit();
                    let patch =
                        event_log.diff_events(commit.as_ref()).await?;
                    let records = patch.into_events::<WriteEvent>().await?;

                    event_log.load_tree().await?;

                    // Update search index for folder changes
                    {
                        let mut accounts_lock = accounts.write().await;
                        if let Some(account) = accounts_lock
                            .iter_mut()
                            .find(|a| a.account_id() == account_id)
                        {
                            let records_clone = ChangeRecords::Folder(
                                *folder_id,
                                records.clone(),
                            );
                            update_account_search_index(
                                account,
                                &records_clone,
                            )
                            .await
                            .map_err(|e| {
                                Error::from(
                                    FileEventError::UpdateSearchIndex(
                                        e.to_string(),
                                    ),
                                )
                            })?;
                        }
                    }

                    // Send event if there are records
                    if !records.is_empty() {
                        let evt = AccountChangeEvent {
                            account_id: account_id.clone(),
                            records: ChangeRecords::Folder(
                                *folder_id, records,
                            ),
                        };
                        if let Err(e) = channel.send(evt) {
                            tracing::error!(error = ?e, "account_channel::send");
                        }
                    }

                    Ok(())
                }
                #[cfg(feature = "files")]
                EventLogType::Files => {
                    // No need to handle file change events
                    Ok(())
                }
            }
        }
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
