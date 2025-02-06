use crate::{Error, Result};
use async_trait::async_trait;
use futures::{pin_mut, StreamExt};
use indexmap::IndexSet;
use sos_audit::AuditStreamSink;
use sos_backend::{
    AccountEventLog, BackendTarget, DeviceEventLog, FileEventLog,
    FolderEventLog,
};
use sos_client_storage::ClientStorage;
use sos_core::{
    decode, encode,
    events::{EventLog, EventRecord},
    VaultId,
};
use sos_core::{Origin, VaultCommit};
use sos_core::{Paths, PublicIdentity, SecretId};
use sos_database::{
    async_sqlite::{rusqlite::Transaction, Client},
    entity::{
        AccountEntity, AccountRow, AuditEntity, EventEntity, EventRecordRow,
        FolderEntity, FolderRow, PreferenceEntity, PreferenceRow, SecretRow,
        ServerEntity, SystemMessageEntity, SystemMessageRow,
    },
};
use sos_filesystem::audit_provider::AuditFileProvider;
use sos_preferences::PreferenceMap;
use sos_server_storage::ServerStorage;
use sos_sync::{StorageEventLogs, SyncStatus, SyncStorage};
use sos_system_messages::SystemMessageMap;
use sos_vault::{list_local_folders, Summary, Vault};
use sos_vfs as vfs;
use std::{collections::HashMap, sync::Arc};
use tokio::sync::RwLock;

pub(crate) enum AccountStorage {
    Server(ServerStorage),
    Client(ClientStorage),
}

impl AccountStorage {
    pub(crate) async fn sync_status(&self) -> Result<SyncStatus> {
        Ok(match self {
            AccountStorage::Server(server) => server.sync_status().await?,
            AccountStorage::Client(client) => client.sync_status().await?,
        })
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl StorageEventLogs for AccountStorage {
    type Error = Error;

    async fn identity_log(&self) -> Result<Arc<RwLock<FolderEventLog>>> {
        Ok(match self {
            AccountStorage::Server(fs) => fs.identity_log().await?,
            AccountStorage::Client(db) => db.identity_log().await?,
        })
    }

    async fn account_log(&self) -> Result<Arc<RwLock<AccountEventLog>>> {
        Ok(match self {
            AccountStorage::Server(fs) => fs.account_log().await?,
            AccountStorage::Client(db) => db.account_log().await?,
        })
    }

    async fn device_log(&self) -> Result<Arc<RwLock<DeviceEventLog>>> {
        Ok(match self {
            AccountStorage::Server(fs) => fs.device_log().await?,
            AccountStorage::Client(db) => db.device_log().await?,
        })
    }

    async fn file_log(&self) -> Result<Arc<RwLock<FileEventLog>>> {
        Ok(match self {
            AccountStorage::Server(fs) => fs.file_log().await?,
            AccountStorage::Client(db) => db.file_log().await?,
        })
    }

    async fn folder_details(&self) -> Result<IndexSet<Summary>> {
        Ok(match self {
            AccountStorage::Server(fs) => fs.folder_details().await?,
            AccountStorage::Client(db) => db.folder_details().await?,
        })
    }

    async fn folder_log(
        &self,
        id: &VaultId,
    ) -> Result<Arc<RwLock<FolderEventLog>>> {
        Ok(match self {
            AccountStorage::Server(fs) => fs.folder_log(id).await?,
            AccountStorage::Client(db) => db.folder_log(id).await?,
        })
    }
}

/// Create global values in the database.
pub(crate) async fn import_globals(
    client: &mut Client,
    paths: &Paths,
) -> Result<()> {
    let global_preferences =
        Paths::new_global(paths.documents_dir().to_owned())
            .preferences_file();
    let global_preferences = if vfs::try_exists(&global_preferences).await? {
        let contents = vfs::read_to_string(global_preferences).await?;
        let map: PreferenceMap = serde_json::from_str(&contents)?;
        let mut rows = Vec::new();
        for (key, value) in map.iter() {
            rows.push(PreferenceRow::new_insert(&key, &value)?);
        }
        Some(rows)
    } else {
        None
    };

    let mut audit_events = Vec::new();
    if vfs::try_exists(paths.audit_file()).await? {
        let log_file = AuditFileProvider::<sos_filesystem::Error>::new(
            paths.audit_file(),
        );
        let stream = log_file.audit_stream(false).await?;
        pin_mut!(stream);
        while let Some(event) = stream.next().await {
            let event = event?;
            audit_events.push((&event).try_into()?);
        }
    }

    client
        .conn_mut(move |conn| {
            let tx = conn.transaction()?;
            let audit_entity = AuditEntity::new(&tx);
            audit_entity.insert_audit_logs(audit_events.as_slice())?;
            if let Some(rows) = global_preferences {
                let pref_entity = PreferenceEntity::new(&tx);
                pref_entity.insert_preferences(None, rows.as_slice())?;
            }
            tx.commit()?;
            Ok(())
        })
        .await?;

    Ok(())
}

/// Create an account in the database.
pub(crate) async fn import_account(
    fs_storage: AccountStorage,
    client: &mut Client,
    paths: &Paths,
    account: &PublicIdentity,
) -> Result<AccountStorage> {
    debug_assert!(!paths.is_global());

    let is_server = paths.is_server();
    let account_name = account.label().to_owned();
    let account_row =
        AccountRow::new_insert(account.account_id(), account_name)?;

    // Identity folder
    let buffer = vfs::read(paths.identity_vault()).await?;
    let identity_vault: Vault = decode(&buffer).await?;
    let identity_vault_meta =
        if let Some(meta) = identity_vault.header().meta() {
            Some(encode(meta).await?)
        } else {
            None
        };
    let identity_rows = collect_vault_rows(&identity_vault).await?;
    let identity_events =
        collect_folder_events(fs_storage.identity_log().await?).await?;

    // Account events
    let account_events =
        collect_account_events(fs_storage.account_log().await?).await?;

    // Device vault
    let device_info = if !is_server {
        let buffer = vfs::read(paths.device_file()).await?;
        let device_vault: Vault = decode(&buffer).await?;
        let device_vault_meta =
            if let Some(meta) = device_vault.header().meta() {
                Some(encode(meta).await?)
            } else {
                None
            };
        let device_rows = collect_vault_rows(&device_vault).await?;
        Some((device_vault, device_vault_meta, device_rows))
    } else {
        None
    };

    // Device events
    let device_events =
        collect_device_events(fs_storage.device_log().await?).await?;

    // File events
    let file_events =
        collect_file_events(fs_storage.file_log().await?).await?;

    // User folders
    let mut folders = Vec::new();
    let user_folders = list_local_folders(paths).await?;
    for (summary, path) in user_folders {
        let buffer = vfs::read(path).await?;
        let vault: Vault = decode(&buffer).await?;
        let vault_meta = if let Some(meta) = vault.header().meta() {
            Some(encode(meta).await?)
        } else {
            None
        };
        let rows = collect_vault_rows(&vault).await?;
        let events =
            collect_folder_events(fs_storage.folder_log(summary.id()).await?)
                .await?;
        folders.push((vault, vault_meta, rows, events));
    }

    let account_preferences = if vfs::try_exists(paths.preferences_file())
        .await?
    {
        let contents = vfs::read_to_string(paths.preferences_file()).await?;
        let map: PreferenceMap = serde_json::from_str(&contents)?;
        let mut rows = Vec::new();
        for (key, value) in map.iter() {
            rows.push(PreferenceRow::new_insert(&key, &value)?);
        }
        Some(rows)
    } else {
        None
    };

    let account_messages =
        if vfs::try_exists(paths.system_messages_file()).await? {
            let contents =
                vfs::read_to_string(paths.system_messages_file()).await?;
            let map: SystemMessageMap = serde_json::from_str(&contents)?;

            let mut rows: Vec<SystemMessageRow> = Vec::new();
            for item in map.into_iter() {
                rows.push(item.try_into()?);
            }
            Some(rows)
        } else {
            None
        };

    let remote_servers = if vfs::try_exists(paths.remote_origins()).await? {
        let buffer = vfs::read(paths.remote_origins()).await?;
        let origins = serde_json::from_slice::<Vec<Origin>>(&buffer)?;
        let mut rows = Vec::new();
        for origin in origins {
            rows.push(origin.try_into()?);
        }
        Some(rows)
    } else {
        None
    };

    client
        .conn_mut_and_then(move |conn| {
            let tx = conn.transaction()?;

            // Create the account
            let account_entity = AccountEntity::new(&tx);
            let account_id = account_entity.insert(&account_row)?;

            // Create the identity login folder
            let (identity_folder_id, _) = create_folder(
                &tx,
                account_id,
                identity_vault,
                identity_vault_meta,
                identity_rows,
                Some(identity_events),
            )?;

            // Create the join entry for the account login folder
            account_entity
                .insert_login_folder(account_id, identity_folder_id)?;

            // Create the device folder without events
            // as it is configured for SYSTEM | DEVICE | NO_SYNC
            if !is_server {
                let (device_vault, device_vault_meta, device_rows) =
                    device_info.unwrap();
                let (device_folder_id, _) = create_folder(
                    &tx,
                    account_id,
                    device_vault,
                    device_vault_meta,
                    device_rows,
                    None,
                )?;

                // Create the join entry for the device folder
                account_entity
                    .insert_device_folder(account_id, device_folder_id)?;
            }

            // Create the account events
            let event_entity = EventEntity::new(&tx);
            event_entity.insert_account_events(
                account_id,
                account_events.as_slice(),
            )?;

            // Create the device events
            event_entity
                .insert_device_events(account_id, device_events.as_slice())?;

            // Create user folders
            let mut folder_ids = HashMap::new();
            for (vault, vault_meta, rows, events) in folders {
                let id = *vault.id();
                let folder_id = create_folder(
                    &tx,
                    account_id,
                    vault,
                    vault_meta,
                    rows,
                    Some(events),
                )?;
                folder_ids.insert(id, folder_id);
            }

            {
                // Create the file events
                event_entity
                    .insert_file_events(account_id, file_events.as_slice())?;
            }

            if let Some(json_data) = account_preferences {
                let pref_entity = PreferenceEntity::new(&tx);
                pref_entity
                    .insert_preferences(Some(account_id), &json_data)?;
            }

            if let Some(rows) = account_messages {
                let msg_entity = SystemMessageEntity::new(&tx);
                msg_entity
                    .insert_system_messages(account_id, &rows.as_slice())?;
            }

            if let Some(servers) = remote_servers {
                let server_entity = ServerEntity::new(&tx);
                server_entity
                    .insert_servers(account_id, servers.as_slice())?;
            }

            tx.commit()?;
            Ok::<_, Error>(())
        })
        .await?;

    let db_storage = if paths.is_server() {
        AccountStorage::Server(
            ServerStorage::new(
                paths,
                account.account_id(),
                BackendTarget::Database(client.clone()),
            )
            .await?,
        )
    } else {
        AccountStorage::Client(
            ClientStorage::new_unauthenticated(
                paths,
                account.account_id(),
                BackendTarget::Database(client.clone()),
            )
            .await?,
        )
    };

    Ok(db_storage)
}

async fn collect_vault_rows(vault: &Vault) -> Result<Vec<SecretRow>> {
    let mut rows = Vec::new();
    for (secret_id, commit) in vault.iter() {
        let VaultCommit(commit, entry) = commit;
        rows.push(SecretRow::new(secret_id, commit, entry).await?);
    }
    Ok(rows)
}

async fn collect_account_events(
    event_log: Arc<RwLock<AccountEventLog>>,
) -> Result<Vec<EventRecordRow>> {
    let mut events = Vec::new();
    let event_log = event_log.read().await;
    let stream = event_log.event_stream(false).await;
    pin_mut!(stream);
    while let Some(record) = stream.next().await {
        events.push(convert_event_row(&record?.0)?);
    }
    Ok(events)
}

async fn collect_folder_events(
    event_log: Arc<RwLock<FolderEventLog>>,
) -> Result<Vec<EventRecordRow>> {
    let mut events = Vec::new();
    let event_log = event_log.read().await;
    let stream = event_log.event_stream(false).await;
    pin_mut!(stream);
    while let Some(record) = stream.next().await {
        events.push(convert_event_row(&record?.0)?);
    }
    Ok(events)
}

async fn collect_device_events(
    event_log: Arc<RwLock<DeviceEventLog>>,
) -> Result<Vec<EventRecordRow>> {
    let mut events = Vec::new();
    let event_log = event_log.read().await;
    let stream = event_log.event_stream(false).await;
    pin_mut!(stream);
    while let Some(record) = stream.next().await {
        events.push(convert_event_row(&record?.0)?);
    }
    Ok(events)
}

async fn collect_file_events(
    event_log: Arc<RwLock<FileEventLog>>,
) -> Result<Vec<EventRecordRow>> {
    let mut events = Vec::new();
    let event_log = event_log.read().await;
    let stream = event_log.event_stream(false).await;
    pin_mut!(stream);
    while let Some(record) = stream.next().await {
        events.push(convert_event_row(&record?.0)?);
    }
    Ok(events)
}

fn convert_event_row(record: &EventRecord) -> Result<EventRecordRow> {
    Ok(EventRecordRow::new(record)?)
}

fn create_folder(
    tx: &Transaction<'_>,
    account_id: i64,
    vault: Vault,
    meta: Option<Vec<u8>>,
    rows: Vec<SecretRow>,
    events: Option<Vec<EventRecordRow>>,
) -> Result<(i64, HashMap<SecretId, i64>)> {
    let salt = vault.salt().cloned();
    let folder_entity = FolderEntity::new(tx);
    let folder_id = folder_entity.insert_folder(
        account_id,
        &FolderRow::new_insert_parts(vault.summary(), salt, meta)?,
    )?;
    let secret_ids =
        folder_entity.insert_folder_secrets(folder_id, rows.as_slice())?;
    if let Some(events) = events {
        // Insert the event rows
        let event_entity = EventEntity::new(tx);
        event_entity.insert_folder_events(folder_id, events.as_slice())?;
    }
    Ok((folder_id, secret_ids))
}
