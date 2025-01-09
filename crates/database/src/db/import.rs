use super::{
    AccountEntity, AuditEntity, EventEntity, FolderEntity, PreferenceEntity,
    ServerEntity,
};
use crate::Result;
use async_sqlite::{
    rusqlite::{Error as SqlError, Transaction},
    Client,
};
use futures::{pin_mut, StreamExt};
use sos_audit::fs::{audit_stream, AuditLogFile};
use sos_core::Origin;
use sos_core::{commit::CommitHash, Paths, PublicIdentity, SecretId};
use sos_core::{
    decode, encode,
    events::{EventLog, EventRecord},
    VaultCommit, VaultEntry,
};
use sos_filesystem::{
    events::{
        AccountEventLog as FsAccountEventLog,
        DeviceEventLog as FsDeviceEventLog,
        FolderEventLog as FsFolderEventLog,
    },
    formats::FormatStreamIterator,
};
use sos_vault::list_local_folders;
use sos_vault::Vault;
use sos_vfs as vfs;
use std::{collections::HashMap, path::Path};

#[cfg(feature = "files")]
use {
    super::FileEntity, crate::files::list_external_files,
    sos_filesystem::events::FileEventLog as FsFileEventLog,
};

type AccountEventLog = FsAccountEventLog<sos_filesystem::Error>;
type DeviceEventLog = FsDeviceEventLog<sos_filesystem::Error>;
type FolderEventLog = FsFolderEventLog<sos_filesystem::Error>;
#[cfg(feature = "files")]
type FileEventLog = FsFileEventLog<sos_filesystem::Error>;

/// Create global values in the database.
pub(crate) async fn import_globals(
    client: &mut Client,
    paths: &Paths,
) -> Result<()> {
    let global_preferences =
        Paths::new_global(paths.documents_dir().to_owned())
            .preferences_file();
    let global_preferences = if vfs::try_exists(&global_preferences).await? {
        Some(vfs::read_to_string(global_preferences).await?)
    } else {
        None
    };

    let mut audit_events = Vec::new();
    if vfs::try_exists(paths.audit_file()).await? {
        let log_file = AuditLogFile::new(paths.audit_file()).await?;
        let mut file = vfs::File::open(paths.audit_file()).await?;
        let mut it = audit_stream(paths.audit_file(), false).await?;
        while let Some(record) = it.next().await? {
            let event = log_file.read_event(&mut file, &record).await?;
            let data = if let Some(data) = event.data() {
                Some(serde_json::to_string(data)?)
            } else {
                None
            };
            audit_events.push((event.time().to_rfc3339()?, event, data));
        }
    }

    client
        .conn_mut(move |conn| {
            let tx = conn.transaction()?;
            let audit_entity = AuditEntity::new(&tx);
            audit_entity.insert_audit_logs(audit_events)?;
            if let Some(json_data) = global_preferences {
                let pref_entity = PreferenceEntity::new(&tx);
                pref_entity.insert_preferences(None, json_data)?;
            }
            tx.commit()?;
            Ok(())
        })
        .await?;

    Ok(())
}

/// Create an account in the database.
pub(crate) async fn import_account(
    client: &mut Client,
    paths: &Paths,
    account: &PublicIdentity,
) -> Result<()> {
    let account_identifier = account.account_id().to_string();
    let account_name = account.label().to_owned();

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
        collect_folder_events(paths.identity_events()).await?;

    // Account events
    let account_events =
        collect_account_events(paths.account_events()).await?;

    // Device vault
    let buffer = vfs::read(paths.device_file()).await?;
    let device_vault: Vault = decode(&buffer).await?;
    let device_vault_meta = if let Some(meta) = device_vault.header().meta() {
        Some(encode(meta).await?)
    } else {
        None
    };
    let device_rows = collect_vault_rows(&device_vault).await?;

    // Device events
    let device_events = collect_device_events(paths.device_events()).await?;

    // File events
    #[cfg(feature = "files")]
    let file_events = collect_file_events(paths.file_events()).await?;

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
            collect_folder_events(paths.event_log_path(summary.id())).await?;
        folders.push((vault, vault_meta, rows, events));
    }

    #[cfg(feature = "files")]
    let user_files = {
        let mut user_files = Vec::new();
        let files = list_external_files(&paths).await?;
        for file in files {
            let path = paths.file_location(
                file.vault_id(),
                file.secret_id(),
                file.file_name().to_string(),
            );
            let buffer = vfs::read(path).await?;
            user_files.push((file, buffer));
        }
        user_files
    };

    let account_preferences =
        if vfs::try_exists(paths.preferences_file()).await? {
            Some(vfs::read_to_string(paths.preferences_file()).await?)
        } else {
            None
        };

    let remote_servers = if vfs::try_exists(paths.remote_origins()).await? {
        let buffer = vfs::read(paths.remote_origins()).await?;
        Some(serde_json::from_slice::<Vec<Origin>>(&buffer)?)
    } else {
        None
    };

    client
        .conn_mut(move |conn| {
            let tx = conn.transaction()?;

            // Create the account
            let account_entity = AccountEntity::new(&tx);
            let account_id =
                account_entity.insert(&account_identifier, &account_name)?;

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

            // Create the account events
            let event_entity = EventEntity::new(&tx);
            event_entity.insert_account_events(account_id, account_events)?;

            // Create the device events
            event_entity.insert_device_events(account_id, device_events)?;

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

            #[cfg(feature = "files")]
            {
                // Create the file events
                event_entity.insert_file_events(account_id, file_events)?;

                // Create the file blobs
                let file_entity = FileEntity::new(&tx);
                file_entity.insert_files(&folder_ids, user_files)?;
            }

            if let Some(json_data) = account_preferences {
                let pref_entity = PreferenceEntity::new(&tx);
                pref_entity
                    .insert_preferences(Some(account_id), json_data)?;
            }

            if let Some(servers) = remote_servers {
                let server_entity = ServerEntity::new(&tx);
                server_entity.insert_servers(account_id, servers)?;
            }

            tx.commit()?;
            Ok(())
        })
        .await?;

    Ok(())
}

async fn collect_vault_rows(
    vault: &Vault,
) -> Result<Vec<(SecretId, CommitHash, Vec<u8>, Vec<u8>)>> {
    let mut rows = Vec::new();
    for (identifier, commit) in vault.iter() {
        let VaultCommit(hash, entry) = commit;
        let VaultEntry(meta, secret) = entry;
        let meta = encode(meta).await?;
        let secret = encode(secret).await?;
        rows.push((*identifier, *hash, meta, secret));
    }
    Ok(rows)
}

async fn collect_account_events(
    path: impl AsRef<Path>,
) -> Result<Vec<(String, CommitHash, EventRecord)>> {
    let mut events = Vec::new();
    let event_log = AccountEventLog::new_account(path).await?;
    let stream = event_log.stream(false).await;
    pin_mut!(stream);
    while let Some(record) = stream.next().await {
        events.push(convert_event_row(record?.0)?);
    }
    Ok(events)
}

async fn collect_folder_events(
    path: impl AsRef<Path>,
) -> Result<Vec<(String, CommitHash, EventRecord)>> {
    let mut events = Vec::new();
    let event_log = FolderEventLog::new(path).await?;
    let stream = event_log.stream(false).await;
    pin_mut!(stream);
    while let Some(record) = stream.next().await {
        events.push(convert_event_row(record?.0)?);
    }
    Ok(events)
}

async fn collect_device_events(
    path: impl AsRef<Path>,
) -> Result<Vec<(String, CommitHash, EventRecord)>> {
    let mut events = Vec::new();
    let event_log = DeviceEventLog::new_device(path).await?;
    let stream = event_log.stream(false).await;
    pin_mut!(stream);
    while let Some(record) = stream.next().await {
        events.push(convert_event_row(record?.0)?);
    }
    Ok(events)
}

#[cfg(feature = "files")]
async fn collect_file_events(
    path: impl AsRef<Path>,
) -> Result<Vec<(String, CommitHash, EventRecord)>> {
    let mut events = Vec::new();
    let event_log = FileEventLog::new_file(path).await?;
    let stream = event_log.stream(false).await;
    pin_mut!(stream);
    while let Some(record) = stream.next().await {
        events.push(convert_event_row(record?.0)?);
    }
    Ok(events)
}

fn convert_event_row(
    record: EventRecord,
) -> Result<(String, CommitHash, EventRecord)> {
    Ok((record.time().to_rfc3339()?, *record.commit(), record))
}

fn create_folder(
    tx: &Transaction<'_>,
    account_id: i64,
    vault: Vault,
    meta: Option<Vec<u8>>,
    rows: Vec<(SecretId, CommitHash, Vec<u8>, Vec<u8>)>,
    events: Option<Vec<(String, CommitHash, EventRecord)>>,
) -> std::result::Result<(i64, HashMap<SecretId, i64>), SqlError> {
    let folder_entity = FolderEntity::new(tx);
    let folder_id =
        folder_entity.insert_folder(account_id, vault.summary(), meta)?;
    let secret_ids = folder_entity.insert_folder_secrets(folder_id, rows)?;
    if let Some(events) = events {
        // Insert the event rows
        let event_entity = EventEntity::new(tx);
        event_entity.insert_folder_events(folder_id, events)?;
    }
    Ok((folder_id, secret_ids))
}
