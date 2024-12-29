use crate::Result;
use async_sqlite::{
    rusqlite::{CachedStatement, Error as SqlError, Transaction},
    Client,
};
use futures::{pin_mut, StreamExt};
use sos_sdk::prelude::{
    AuditLogFile,
    AuditEvent,
    AccountEventLog, DeviceEventLog, FileEventLog,
    decode, encode, list_external_files, vfs, CommitHash,
    Error as SdkError, EventLogExt, EventRecord, ExternalFile,
    FolderEventLog, Identity, Paths, PublicIdentity, SecretId, Vault,
    VaultCommit, VaultEntry,
    FormatStreamIterator,
    VaultId,
};
use sos_protocol::Origin;
use std::{collections::HashMap, path::Path};

/// Create global values in the database.
pub(crate) async fn import_globals(
    client: &mut Client,
    paths: &Paths,
) -> Result<()> {
    let global_preferences =
        Paths::new_global(paths.documents_dir().to_owned())
            .preferences_file();
    let global_preferences = if vfs::try_exists(&global_preferences)
        .await
        .map_err(SdkError::from)?
    {
        Some(
            vfs::read_to_string(global_preferences)
                .await
                .map_err(SdkError::from)?,
        )
    } else {
        None
    };

    let mut audit_events = Vec::new();
    if vfs::try_exists(paths.audit_file()).await.map_err(SdkError::from)? {
        let log_file = AuditLogFile::new(paths.audit_file()).await?;
        let mut file = vfs::File::open(paths.audit_file()).await.map_err(SdkError::from)?;
        let mut it = log_file.iter(false).await?;
        while let Some(record) = it.next().await? {
            let event = log_file.read_event(&mut file, &record).await?;
            let data = if let Some(data) = event.data() {
                Some(serde_json::to_string(data).map_err(SdkError::from)?)
            } else { None };
            audit_events.push((event.time().to_rfc3339()?, event, data));
        }
    }

    client
        .conn_mut(move |conn| {
            let mut tx = conn.transaction()?;
            futures::executor::block_on(async {
                create_audit_logs(&mut tx, audit_events).await?;
                if let Some(json_data) = global_preferences {
                    create_preferences(&mut tx, None, json_data).await?;
                }
                Ok::<_, SqlError>(())
            })?;
            tx.commit()?;
            Ok(())
        }).await?;
    
    Ok(())

}

/// Create an account in the database.
pub(crate) async fn import_account(
    client: &mut Client,
    paths: &Paths,
    account: &PublicIdentity,
) -> Result<()> {
    let account_identifier = account.address().to_string();
    let account_name = account.label().to_owned();

    // Identity folder
    let buffer = vfs::read(paths.identity_vault())
        .await
        .map_err(SdkError::from)?;
    let identity_vault: Vault = decode(&buffer).await?;
    let identity_rows = collect_vault_rows(&identity_vault).await?;
    let identity_events =
        collect_folder_events(paths.identity_events()).await?;

    // Account events
    let account_events =
        collect_account_events(paths.account_events()).await?;

    // Device vault
    let buffer = vfs::read(paths.device_file())
        .await
        .map_err(SdkError::from)?;
    let device_vault: Vault = decode(&buffer).await?;
    let device_rows = collect_vault_rows(&device_vault).await?;

    // Device events
    let device_events = collect_device_events(paths.device_events()).await?;

    // File events
    let file_events = collect_file_events(paths.file_events()).await?;

    // User folders
    let mut folders = Vec::new();
    let user_folders = Identity::list_local_folders(paths).await?;
    for (summary, path) in user_folders {
        let buffer = vfs::read(path).await.map_err(SdkError::from)?;
        let vault: Vault = decode(&buffer).await?;
        let rows = collect_vault_rows(&vault).await?;
        let events =
            collect_folder_events(paths.event_log_path(summary.id())).await?;
        folders.push((vault, rows, events));
    }

    let mut user_files = Vec::new();
    let files = list_external_files(&paths).await?;
    for file in files {
        let path = paths.file_location(
            file.vault_id(),
            file.secret_id(),
            file.file_name().to_string(),
        );
        let buffer = vfs::read(path).await.map_err(SdkError::from)?;
        user_files.push((file, buffer));
    }

    let account_preferences = if vfs::try_exists(paths.preferences_file())
        .await
        .map_err(SdkError::from)?
    {
        Some(
            vfs::read_to_string(paths.preferences_file())
                .await
                .map_err(SdkError::from)?,
        )
    } else {
        None
    };

    let remote_servers = if vfs::try_exists(paths.remote_origins())
        .await
        .map_err(SdkError::from)?
    {
        let buffer = vfs::read(paths.remote_origins())
                .await
                .map_err(SdkError::from)?;
        Some(serde_json::from_slice::<Vec<Origin>>(&buffer).map_err(SdkError::from)?)
    } else {
        None
    };

    client
        .conn_mut(move |conn| {
            let mut tx = conn.transaction()?;

            futures::executor::block_on(async {
                    
                // Create the account
                let account_id = {
                    tx.execute(
                        r#"
                          INSERT INTO accounts (identifier, name)
                          VALUES (?1, ?2)
                        "#,
                        (&account_identifier, &account_name),
                    )?;
                    tx.last_insert_rowid()
                };

                // Create the identity folder
                let (identity_folder_id, _) = create_folder(
                    &mut tx,
                    account_id,
                    identity_vault,
                    identity_rows,
                    Some(identity_events),
                )
                .await?;
                // Create the join entry for the account login folder
                tx.execute(
                    r#"
                      INSERT INTO account_login_folder (account_id, folder_id) 
                      VALUES (?1, ?2)
                    "#,
                    (&account_id, &identity_folder_id),
                )?;

                // Create the device folder without events
                // as it is configured for SYSTEM | DEVICE | NO_SYNC
                let (device_folder_id, _) = create_folder(
                    &mut tx,
                    account_id,
                    device_vault,
                    device_rows,
                    None,
                )
                .await?;
                // Create the join entry for the device folder
                tx.execute(
                    r#"
                      INSERT INTO account_device_folder (account_id, folder_id) 
                      VALUES (?1, ?2)
                    "#,
                    (&account_id, &device_folder_id),
                )?;

                // Create the account events
                create_account_events(&mut tx, account_id, account_events)
                    .await?;

                // Create the device events
                create_device_events(&mut tx, account_id, device_events)
                    .await?;

                // Create the file events
                create_file_events(&mut tx, account_id, file_events).await?;

                // Create user folders
                let mut folder_ids = HashMap::new();
                for (vault, rows, events) in folders {
                    let id = *vault.id();
                    let folder_id = create_folder(
                      &mut tx,
                      account_id,
                      vault,
                      rows,
                      Some(events),
                    )
                    .await?;
                    folder_ids.insert(id, folder_id);
                }

                create_files(&mut tx, &folder_ids, user_files).await?;

                if let Some(json_data) = account_preferences {
                    create_preferences(&mut tx, Some(account_id), json_data).await?;
                }

                if let Some(servers) = remote_servers {
                    create_servers(&mut tx, account_id, servers).await?;
                }

                Ok::<_, SqlError>(())
            })?;

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

async fn create_folder(
    tx: &mut Transaction<'_>,
    account_id: i64,
    vault: Vault,
    rows: Vec<(SecretId, CommitHash, Vec<u8>, Vec<u8>)>,
    events: Option<Vec<(String, CommitHash, EventRecord)>>,
) -> std::result::Result<(i64, HashMap<SecretId, i64>), SqlError> {
    // Insert folder meta data and get folder_id
    let folder_id = {
        let identifier = vault.id().to_string();
        let name = vault.name().to_string();
        let version = vault.summary().version();
        let cipher = vault.summary().cipher().to_string();
        let kdf = vault.summary().kdf().to_string();
        let flags = vault.summary().flags().bits().to_le_bytes();

        let mut stmt = tx.prepare_cached(
            r#"
              INSERT INTO folders
                (account_id, identifier, name, version, cipher, kdf, flags)
                VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
            "#,
        )?;
        stmt.execute((
            &account_id,
            &identifier,
            &name,
            &version,
            &cipher,
            &kdf,
            &flags,
        ))?;

        tx.last_insert_rowid()
    };

    // Insert the vault secret rows
    let mut secret_ids = HashMap::new();
    {
        let mut stmt = tx.prepare_cached(
            r#"
              INSERT INTO folder_secrets
                (folder_id, identifier, commit_hash, meta, secret)
                VALUES (?1, ?2, ?3, ?4, ?5)
            "#,
        )?;
        for (identifier, commit_hash, meta, secret) in rows {
            stmt.execute((
                &folder_id,
                &identifier.to_string(),
                commit_hash.to_string(),
                &meta,
                &secret,
            ))?;
            secret_ids.insert(identifier, tx.last_insert_rowid());
        }
    }

    // Insert the event rows
    if let Some(events) = events {
        let stmt = tx.prepare_cached(
            r#"
              INSERT INTO folder_events
              (folder_id, created_at, commit_hash, event)
              VALUES (?1, ?2, ?3, ?4)"#,
        )?;
        create_events(stmt, folder_id, events).await?;
    }

    Ok((folder_id, secret_ids))
}

async fn create_account_events(
    tx: &mut Transaction<'_>,
    account_id: i64,
    events: Vec<(String, CommitHash, EventRecord)>,
) -> std::result::Result<(), SqlError> {
    let stmt = tx.prepare_cached(
        r#"
          INSERT INTO account_events
            (account_id, created_at, commit_hash, event)
            VALUES (?1, ?2, ?3, ?4)
        "#,
    )?;
    create_events(stmt, account_id, events).await
}

async fn create_device_events(
    tx: &mut Transaction<'_>,
    account_id: i64,
    events: Vec<(String, CommitHash, EventRecord)>,
) -> std::result::Result<(), SqlError> {
    let stmt = tx.prepare_cached(
        r#"
          INSERT INTO device_events
            (account_id, created_at, commit_hash, event)
            VALUES (?1, ?2, ?3, ?4)
        "#,
    )?;
    create_events(stmt, account_id, events).await
}

async fn create_file_events(
    tx: &mut Transaction<'_>,
    account_id: i64,
    events: Vec<(String, CommitHash, EventRecord)>,
) -> std::result::Result<(), SqlError> {
    let stmt = tx.prepare_cached(
        r#"
          INSERT INTO file_events
            (account_id, created_at, commit_hash, event)
            VALUES (?1, ?2, ?3, ?4)
        "#,
    )?;
    create_events(stmt, account_id, events).await
}

async fn create_events(
    mut stmt: CachedStatement<'_>,
    id: i64,
    events: Vec<(String, CommitHash, EventRecord)>,
) -> std::result::Result<(), SqlError> {
    for (time, commit, record) in events {
        stmt.execute((&id, time, commit.to_string(), record.event_bytes()))?;
    }
    Ok(())
}

async fn create_files(
    tx: &mut Transaction<'_>,
    folder_ids: &HashMap<VaultId, (i64, HashMap<SecretId, i64>)>,
    user_files: Vec<(ExternalFile, Vec<u8>)>,
) -> std::result::Result<(), SqlError> {
    for (file, contents) in user_files {
        if let Some((folder_id, secret_ids)) =
            folder_ids.iter().find_map(|(k, v)| {
                if k == file.vault_id() {
                    Some(v)
                } else {
                    None
                }
            })
        {
            if let Some(secret_id) = secret_ids.get(file.secret_id()) {
                let mut stmt = tx.prepare_cached(
                    r#"
                      INSERT INTO folder_files
                        (folder_id, secret_id, checksum, contents)
                        VALUES (?1, ?2, ?3, ?4)
                    "#,
                )?;
                stmt.execute((
                    folder_id,
                    secret_id,
                    file.file_name().to_string(),
                    contents,
                ))?;
            } else {
                tracing::warn!(
                    file = %file,
                    "db::import::no_secret_for_file",
                );
            }
        } else {
            tracing::warn!(
                file = %file,
                "db::import::no_folder_for_file",
            );
        }
    }
    Ok(())
}

async fn create_preferences(
    tx: &mut Transaction<'_>,
    account_id: Option<i64>,
    json_data: String,
) -> std::result::Result<(), SqlError> {
    let mut stmt = tx.prepare_cached(
        r#"
          INSERT INTO preferences
            (account_id, json_data)
            VALUES (?1, ?2)
        "#,
    )?;
    stmt.execute((account_id, json_data))?;
    Ok(())
}

async fn create_servers(
    tx: &mut Transaction<'_>,
    account_id: i64,
    servers: Vec<Origin>,
) -> std::result::Result<(), SqlError> {
    let mut stmt = tx.prepare_cached(
        r#"
          INSERT INTO servers
            (account_id, name, url)
            VALUES (?1, ?2, ?3)
        "#,
    )?;
        
    for server in servers {
        stmt.execute((account_id, server.name(), server.url().to_string()))?;
    }

    Ok(())
}

async fn create_audit_logs(
    tx: &mut Transaction<'_>,
    events: Vec<(String, AuditEvent, Option<String>)>,
) -> std::result::Result<(), SqlError> {
    let mut stmt = tx.prepare_cached(
        r#"
          INSERT INTO audit_logs
            (created_at, account_identifier, event_kind, event_data)
            VALUES (?1, ?2, ?3, ?4)
        "#,
    )?;
    for (time, event, data) in events {
        stmt.execute((time, event.address().to_string(), event.event_kind().to_string(), data))?;
    }
    Ok(())
}
