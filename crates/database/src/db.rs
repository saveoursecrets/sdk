use crate::Result;
use async_sqlite::{
    rusqlite::{CachedStatement, Error as SqlError, Transaction},
    Client,
};
use futures::{pin_mut, StreamExt};
use sos_sdk::{
    events::{AccountEventLog, DeviceEventLog, FileEventLog},
    prelude::{
        decode, encode, vfs, CommitHash, Error as SdkError, EventLogExt,
        EventRecord, FolderEventLog, Identity, Paths, PublicIdentity,
        SecretId, Vault, VaultCommit, VaultEntry,
    },
};
use std::path::Path;

/// Create an account in the database.
pub async fn import_account(
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
                let identity_folder_id = create_folder(
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
                let device_folder_id = create_folder(
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
                for (vault, rows, events) in folders {
                  create_folder(
                      &mut tx,
                      account_id,
                      vault,
                      rows,
                      Some(events),
                  )
                  .await?;
                }

                // TODO: file blobs

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
) -> std::result::Result<i64, SqlError> {
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

    Ok(folder_id)
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
