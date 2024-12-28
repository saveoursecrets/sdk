use crate::Result;
use async_sqlite::{
    rusqlite::{Error as SqlError, Transaction},
    Client,
};
use futures::{pin_mut, StreamExt};
use sos_sdk::prelude::{
    decode, encode, vfs, CommitHash, Error as SdkError, EventLogExt,
    EventRecord, FolderEventLog, Paths, PublicIdentity, SecretId, Vault,
    VaultCommit, VaultEntry,
};
use std::path::Path;

/// Create an account in the database.
pub async fn import_account(
    client: &mut Client,
    paths: &Paths,
    account: &PublicIdentity,
) -> Result<()> {
    let buffer = vfs::read(paths.identity_vault())
        .await
        .map_err(SdkError::from)?;

    let identity_vault: Vault = decode(&buffer).await?;
    let identity_rows = collect_vault_rows(&identity_vault).await?;
    let identity_events =
        collect_folder_events(paths.identity_events()).await?;

    let account_identifier = account.address().to_string();
    let account_name = account.label().to_owned();

    client
        .conn_mut(move |conn| {
            let mut tx = conn.transaction()?;

            futures::executor::block_on(async {
                // Create the account
                let account_id = {
                    tx.execute(
                      "INSERT INTO accounts (identifier, name) VALUES (?1, ?2)",
                      (&account_identifier, &account_name),
                    )?;
                    tx.last_insert_rowid()
                };

                // Create the identity folder first
                create_folder(
                  &mut tx,
                  account_id,
                  identity_vault,
                  identity_rows,
                  identity_events,
                ).await?;

                // TODO: devices folder
                // TODO: account events
                // TODO: user folders
                // TODO: file events
                // TODO: file blobs

                Ok::<_, SqlError>(())
            })?;

            tx.commit()?;
            Ok(())
        })
        .await?;

    todo!();
}

async fn collect_vault_rows(
    vault: &Vault,
) -> Result<Vec<(SecretId, Vec<u8>, Vec<u8>)>> {
    let mut rows = Vec::new();
    for (identifier, commit) in vault.iter() {
        let VaultCommit(_hash, entry) = commit;
        let VaultEntry(meta, secret) = entry;
        let meta = encode(meta).await?;
        let secret = encode(secret).await?;
        rows.push((*identifier, meta, secret));
    }
    Ok(rows)
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

fn convert_event_row(
    record: EventRecord,
) -> Result<(String, CommitHash, EventRecord)> {
    Ok((record.time().to_rfc3339()?, *record.commit(), record))
}

async fn create_folder(
    tx: &mut Transaction<'_>,
    account_id: i64,
    vault: Vault,
    rows: Vec<(SecretId, Vec<u8>, Vec<u8>)>,
    events: Vec<(String, CommitHash, EventRecord)>,
) -> std::result::Result<(), SqlError> {
    // Insert folder meta data and get folder_id
    let folder_id = {
        let identifier = vault.id().to_string();
        let name = vault.name().to_string();
        let version = vault.summary().version();
        let cipher = vault.summary().cipher().to_string();
        let kdf = vault.summary().kdf().to_string();
        let flags = vault.summary().flags().bits().to_le_bytes();

        let mut stmt = tx.prepare_cached(
            "INSERT INTO folders (account_id, identifier, name, version, cipher, kdf, flags) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
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

    // Insert the vault rows
    {
        let mut stmt = tx.prepare_cached(
            "INSERT INTO vaults (folder_id, identifier, meta, secret) VALUES (?1, ?2, ?3, ?4)",
        )?;
        for (identifier, meta, secret) in rows {
            stmt.execute((
                &folder_id,
                &identifier.to_string(),
                &meta,
                &secret,
            ))?;
        }
    }

    // Insert the event rows
    {
        let mut stmt = tx.prepare_cached(
            "INSERT INTO events (folder_id, event_type, created_at, commit_hash, event) VALUES (?1, ?2, ?3, ?4, ?5)",
        )?;
        for (time, commit, record) in events {
            stmt.execute((
                &folder_id,
                "folder",
                time,
                commit.to_string(),
                record.event_bytes(),
            ))?;
        }
    }

    Ok(())
}
