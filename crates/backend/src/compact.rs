//! Compact folders.
use crate::{BackendEventLog, Error, FolderEventLog, Result};
use sos_core::{
    AccountId, VaultId,
    events::{
        EventLog, EventLogType, EventRecord,
        patch::{FolderDiff, Patch},
    },
};
use sos_database::{
    EventLogOwner,
    entity::{
        AccountEntity, AccountRow, FolderEntity, FolderRecord, FolderRow,
    },
    open_memory,
};
use sos_filesystem::FolderEventLog as FsFolderEventLog;
use sos_reducers::FolderReducer;
use sos_vault::Vault;
use tempfile::NamedTempFile;

/// Compact a folder event log.
pub async fn compact_folder(
    account_id: &AccountId,
    folder_id: &VaultId,
    event_log: &mut FolderEventLog,
) -> Result<()> {
    match event_log {
        BackendEventLog::Database(event_log) => {
            // Get the reduced set of events
            let events = FolderReducer::new()
                .reduce(event_log)
                .await?
                .compact()
                .await?;

            // Apply them to a temporary event log file so we
            // can compute a checkpoint for the diff
            let client = open_memory().await?;

            // Ensure the foreign key constrains exist
            // in the temporary database
            let temp_name = "compact_temp";
            let account_row =
                AccountRow::new_insert(account_id, temp_name.to_owned())?;
            let mut vault = Vault::default();
            *vault.header_mut().id_mut() = *folder_id;
            let folder_row = FolderRow::new_insert(&vault).await?;
            let db_folder_id = *folder_id;

            let folder_row = client
                .conn(move |conn| {
                    let account_entity = AccountEntity::new(&conn);
                    let folder_entity = FolderEntity::new(&conn);
                    let account_id = account_entity.insert(&account_row)?;
                    folder_entity.insert_folder(account_id, &folder_row)?;
                    folder_entity.find_one(&db_folder_id)
                })
                .await
                .map_err(sos_database::Error::from)?;
            let folder_record = FolderRecord::from_row(folder_row).await?;

            // Copy the event log using the new temporary owner
            let mut temp_event_log = event_log.with_new_client(
                client,
                Some(EventLogOwner::Folder(*account_id, folder_record)),
            );
            temp_event_log.apply(events.as_slice()).await?;

            let mut records = Vec::new();
            for event in &events {
                records.push(EventRecord::encode_event(event).await?);
            }

            let checkpoint = temp_event_log
                .tree()
                .proof(&[temp_event_log.tree().len() - 1])?;

            let diff = FolderDiff::new(Patch::new(records), checkpoint, None);
            event_log.replace_all_events(&diff).await?;

            Ok(())
        }
        BackendEventLog::FileSystem(event_log) => {
            // Get the reduced set of events
            let events = FolderReducer::new()
                .reduce(event_log)
                .await?
                .compact()
                .await?;

            // Apply them to a temporary event log file
            let temp = NamedTempFile::new()?;
            let mut temp_event_log = FsFolderEventLog::<Error>::new_folder(
                temp.path(),
                *account_id,
                EventLogType::Folder(*folder_id),
            )
            .await?;
            temp_event_log.apply(events.as_slice()).await?;

            let mut records = Vec::new();
            for event in &events {
                records.push(EventRecord::encode_event(event).await?);
            }

            let diff = FolderDiff::new(
                Patch::new(records),
                temp_event_log
                    .tree()
                    .proof(&[temp_event_log.tree().len() - 1])?,
                None,
            );

            event_log.replace_all_events(&diff).await?;

            temp.close()?;

            Ok(())
        }
    }
}
