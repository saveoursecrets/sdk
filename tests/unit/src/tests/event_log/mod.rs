mod stream;

pub mod mock {
    use anyhow::Result;
    use sos_backend::{AccountEventLog, FolderEventLog};
    use sos_core::{events::EventLog, AccountId};
    use sos_database::async_sqlite::Client;
    use sos_sdk::crypto::PrivateKey;
    use sos_test_utils::mock;
    use sos_vault::Vault;
    use tempfile::NamedTempFile;

    /*
    pub async fn fs_account_event_log(
    ) -> Result<(NamedTempFile, AccountEventLog)> {
        let temp = NamedTempFile::new()?;
        let event_log = AccountEventLog::new_fs_account(temp.path()).await?;
        Ok((temp, event_log))
    }
    */

    pub async fn fs_folder_event_log(
    ) -> Result<(NamedTempFile, FolderEventLog)> {
        let temp = NamedTempFile::new()?;
        let event_log = FolderEventLog::new_fs_folder(temp.path()).await?;
        Ok((temp, event_log))
    }

    pub async fn db_folder_event_log(
        client: &mut Client,
        vault: &Vault,
    ) -> Result<(AccountId, FolderEventLog)> {
        let (account_id, _, _) =
            mock::insert_database_vault(client, vault).await?;
        let event_log = FolderEventLog::new_db_folder(
            client.clone(),
            account_id,
            *vault.id(),
        )
        .await?;
        Ok((account_id, event_log))
    }

    pub async fn db_event_log_folder(
        client: &mut Client,
    ) -> Result<(AccountId, FolderEventLog)> {
        let (encryption_key, _, _) = mock::encryption_key()?;
        let (_, mut vault) = mock::vault_file().await?;

        let (account_id, mut event_log) =
            db_folder_event_log(client, &vault).await?;
        insert_mock_folder_events(encryption_key, vault, &mut event_log)
            .await?;
        Ok((account_id, event_log))
    }

    pub async fn fs_event_log_file() -> Result<(NamedTempFile, FolderEventLog)>
    {
        let (encryption_key, _, _) = mock::encryption_key()?;
        let (_, vault) = mock::vault_file().await?;
        let (temp, mut event_log) = fs_folder_event_log().await?;
        insert_mock_folder_events(encryption_key, vault, &mut event_log)
            .await?;
        Ok((temp, event_log))
    }

    // Insert create vault, create secret and update secret
    // events into a folder event log.
    async fn insert_mock_folder_events(
        encryption_key: PrivateKey,
        mut vault: Vault,
        event_log: &mut FolderEventLog,
    ) -> Result<()> {
        // Create the vault
        let event = vault.into_event().await?;
        event_log.apply(vec![&event]).await?;

        // Create a secret
        let (secret_id, _, _, _, event) = mock::vault_note(
            &mut vault,
            &encryption_key,
            "event log Note",
            "This a event log note secret.",
        )
        .await?;
        event_log.apply(vec![&event]).await?;

        // Update the secret
        let (_, _, _, event) = mock::vault_note_update(
            &mut vault,
            &encryption_key,
            &secret_id,
            "event log Note Edited",
            "This a event log note secret that was edited.",
        )
        .await?;
        if let Some(event) = event {
            event_log.apply(vec![&event]).await?;
        }

        Ok(())
    }
}
