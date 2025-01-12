mod compare;
mod diff_events;
mod last_commit;
mod stream;

pub mod mock {
    use anyhow::Result;
    use futures::{pin_mut, StreamExt};
    use sos_backend::{AccountEventLog, FolderEventLog};
    use sos_core::commit::{CommitHash, CommitTree};
    use sos_core::{events::EventLog, AccountId};
    use sos_database::async_sqlite::Client;
    use sos_sdk::crypto::PrivateKey;
    use sos_sdk::prelude::*;
    use sos_test_utils::mock;
    use sos_vault::Vault;
    use std::path::Path;
    use tempfile::NamedTempFile;
    use uuid::Uuid;

    pub async fn fs_account_event_log(
    ) -> Result<(NamedTempFile, AccountEventLog)> {
        let temp = NamedTempFile::new()?;
        let event_log = AccountEventLog::new_fs_account(temp.path()).await?;
        Ok((temp, event_log))
    }

    pub async fn db_account_event_log(
        client: &mut Client,
    ) -> Result<(AccountId, AccountEventLog)> {
        let (account_id, _) = mock::insert_database_account(client).await?;
        let event_log =
            AccountEventLog::new_db_account(client.clone(), account_id)
                .await?;
        Ok((account_id, event_log))
    }

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
        let (_, vault) = mock::vault_file().await?;

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

    async fn mock_secret<'a>() -> Result<(SecretId, VaultCommit)> {
        let id = Uuid::new_v4();
        let entry = VaultEntry(Default::default(), Default::default());
        let buffer = encode(&entry).await?;
        let commit = CommitHash(CommitTree::hash(&buffer));
        let result = VaultCommit(commit, entry);
        Ok((id, result))
    }

    pub async fn fs_event_log_standalone(
        path: impl AsRef<Path>,
    ) -> Result<(FolderEventLog, SecretId)> {
        if vfs::try_exists(path.as_ref()).await? {
            vfs::remove_file(path.as_ref()).await?;
        }

        let mut vault: Vault = Default::default();
        vault.set_name(String::from("Standalone vault"));
        let vault_buffer = encode(&vault).await?;

        let (id, data) = mock_secret().await?;

        // Create a simple event log
        let mut event_log =
            FolderEventLog::new_fs_folder(path.as_ref()).await?;
        event_log
            .apply(vec![
                &WriteEvent::CreateVault(vault_buffer),
                &WriteEvent::CreateSecret(id, data),
            ])
            .await?;

        Ok((event_log, id))
    }

    pub async fn fs_event_log_server_client(
    ) -> Result<(FolderEventLog, FolderEventLog, SecretId)> {
        // Required for CI which is setting the current
        // working directory to the workspace member rather
        // than using the top-level working directory
        vfs::create_dir_all("target/mock-event-log").await?;

        let server_file = "target/mock-event-log/server.events";
        let client_file = "target/mock-event-log/client.events";
        if vfs::try_exists(server_file).await? {
            let _ = vfs::remove_file(server_file).await;
        }
        if vfs::try_exists(&client_file).await? {
            let _ = vfs::remove_file(client_file).await;
        }

        let vault: Vault = Default::default();
        let vault_buffer = encode(&vault).await?;

        let (id, data) = mock_secret().await?;

        // Create a simple event log
        let mut server = FolderEventLog::new_fs_folder(server_file).await?;
        server
            .apply(vec![
                &WriteEvent::CreateVault(vault_buffer),
                &WriteEvent::CreateSecret(id, data),
            ])
            .await?;

        // Duplicate the server events on the client
        let mut client = FolderEventLog::new_fs_folder(client_file).await?;
        {
            let stream = server.event_stream(false).await;
            pin_mut!(stream);
            while let Some(result) = stream.next().await {
                let (_, event) = result?;
                client.apply(vec![&event]).await?;
            }
        }

        Ok((server, client, id))
    }

    pub async fn db_event_log_standalone(
        client: &mut Client,
    ) -> Result<(FolderEventLog, SecretId)> {
        let mut vault: Vault = Default::default();
        vault.set_name(String::from("Standalone vault"));

        let (account_id, _, _) =
            mock::insert_database_vault(client, &vault).await?;

        // Create a simple event log
        let mut event_log = FolderEventLog::new_db_folder(
            client.clone(),
            account_id,
            *vault.id(),
        )
        .await?;

        let vault_buffer = encode(&vault).await?;
        let (id, data) = mock_secret().await?;
        event_log
            .apply(vec![
                &WriteEvent::CreateVault(vault_buffer),
                &WriteEvent::CreateSecret(id, data),
            ])
            .await?;

        Ok((event_log, id))
    }

    pub async fn db_event_log_server_client(
        client: &mut Client,
    ) -> Result<(FolderEventLog, FolderEventLog, SecretId)> {
        let vault: Vault = Default::default();
        let (account_id, _, _) =
            mock::insert_database_vault(client, &vault).await?;

        // Create a simple event log
        let mut server = FolderEventLog::new_db_folder(
            client.clone(),
            account_id,
            *vault.id(),
        )
        .await?;

        let vault_buffer = encode(&vault).await?;
        let (id, data) = mock_secret().await?;

        server
            .apply(vec![
                &WriteEvent::CreateVault(vault_buffer),
                &WriteEvent::CreateSecret(id, data),
            ])
            .await?;

        // Duplicate the server events on the client
        let mut client = FolderEventLog::new_db_folder(
            client.clone(),
            account_id,
            *vault.id(),
        )
        .await?;

        {
            let stream = server.event_stream(false).await;
            pin_mut!(stream);
            while let Some(result) = stream.next().await {
                let (_, event) = result?;
                client.apply(vec![&event]).await?;
            }
        }

        Ok((server, client, id))
    }
}
