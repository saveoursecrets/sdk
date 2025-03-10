mod compare;
mod diff_events;
mod last_commit;
mod load_tree;
mod rewind;
mod stream;

pub mod mock {
    use anyhow::Result;
    use futures::{pin_mut, StreamExt};
    use sos_backend::{
        AccountEventLog, BackendEventLog, BackendTarget, FolderEventLog,
    };
    use sos_core::{
        commit::{CommitHash, CommitTree},
        crypto::PrivateKey,
        encode,
        events::{EventLog, WriteEvent},
        AccountId, Paths, SecretId, VaultCommit, VaultEntry, VaultId,
    };
    use sos_database::async_sqlite::Client;
    use sos_test_utils::mock;
    use sos_vault::Vault;
    use sos_vfs as vfs;
    use std::path::Path;
    use tempfile::{tempdir_in, TempDir};
    use uuid::Uuid;

    pub async fn fs_account_event_log() -> Result<(TempDir, AccountEventLog)>
    {
        let temp = tempdir_in("target")?;
        let account_id = AccountId::random();
        let paths =
            Paths::new_client(temp.path()).with_account_id(&account_id);
        paths.ensure().await?;
        let event_log = AccountEventLog::new_account(
            BackendTarget::FileSystem(paths),
            &account_id,
        )
        .await?;
        Ok((temp, event_log))
    }

    pub async fn db_account_event_log(
        client: &mut Client,
    ) -> Result<(AccountId, AccountEventLog, TempDir)> {
        let temp = tempdir_in("target")?;
        let (account_id, _) = mock::insert_database_account(client).await?;
        let paths =
            Paths::new_client(temp.path()).with_account_id(&account_id);
        let event_log = AccountEventLog::new_account(
            BackendTarget::Database(paths, client.clone()),
            &account_id,
        )
        .await?;
        Ok((account_id, event_log, temp))
    }

    pub async fn fs_folder_event_log() -> Result<(TempDir, FolderEventLog)> {
        let temp = tempdir_in("target")?;
        let account_id = AccountId::random();
        let paths =
            Paths::new_client(temp.path()).with_account_id(&account_id);
        paths.ensure().await?;
        let folder_id = VaultId::new_v4();
        let event_log = FolderEventLog::new_folder(
            BackendTarget::FileSystem(paths),
            &account_id,
            &folder_id,
        )
        .await?;
        Ok((temp, event_log))
    }

    pub async fn db_folder_event_log(
        client: &mut Client,
        vault: &Vault,
    ) -> Result<(AccountId, FolderEventLog, TempDir)> {
        let temp = tempdir_in("target")?;
        let (account_id, _, _) =
            mock::insert_database_vault(client, vault, false).await?;
        let paths =
            Paths::new_client(temp.path()).with_account_id(&account_id);
        let event_log = FolderEventLog::new_folder(
            BackendTarget::Database(paths, client.clone()),
            &account_id,
            vault.id(),
        )
        .await?;
        Ok((account_id, event_log, temp))
    }

    pub async fn db_event_log_folder(
        client: &mut Client,
    ) -> Result<(AccountId, FolderEventLog, TempDir)> {
        let (encryption_key, _, _) = mock::encryption_key()?;
        let (_, vault, _) = mock::vault_file().await?;

        let (account_id, mut event_log, temp) =
            db_folder_event_log(client, &vault).await?;
        insert_mock_folder_events(encryption_key, vault, &mut event_log)
            .await?;
        Ok((account_id, event_log, temp))
    }

    pub async fn fs_event_log_file() -> Result<(TempDir, FolderEventLog)> {
        let (encryption_key, _, _) = mock::encryption_key()?;
        let (_, vault, _) = mock::vault_file().await?;
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
        event_log.apply(&[event]).await?;

        // Create a secret
        let (secret_id, _, _, _, event) = mock::vault_note(
            &mut vault,
            &encryption_key,
            "event log Note",
            "This a event log note secret.",
        )
        .await?;
        event_log.apply(&[event]).await?;

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
            event_log.apply(&[event]).await?;
        }

        Ok(())
    }

    pub async fn mock_secret() -> Result<(SecretId, VaultCommit)> {
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
        let mut event_log = BackendEventLog::FileSystem(
            sos_filesystem::FolderEventLog::new_folder(path.as_ref()).await?,
        );
        event_log
            .apply(&[
                WriteEvent::CreateVault(vault_buffer),
                WriteEvent::CreateSecret(id, data),
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
        let mut server = BackendEventLog::FileSystem(
            sos_filesystem::FolderEventLog::new_folder(server_file).await?,
        );
        server
            .apply(&[
                WriteEvent::CreateVault(vault_buffer),
                WriteEvent::CreateSecret(id, data),
            ])
            .await?;

        // Duplicate the server events on the client
        let mut client = BackendEventLog::FileSystem(
            sos_filesystem::FolderEventLog::new_folder(client_file).await?,
        );
        {
            let stream = server.event_stream(false).await;
            pin_mut!(stream);
            while let Some(result) = stream.next().await {
                let (_, event) = result?;
                client.apply(&[event]).await?;
            }
        }

        Ok((server, client, id))
    }

    pub async fn db_event_log_standalone(
        client: &mut Client,
    ) -> Result<(FolderEventLog, AccountId, VaultId, SecretId, Vault, TempDir)>
    {
        let temp = tempdir_in("target")?;
        let mut vault: Vault = Default::default();
        vault.set_name(String::from("Standalone vault"));

        let (account_id, _, _) =
            mock::insert_database_vault(client, &vault, false).await?;

        let paths =
            Paths::new_client(temp.path()).with_account_id(&account_id);
        let target = BackendTarget::Database(paths, client.clone());

        // Create a simple event log
        let mut event_log =
            FolderEventLog::new_folder(target, &account_id, vault.id())
                .await?;

        let vault_buffer = encode(&vault).await?;
        let (id, data) = mock_secret().await?;
        event_log
            .apply(&[
                WriteEvent::CreateVault(vault_buffer),
                WriteEvent::CreateSecret(id, data),
            ])
            .await?;

        Ok((event_log, account_id, *vault.id(), id, vault, temp))
    }

    pub async fn db_event_log_server_client(
        client: &mut Client,
    ) -> Result<(FolderEventLog, FolderEventLog, SecretId, TempDir)> {
        let temp = tempdir_in("target")?;
        let vault: Vault = Default::default();
        let (account_id, _, _) =
            mock::insert_database_vault(client, &vault, false).await?;
        let paths =
            Paths::new_client(temp.path()).with_account_id(&account_id);
        let target = BackendTarget::Database(paths, client.clone());

        // Create a simple event log
        let mut server = FolderEventLog::new_folder(
            target.clone(),
            &account_id,
            vault.id(),
        )
        .await?;

        let vault_buffer = encode(&vault).await?;
        let (id, data) = mock_secret().await?;

        server
            .apply(&[
                WriteEvent::CreateVault(vault_buffer),
                WriteEvent::CreateSecret(id, data),
            ])
            .await?;

        // Duplicate the server events on the client
        let mut client =
            FolderEventLog::new_folder(target, &account_id, vault.id())
                .await?;

        {
            let stream = server.event_stream(false).await;
            pin_mut!(stream);
            while let Some(result) = stream.next().await {
                let (_, event) = result?;
                client.apply(&[event]).await?;
            }
        }

        Ok((server, client, id, temp))
    }
}
