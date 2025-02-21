use super::last_log_event;
use crate::test_utils::{mock, setup, teardown};
use anyhow::Result;
use sos_account::{Account, LocalAccount, SecretChange};
use sos_backend::FolderEventLog;
use sos_core::{
    crypto::AccessKey,
    decode, encode,
    events::{EventLog, WriteEvent},
    Paths,
};
use sos_password::diceware::generate_passphrase;
use sos_test_utils::make_client_backend;
use sos_vault::Vault;

/// Tests events saved to a folder event log.
#[tokio::test]
async fn event_log_folder() -> Result<()> {
    const TEST_ID: &str = "event_log_folder";
    //crate::test_utils::init_tracing();

    let mut dirs = setup(TEST_ID, 1).await?;
    let data_dir = dirs.clients.remove(0);
    let paths = Paths::new_global(&data_dir);

    let account_name = TEST_ID.to_string();
    let (password, _) = generate_passphrase()?;

    let mut account = LocalAccount::new_account(
        account_name.clone(),
        password.clone(),
        make_client_backend(&paths).await?,
    )
    .await?;

    let key: AccessKey = password.into();
    account.sign_in(&key).await?;
    let default_folder = account.default_folder().await.unwrap();

    let folder_events = account.paths().event_log_path(default_folder.id());

    // Just has the create vault event to begin with
    let mut event_log = FolderEventLog::new_fs_folder(&folder_events).await?;
    let event = last_log_event(&mut event_log, None).await?;
    assert!(matches!(event, Some(WriteEvent::CreateVault(_))));

    // Create secret event
    let commit = event_log.tree().last_commit();
    let (meta, secret) = mock::note("note", TEST_ID);
    let SecretChange { id, .. } = account
        .create_secret(meta, secret, Default::default())
        .await?;
    let event = last_log_event(&mut event_log, commit.as_ref()).await?;
    assert!(matches!(event, Some(WriteEvent::CreateSecret(_, _))));

    // Update secret event
    let commit = event_log.tree().last_commit();
    let (meta, secret) = mock::note("note_edited", TEST_ID);
    account
        .update_secret(&id, meta.clone(), Some(secret), Default::default())
        .await?;
    let event = last_log_event(&mut event_log, commit.as_ref()).await?;
    assert!(matches!(event, Some(WriteEvent::UpdateSecret(_, _))));

    // Delete secret event
    let commit = event_log.tree().last_commit();
    account.delete_secret(&id, Default::default()).await?;
    let event = last_log_event(&mut event_log, commit.as_ref()).await?;
    assert!(matches!(event, Some(WriteEvent::DeleteSecret(_))));

    // Rename the folder
    let commit = event_log.tree().last_commit();
    account
        .rename_folder(default_folder.id(), "new_name".to_string())
        .await?;
    let event = last_log_event(&mut event_log, commit.as_ref()).await?;
    assert!(matches!(event, Some(WriteEvent::SetVaultName(_))));

    // Set the folder description
    let commit = event_log.tree().last_commit();
    account
        .set_folder_description(
            default_folder.id(),
            "new_description".to_string(),
        )
        .await?;
    let event = last_log_event(&mut event_log, commit.as_ref()).await?;
    assert!(matches!(event, Some(WriteEvent::SetVaultMeta(_))));

    // Export a vault so we can do an import,
    // this would be the flow used if we wanted
    // to move a folder between accounts we own
    let (vault_password, _) = generate_passphrase()?;
    let vault_key: AccessKey = vault_password.into();
    let mut vault: Vault = {
        let buffer = account
            .export_folder_buffer(
                default_folder.id(),
                vault_key.clone(),
                false,
            )
            .await?;
        decode(&buffer).await?
    };
    // We can also rename the vault like this between
    // the export and import operations
    vault.set_name("moved_vault".to_owned());

    // Encode and import the vault into the account
    // overwriting the existing data

    // When we import the entire event log is reduced
    // to a single create vault event, if the vault
    // had secrets it would also include the create
    // secret events from the vault
    let buffer = encode(&vault).await?;
    account
        .import_folder_buffer(&buffer, vault_key.clone(), true)
        .await?;
    let event = last_log_event(&mut event_log, None).await?;
    assert!(matches!(event, Some(WriteEvent::CreateVault(_))));

    teardown(TEST_ID).await;

    Ok(())
}
