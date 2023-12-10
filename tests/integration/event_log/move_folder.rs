use crate::test_utils::{mock, setup, teardown};
use anyhow::Result;
use sos_net::sdk::prelude::*;

use super::all_events;

const TEST_ID: &str = "events_move_folder";

/// Tests events after moving a folder between accounts.
#[tokio::test]
async fn integration_events_move_folder() -> Result<()> {
    //crate::test_utils::init_tracing();

    let mut dirs = setup(TEST_ID, 1).await?;
    let data_dir = dirs.clients.remove(0);

    let account_name = TEST_ID.to_string();
    let (password1, _) = generate_passphrase()?;
    let (password2, _) = generate_passphrase()?;

    let mut account1 = LocalAccount::new_account(
        account_name.clone(),
        password1.clone(),
        Some(data_dir.clone()),
        None,
    )
    .await?;

    let mut account2 = LocalAccount::new_account(
        account_name.clone(),
        password2.clone(),
        Some(data_dir.clone()),
        None,
    )
    .await?;

    let key: AccessKey = password1.into();
    account1.sign_in(&key).await?;
    let default_folder1 = account1.default_folder().await.unwrap();

    // Create some data in the first folder
    let docs = vec![
        mock::note("note", "secret"),
        mock::card("card", TEST_ID, "123"),
        mock::bank("bank", TEST_ID, "12-34-56"),
    ];
    account1.insert_secrets(docs).await?;

    // Export a vault so we can do an import,
    // this would be the flow used if we wanted
    // to move a folder between accounts we own
    let (vault_password, _) = generate_passphrase()?;
    let vault_key: AccessKey = vault_password.into();
    let mut vault: Vault = {
        let buffer = account1
            .export_folder_buffer(&default_folder1, vault_key.clone(), false)
            .await?;
        decode(&buffer).await?
    };
    // We can also rename the vault like this between
    // the export and import operations
    vault.set_name("moved_folder".to_owned());
    let folder_id = *vault.id();

    // Encode and import the vault into the account
    // overwriting the existing data
    let key: AccessKey = password2.into();
    account2.sign_in(&key).await?;

    // Import the folder into the other account
    let buffer = encode(&vault).await?;
    account2
        .import_folder_buffer(&buffer, vault_key.clone(), false)
        .await?;

    let account_events = account2.paths().account_events();
    let mut event_log = AccountEventLog::new_account(&account_events).await?;
    let events = all_events(&mut event_log).await?;
    // The account should have two create folder events now,
    // one for the default folder and one for the imported folder
    assert_eq!(2, events.len());
    assert!(matches!(events.get(0), Some(AccountEvent::CreateFolder(_))));
    assert!(matches!(events.get(1), Some(AccountEvent::CreateFolder(_))));

    // Find the imported folder and check the name
    let folder = account2.find(|s| s.id() == &folder_id).await.unwrap();
    assert_eq!("moved_folder", folder.name());

    // Check the folder event log
    let folder_events = account2.paths().event_log_path(&folder_id);
    let mut event_log = FolderEventLog::new_folder(&folder_events).await?;
    let events = all_events(&mut event_log).await?;
    // Should have the create vault and 3 create secret events
    assert_eq!(4, events.len());
    assert!(matches!(events.get(0), Some(WriteEvent::CreateVault(_))));
    assert!(matches!(
        events.get(1),
        Some(WriteEvent::CreateSecret(_, _))
    ));
    assert!(matches!(
        events.get(2),
        Some(WriteEvent::CreateSecret(_, _))
    ));
    assert!(matches!(
        events.get(3),
        Some(WriteEvent::CreateSecret(_, _))
    ));

    teardown(TEST_ID).await;

    Ok(())
}
