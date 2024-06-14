use super::last_log_event;
use crate::test_utils::{mock, setup, teardown};
use anyhow::Result;
use sos_net::sdk::prelude::*;

/// Tests compacting a folder event log.
#[tokio::test]
async fn event_log_compact() -> Result<()> {
    const TEST_ID: &str = "event_log_compact";
    //crate::test_utils::init_tracing();

    let mut dirs = setup(TEST_ID, 1).await?;
    let data_dir = dirs.clients.remove(0);

    let account_name = TEST_ID.to_string();
    let (password, _) = generate_passphrase()?;

    let mut account = LocalAccount::new_account(
        account_name.clone(),
        password.clone(),
        Some(data_dir.clone()),
    )
    .await?;

    let key: AccessKey = password.into();
    account.sign_in(&key).await?;
    let default_folder = account.default_folder().await.unwrap();

    // Create some secrets
    let docs = vec![
        mock::note("note", "secret"),
        mock::card("card", TEST_ID, "123"),
        mock::bank("bank", TEST_ID, "12-34-56"),
    ];
    let bulk = account.insert_secrets(docs).await?;
    let mut ids: Vec<_> = bulk.results.into_iter().map(|r| r.id).collect();

    let bank = ids.pop().unwrap();
    let card = ids.pop().unwrap();

    // Delete some secrets to create some more events
    account.delete_secret(&bank, Default::default()).await?;
    account.delete_secret(&card, Default::default()).await?;

    let folder_events = account.paths().event_log_path(default_folder.id());
    let event_log = FolderEventLog::new(&folder_events).await?;
    let patch = event_log.diff(None).await?;
    // One create vault event, three create secret events
    // and two delete events
    assert_eq!(6, patch.len());

    let old_root = account.root_commit(&default_folder).await?;

    account.compact_folder(&default_folder).await?;

    // Now it's just the create vault and a single create
    // secret event

    // Check the in-memory commit tree
    let new_root = {
        let storage = account.storage().await?;
        let reader = storage.read().await;
        let folder = reader.cache().get(default_folder.id()).unwrap();
        let event_log = folder.event_log();
        let event_log = event_log.read().await;
        let tree = event_log.tree();
        assert_eq!(2, tree.len());
        tree.root().unwrap()
    };

    // Trees have diverged
    assert_ne!(&old_root, &new_root);

    // Load a new patch from disc
    let patch = event_log.diff(None).await?;
    assert_eq!(2, patch.len());

    // Check the account event log registered the compact event
    let account_events = account.paths().account_events();
    let mut event_log = AccountEventLog::new_account(&account_events).await?;
    let event = last_log_event(&mut event_log, None).await?;
    assert!(matches!(event, Some(AccountEvent::CompactFolder(_, _))));

    teardown(TEST_ID).await;

    Ok(())
}
