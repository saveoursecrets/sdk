use crate::test_utils::{mock, setup, teardown};
use anyhow::Result;
use sos_net::{
    events::Patch,
    sdk::{
        account::{
            LocalAccount, UserPaths,
        },
        passwd::diceware::generate_passphrase,
        events::{WriteEvent, FolderEventLog, AccountEvent, AccountEventLog},
    },
};

const TEST_ID: &str = "compact_events";

/// Tests compacting a folder event log.
#[tokio::test]
async fn integration_events_compact() -> Result<()> {
    //crate::test_utils::init_tracing();

    let mut dirs = setup(TEST_ID, 1).await?;
    let data_dir = dirs.clients.remove(0);

    let account_name = TEST_ID.to_string();
    let (password, _) = generate_passphrase()?;

    UserPaths::scaffold(Some(data_dir.clone())).await?;
    UserPaths::new_global(data_dir.clone());

    let (mut account, new_account) = LocalAccount::new_account(
        account_name.clone(),
        password.clone(),
        Some(data_dir.clone()),
        None,
    )
    .await?;

    let default_folder = new_account.default_folder();
    account.sign_in(password.clone()).await?;
    account.open_folder(&default_folder).await?;

    let default_folder_docs = vec![
        mock::note("note", "secret"),
        mock::card("card", TEST_ID, "123"),
        mock::bank("bank", TEST_ID, "12-34-56"),
    ];

    // Create a document for each secret type
    let results = account.insert(default_folder_docs).await?;
    let mut ids: Vec<_> = results.into_iter().map(|r| r.0).collect();

    let bank = ids.pop().unwrap();
    let card = ids.pop().unwrap();
    
    // Delete some secrets to create some more events
    account.delete_secret(&bank, Default::default()).await?;
    account.delete_secret(&card, Default::default()).await?;

    let folder_events = account.paths().event_log_path(
        default_folder.id().to_string());
    let mut event_log = FolderEventLog::new_folder(&folder_events).await?;
    let records = event_log.patch_until(None).await?;
    let patch: Patch = records.into();
    let events = patch.into_events::<WriteEvent>().await?;
    // One create vault event, three create secret events 
    // and two delete events
    assert_eq!(6, events.len());

    let old_root = account.root_commit(&default_folder).await?;

    account.compact(&default_folder).await?;

    // Now it's just the create vault and a single create 
    // secret event

    // Check the in-memory commit tree
    let new_root = {
        let storage = account.storage()?;
        let reader = storage.read().await;
        let tree = reader.commit_tree(&default_folder).unwrap();
        assert_eq!(2, tree.len());
        tree.root().unwrap()
    };
    
    // Trees have diverged
    assert_ne!(old_root.as_ref(), &new_root);
    
    // Load a new patch from disc
    let records = event_log.patch_until(None).await?;
    let patch: Patch = records.into();
    let events = patch.into_events::<WriteEvent>().await?;
    assert_eq!(2, events.len());

    // Check the account event log registered the compact event
    let account_events = account.paths().account_events();
    let mut event_log = AccountEventLog::new_account(&account_events).await?;
    let records = event_log.patch_until(None).await?;
    let patch: Patch = records.into();
    let mut events = patch.into_events::<AccountEvent>().await?;
    let compact_event = events.pop();
    assert!(matches!(compact_event, Some(AccountEvent::CompactFolder(_))));

    teardown(TEST_ID).await;

    Ok(())
}
