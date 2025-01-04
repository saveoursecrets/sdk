use crate::test_utils::{setup, teardown};
use anyhow::Result;
use sos_net::extras::system_messages::*;
use sos_sdk::prelude::*;
use sos_signer::{ecdsa::SingleParty, Signer};
use std::sync::Arc;
use tokio::sync::Mutex;
use urn::Urn;

/// Tests sorting of system messages.
#[tokio::test]
async fn system_messages_sort() -> Result<()> {
    const TEST_ID: &str = "system_messages_sort";
    //crate::test_utils::init_tracing();

    let mut dirs = setup(TEST_ID, 1).await?;
    let data_dir = dirs.clients.remove(0);

    let mock_signer = SingleParty::new_random();
    let address = mock_signer.address()?;

    // Ensure paths exist
    Paths::scaffold(Some(data_dir.clone())).await?;
    let paths = Paths::new(data_dir.clone(), address.to_string());
    paths.ensure().await?;

    let mut messages = SystemMessages::new(&paths);
    assert!(messages.get(&"urn:sos:unknown-key".parse()?).is_none());

    // Check stream subscription
    let mut rx = messages.subscribe();
    let lengths = Arc::new(Mutex::new(vec![]));
    let task_lengths = Arc::clone(&lengths);
    tokio::task::spawn(async move {
        while let Ok(len) = rx.recv().await {
            let mut writer = task_lengths.lock().await;
            writer.push(len);
        }
    });

    let sync_error: Urn = "urn:sos:sync:error".parse()?;
    let software_update: Urn = "urn:sos:software:update".parse()?;
    let backup_due: Urn = "urn:sos:backup:due".parse()?;

    messages
        .insert(
            sync_error.clone(),
            SysMessage::new_priority(
                "Sync error".to_owned(),
                "Failed to sync with http://192.168.1.1:5053".to_owned(),
                0,
                Default::default(),
            ),
        )
        .await?;

    messages
        .insert(
            software_update.clone(),
            SysMessage::new_priority(
                "New version available".to_owned(),
                "A new release of the app is available to download."
                    .to_owned(),
                100,
                Default::default(),
            ),
        )
        .await?;

    messages
        .insert(
            backup_due.clone(),
            SysMessage::new(
                "Backup due".to_owned(),
                "No backup for a month, backup your account now.".to_owned(),
            ),
        )
        .await?;

    // Mark a message as read
    messages.mark_read(&software_update).await?;
    let software_update_msg = messages.get(&software_update).unwrap();
    assert!(software_update_msg.is_read);

    assert_eq!(3, messages.len());

    let list = messages.sorted_list();

    // First item is the highest priority
    assert_eq!("New version available", &list.get(0).unwrap().1.title);
    // Next is the backup due sorted by created date
    // with the most recent being first
    assert_eq!("Backup due", &list.get(1).unwrap().1.title);
    // Finally the sync error
    assert_eq!("Sync error", &list.get(2).unwrap().1.title);

    // Remove a message
    messages.remove(&software_update).await?;

    // Load from disc
    messages.load().await?;
    assert_eq!(2, messages.len());

    // Clear all messages
    messages.clear().await?;
    assert!(messages.is_empty());

    let expected = [
        SysMessageCount {
            total: 1,
            unread: 1,
            unread_info: 1,
            unread_warn: 0,
            unread_error: 0,
        },
        SysMessageCount {
            total: 2,
            unread: 2,
            unread_info: 2,
            unread_warn: 0,
            unread_error: 0,
        },
        SysMessageCount {
            total: 3,
            unread: 3,
            unread_info: 3,
            unread_warn: 0,
            unread_error: 0,
        },
        SysMessageCount {
            total: 3,
            unread: 2,
            unread_info: 2,
            unread_warn: 0,
            unread_error: 0,
        },
        SysMessageCount {
            total: 2,
            unread: 2,
            unread_info: 2,
            unread_warn: 0,
            unread_error: 0,
        },
        SysMessageCount {
            total: 0,
            unread: 0,
            unread_info: 0,
            unread_warn: 0,
            unread_error: 0,
        },
    ];

    // Wait for the last message to be delivered
    loop {
        let lengths = lengths.lock().await;
        if lengths.len() == expected.len() {
            assert_eq!(expected.as_slice(), lengths.as_slice());
            break;
        }
    }

    teardown(TEST_ID).await;

    Ok(())
}
