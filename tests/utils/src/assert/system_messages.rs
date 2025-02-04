use anyhow::Result;
use sos_backend::SystemMessages;
use sos_core::UtcDateTime;
use sos_system_messages::{
    SysMessage, SysMessageCount, SysMessageLevel, SystemMessageManager,
    SystemMessageStorage,
};
use std::sync::Arc;
use tokio::sync::{watch, Mutex};
use urn::Urn;

fn mock_message(
    priority: usize,
    level: SysMessageLevel,
    is_read: bool,
) -> SysMessage {
    SysMessage {
        id: None,
        created: UtcDateTime::now().into(),
        title: "Mock message".to_owned(),
        sub_title: None,
        content: None,
        priority,
        is_read,
        level,
    }
}

async fn assert_counter(
    notify_change: &mut watch::Receiver<()>,
    counter: Arc<Mutex<SysMessageCount>>,
    total: usize,
    unread: usize,
    unread_info: usize,
    unread_warn: usize,
    unread_error: usize,
) -> Result<()> {
    notify_change.changed().await?;
    let c = counter.lock().await;
    assert_eq!(total, c.total);
    assert_eq!(unread, c.unread);
    assert_eq!(unread_info, c.unread_info);
    assert_eq!(unread_warn, c.unread_warn);
    assert_eq!(unread_error, c.unread_error);
    Ok(())
}

/// Assert on system messages.
pub async fn assert_system_messages(
    messages: &mut SystemMessages,
) -> Result<()> {
    messages.load_system_messages().await?;

    let default_count: SysMessageCount = Default::default();
    let initial_count = messages.counts();
    assert_eq!(default_count, initial_count);

    let counter: Arc<Mutex<SysMessageCount>> =
        Arc::new(Mutex::new(Default::default()));

    let mut rx = messages.subscribe();
    let task_counter = counter.clone();
    let (tx, mut notify_change) = watch::channel(());
    tokio::task::spawn(async move {
        while let Ok(count) = rx.recv().await {
            let mut c = task_counter.lock().await;
            // println!("{:#?}", count);
            *c = count;
            tx.send(()).unwrap();
        }
    });

    // Insert message
    let key: Urn = "urn:mock:info".parse()?;
    let message = mock_message(100, SysMessageLevel::Info, false);
    messages
        .insert_system_message(key.clone(), message.clone())
        .await?;
    assert_eq!(1, messages.len());
    assert_counter(&mut notify_change, counter.clone(), 1, 1, 1, 0, 0)
        .await?;

    // Get message from memory
    let info_message = messages.get(&key).unwrap();
    assert_eq!(&message, info_message);

    // Mark message as read
    messages.mark_system_message(&key, true).await?;
    let info_message = messages.get(&key).unwrap();
    assert!(info_message.is_read);
    assert_counter(&mut notify_change, counter.clone(), 1, 0, 0, 0, 0)
        .await?;

    // Delete a message
    messages.remove_system_message(&key).await?;
    assert!(messages.is_empty());
    assert_counter(&mut notify_change, counter.clone(), 0, 0, 0, 0, 0)
        .await?;

    let n = 3;
    for i in 1..=n {
        let key: Urn = format!("urn:mock:{}", i).parse()?;
        let message = mock_message(n, SysMessageLevel::Info, false);
        messages.insert_system_message(key, message).await?;
        assert_counter(&mut notify_change, counter.clone(), i, i, i, 0, 0)
            .await?;
    }

    // Check sorted list uses priority
    let mut list = messages.sorted_list();
    let (_, head) = list.remove(0);
    assert_eq!(n, head.priority);

    // Clear all messages
    assert_eq!(3, messages.len());
    messages.clear_system_messages().await?;
    assert!(messages.is_empty());
    assert_counter(&mut notify_change, counter.clone(), 0, 0, 0, 0, 0)
        .await?;

    Ok(())
}
