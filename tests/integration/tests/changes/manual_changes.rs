use std::time::Duration;

use anyhow::Result;
use sos_changes::{consumer::ChangeConsumer, producer::ChangeProducer};
use sos_core::{
    events::{changes_feed, LocalChangeEvent},
    AccountId, Paths,
};
use sos_test_utils::{setup, teardown};
use tokio::sync::mpsc;

/// Dispatch changes via the feed to a producer and consumer.
#[tokio::test]
async fn changes_manual_dispatch() -> Result<()> {
    const TEST_ID: &str = "changes_manual_dispatch";
    sos_test_utils::init_tracing();

    let mut dirs = setup(TEST_ID, 1).await?;
    let data_dir = dirs.clients.remove(0);
    let paths = Paths::new_client(&data_dir);

    let (tx, mut rx) = mpsc::channel(4);

    // Consumer spawns a task
    let mut handle = ChangeConsumer::listen(paths.clone())?;
    tokio::task::spawn(async move {
        let events = handle.changes();
        while let Some(event) = events.recv().await {
            tx.send(event).await.unwrap();
        }
        Ok::<_, anyhow::Error>(())
    });

    // Producer spawns a task
    let interval = Duration::from_secs(30);
    ChangeProducer::listen(paths.clone(), interval).await?;

    // Simulate producing some events
    let send = async move {
        let feed = changes_feed();
        feed.send_replace(LocalChangeEvent::AccountCreated(
            AccountId::random(),
        ));

        // Need to delay between triggering change events
        // like in the real world as the changes feed uses
        // a watch channel not a broadcast channel
        tokio::time::sleep(Duration::from_millis(50)).await;

        feed.send_replace(LocalChangeEvent::AccountDeleted(
            AccountId::random(),
        ));
    };

    // Listen for the consumer events
    let recv = async move {
        let mut events = Vec::new();
        while let Some(event) = rx.recv().await {
            events.push(event);
            if events.len() == 2 {
                break;
            }
        }
    };

    futures::future::join(send, recv).await;

    teardown(TEST_ID).await;

    Ok(())
}
