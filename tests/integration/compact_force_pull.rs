use anyhow::Result;
use serial_test::serial;

use crate::test_utils::*;

use futures::stream::StreamExt;
use reqwest_eventsource::Event;
use std::{sync::Arc, time::Duration};
use tokio::sync::{mpsc, RwLock};

use sos_core::{commit_tree::CommitProof, events::ChangeNotification};
use sos_node::{login, ClientCache, ClientCredentials};

#[tokio::test]
#[serial]
async fn integration_compact_force_pull() -> Result<()> {
    let dirs = setup(2)?;

    let (rx, _handle) = spawn()?;
    let _ = rx.await?;

    let server_url = server();

    // Signup a new account
    let (_, credentials, mut creator) = signup(&dirs, 0).await?;
    let ClientCredentials {
        summary,
        encryption_passphrase,
        keystore_file,
        keystore_passphrase,
        ..
    } = credentials;

    // Set up another connected client to listen for changes
    let cache_dir = dirs.clients.get(1).unwrap().to_path_buf();
    let mut listener =
        login(server_url, cache_dir, keystore_file, keystore_passphrase)?;
    let _ = listener.load_vaults().await?;

    let (change_tx, mut change_rx) = mpsc::channel(16);

    let (tx, mut rx) = mpsc::channel(1);

    let mut es = listener.client().changes().await?;
    tokio::task::spawn(async move {
        while let Some(event) = es.next().await {
            match event {
                Ok(Event::Open) => tx
                    .send(())
                    .await
                    .expect("failed to send changes feed open message"),
                Ok(Event::Message(message)) => {
                    let notification: ChangeNotification =
                        serde_json::from_str(&message.data)?;
                    change_tx
                        .send(notification)
                        .await
                        .expect("failed to relay change notification")
                }
                Err(e) => {
                    es.close();
                    return Err(e.into());
                }
            }
        }

        Ok::<(), sos_client::Error>(())
    });

    // Wait for the changes feed to connect before
    // we start to make changes
    let _ = rx
        .recv()
        .await
        .expect("failed to receive changes feed open message");

    // Both clients use the login vault
    creator.open_vault(&summary, &encryption_passphrase).await?;
    listener
        .open_vault(&summary, &encryption_passphrase)
        .await?;

    let listener_cache = Arc::new(RwLock::new(listener));
    let listener_summary = summary.clone();

    let listener_change: Arc<RwLock<Option<CommitProof>>> =
        Arc::new(RwLock::new(None));
    let listener_head = Arc::clone(&listener_change);

    // Spawn a task to handle change notifications
    tokio::task::spawn(async move {
        let notification = change_rx
            .recv()
            .await
            .expect("failed to receive changes notification");

        let mut writer = listener_cache.write().await;
        writer
            .handle_change(notification)
            .await
            .expect("failed to handle change");

        let head =
            writer.wal_tree(&listener_summary).unwrap().head().unwrap();

        // Close the listener vault
        writer.close_vault();
        drop(writer);

        let mut writer = listener_head.write().await;
        *writer = Some(head);
    });

    // Create some secrets in the creator
    let notes = create_secrets(&mut creator, &summary).await?;

    // Delete a secret so that compacting would have an impact
    let delete_secret_id = notes.get(0).unwrap().0;
    delete_secret(&mut creator, &summary, &delete_secret_id).await?;

    // Compact the vault history to trigger the
    // update vault notification
    let _ = creator.compact(&summary).await?;

    let creator_head = creator.wal_tree(&summary).unwrap().head()?;

    // Delay a while so the change notification SSE events
    // can be received
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Verify our spawned task handled the notification
    let updated_head = listener_change.read().await;
    assert_eq!(&creator_head, updated_head.as_ref().unwrap());

    // Close the creator vault
    creator.close_vault();

    Ok(())
}
