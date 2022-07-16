use anyhow::Result;
use serial_test::serial;

use crate::test_utils::*;

use futures::stream::StreamExt;
use std::{sync::Arc, time::Duration};
use tokio::sync::{mpsc, RwLock};

use secrecy::ExposeSecret;
use sos_core::commit_tree::CommitProof;
use sos_node::client::{
    account::{login, AccountCredentials},
    net::changes::ChangeStreamEvent,
    LocalCache,
};

#[tokio::test]
#[serial]
async fn integration_handle_change() -> Result<()> {
    let dirs = setup(2)?;

    let (rx, _handle) = spawn()?;
    let _ = rx.await?;

    let server_url = server();

    // Signup a new account
    let (_, credentials, mut creator) = signup(&dirs, 0).await?;
    let AccountCredentials {
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
            let event = event?;
            match event {
                ChangeStreamEvent::Open => tx
                    .send(())
                    .await
                    .expect("failed to send changes feed open message"),
                ChangeStreamEvent::Message(notification) => change_tx
                    .send(notification)
                    .await
                    .expect("failed to relay change notification"),
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
    creator
        .open_vault(&summary, encryption_passphrase.expose_secret())
        .await?;
    listener
        .open_vault(&summary, encryption_passphrase.expose_secret())
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
    // to trigger a change notification
    let _notes = create_secrets(&mut creator, &summary).await?;

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
