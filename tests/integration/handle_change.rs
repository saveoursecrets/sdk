use anyhow::Result;
use serial_test::serial;

use crate::test_utils::*;

use futures::stream::StreamExt;
use reqwest_eventsource::Event;
use std::{sync::Arc, time::Duration};
use tokio::sync::{mpsc, RwLock};

use sos_client::{
    login, Client, ClientCache, ClientCredentials, FileCache, SyncStatus,
};
use sos_core::{
    constants::DEFAULT_VAULT_NAME,
    events::{ChangeEvent, ChangeNotification},
    generate_passphrase,
    secret::SecretRef,
    ChangePassword,
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
    let notifications: Arc<RwLock<Vec<ChangeNotification>>> =
        Arc::new(RwLock::new(Vec::new()));
    let changed = Arc::clone(&notifications);

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

    let change_flag = Arc::new(RwLock::new(false));
    let listener_changed = Arc::clone(&change_flag);

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
        // Close the listener vault
        writer.close_vault();

        let mut changed_flag = listener_changed.write().await;
        *changed_flag = true;
    });

    // Create some secrets in the creator
    // to trigger a change notification
    let _notes = create_secrets(&mut creator, &summary).await?;

    // Delay a while so the change notification SSE events
    // can be received
    tokio::time::sleep(Duration::from_millis(250)).await;

    // Verify our spawned task handled the notification
    let was_changed = change_flag.read().await;
    assert!(*was_changed);

    // Close the creator vault
    creator.close_vault();

    Ok(())
}
