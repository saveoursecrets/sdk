use anyhow::Result;
use serial_test::serial;

use crate::test_utils::*;

use futures::stream::StreamExt;
use std::{sync::Arc, time::Duration};
use tokio::sync::RwLock;

use sos_net::{
    client::{
        net::changes::{changes, connect},
        provider::StorageProvider,
    },
    sdk::{commit::CommitProof, mpc::generate_keypair},
};

#[tokio::test]
#[serial]
async fn integration_handle_change() -> Result<()> {
    let dirs = setup(2).await?;

    let (rx, _handle) = spawn()?;
    let _ = rx.await?;

    let server_url = server();

    // Signup a new account
    let (_, credentials, mut creator, signer) = signup(&dirs, 0).await?;
    let AccountCredentials {
        summary,
        encryption_passphrase,
        ..
    } = credentials;

    // Set up another connected client to listen for changes
    let data_dir = dirs.clients.get(0).unwrap().to_path_buf();
    let mut listener =
        login(server_url.clone(), data_dir, &signer, generate_keypair()?)
            .await?;
    let _ = listener.load_vaults().await?;

    // Both clients use the login vault
    creator
        .open_vault(&summary, encryption_passphrase.clone().into(), None)
        .await?;

    listener
        .open_vault(&summary, encryption_passphrase.clone().into(), None)
        .await?;

    let listener_cache = Arc::new(RwLock::new(listener));
    let listener_summary = summary.clone();

    let listener_change: Arc<RwLock<Option<CommitProof>>> =
        Arc::new(RwLock::new(None));
    let listener_head = Arc::clone(&listener_change);

    // Spawn a task to handle change notifications
    tokio::task::spawn(async move {
        // Create the websocket connection
        let (stream, client) = connect(
            server_url,
            server_public_key()?,
            signer,
            generate_keypair()?,
        )
        .await?;

        // Wrap the stream to read change notifications
        let mut stream = changes(stream, client);

        while let Some(notification) = stream.next().await {
            let notification = notification?.await?;
            let mut writer = listener_cache.write().await;
            writer.handle_change(notification).await?;

            let head = writer
                .commit_tree(&listener_summary)
                .unwrap()
                .head()
                .unwrap();

            // Close the listener vault
            writer.close_vault();
            drop(writer);

            let mut writer = listener_head.write().await;
            *writer = Some(head);
        }

        Ok::<(), anyhow::Error>(())
    });

    // Give the websocket client some time to connect
    tokio::time::sleep(Duration::from_millis(250)).await;

    // Create some secrets in the creator
    // to trigger a change notification
    let _notes = create_secrets(&mut creator, &summary).await?;

    let creator_head = creator.commit_tree(&summary).unwrap().head()?;

    // Delay a while so the change notification SSE events
    // can be received
    tokio::time::sleep(Duration::from_millis(250)).await;

    // Verify our spawned task handled the notification
    let updated_head = listener_change.read().await;

    assert_eq!(&creator_head, updated_head.as_ref().unwrap());

    // Close the creator vault
    creator.close_vault();

    Ok(())
}
