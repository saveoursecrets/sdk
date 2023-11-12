use anyhow::Result;
use serial_test::serial;

use crate::test_utils::*;

use futures::stream::StreamExt;
use std::{
    sync::{Arc, RwLock},
    time::Duration,
};

use sos_net::{
    client::{
        net::changes::{changes, connect},
        provider::StorageProvider,
    },
    sdk::{
        events::{ChangeEvent, ChangeNotification},
        mpc::generate_keypair,
        passwd::diceware::generate_passphrase,
    },
};

#[tokio::test]
#[serial]
async fn integration_change_password() -> Result<()> {
    let dirs = setup(1).await?;

    let (rx, _handle) = spawn()?;
    let _ = rx.await?;

    let server_url = server();

    let (address, credentials, mut provider, signer) =
        signup(&dirs, 0).await?;
    let AccountCredentials {
        summary,
        encryption_passphrase,
        ..
    } = credentials;

    // Use the new vault
    provider
        .local_mut()
        .open_vault(&summary, encryption_passphrase.clone().into(), None)
        .await?;

    // Create some secrets
    let _notes = create_secrets(provider.local_mut(), &summary).await?;

    // Check our new list of secrets has the right length
    let keeper = provider.local().current().unwrap();

    let index = keeper.index();
    let index_reader = index.read().await;
    let meta = index_reader.values();
    assert_eq!(3, meta.len());
    drop(index_reader);

    let keeper = provider.local_mut().current_mut().unwrap();
    let (new_passphrase, _) = generate_passphrase()?;

    let vault = keeper.vault().clone();

    provider
        .local_mut()
        .change_password(
            &vault,
            encryption_passphrase.into(),
            new_passphrase.into(),
        )
        .await?;

    // Close the vault
    provider.local_mut().close_vault();

    Ok(())
}
