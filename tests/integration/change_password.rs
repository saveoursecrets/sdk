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
    let (address, credentials, mut provider, signer) = 
        signup_local("change_password").await?;

    let AccountCredentials {
        summary,
        encryption_passphrase,
        ..
    } = credentials;

    // Use the new vault
    provider
        .open_vault(&summary, encryption_passphrase.clone().into(), None)
        .await?;

    // Create some secrets
    let _notes = create_secrets(&mut provider, &summary).await?;

    // Check our new list of secrets has the right length
    let keeper = provider.current().unwrap();

    let index = keeper.index();
    let index_reader = index.read().await;
    let meta = index_reader.values();
    assert_eq!(3, meta.len());
    drop(index_reader);

    let keeper = provider.current_mut().unwrap();
    let (new_passphrase, _) = generate_passphrase()?;

    let vault = keeper.vault().clone();

    provider
        .change_password(
            &vault,
            encryption_passphrase.into(),
            new_passphrase.into(),
        )
        .await?;

    // Close the vault
    provider.close_vault();

    Ok(())
}
