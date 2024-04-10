use crate::test_utils::{
    assert_local_remote_events_eq, mock, num_events, simulate_device, spawn,
    teardown,
};
use anyhow::Result;
use sos_net::{client::RemoteSync, sdk::prelude::*};

/// Tests changing the account cipher and force syncing
/// the updated and diverged account data.
#[tokio::test]
async fn network_sync_change_cipher() -> Result<()> {
    const TEST_ID: &str = "sync_change_cipher";
    //crate::test_utils::init_tracing();

    // Spawn a backend server and wait for it to be listening
    let server = spawn(TEST_ID, None, None).await?;

    // Prepare mock devices
    let mut device1 = simulate_device(TEST_ID, 2, Some(&server)).await?;
    // let default_folder_id = device1.default_folder_id.clone();
    // let origin = device1.origin.clone();
    // let folders = device1.folders.clone();
    //
    let identity_summary = device1.owner.identity_folder_summary().await?;
    let cipher = identity_summary.cipher();
    assert_eq!(cipher, &Cipher::default());

    let mut device2 = device1.connect(1, None).await?;

    // Create a secret in the primary owner which won't exist
    // in the second device
    let (meta, secret) = mock::note(TEST_ID, TEST_ID);
    device1
        .owner
        .create_secret(meta, secret, Default::default())
        .await?;

    assert!(device2.owner.sync().await.is_none());

    let conversion = device1
        .owner
        .change_cipher(&Cipher::XChaCha20Poly1305)
        .await?;
    assert!(!conversion.is_empty());

    /*
    // Get the remote out of the owner so we can
    // assert on equality between local and remote
    let mut bridge = device1.owner.remove_server(&origin).await?.unwrap();
    assert_local_remote_events_eq(
        folders.clone(),
        &mut device1.owner,
        &mut bridge,
    )
    .await?;

    let mut bridge = device2.owner.remove_server(&origin).await?.unwrap();
    assert_local_remote_events_eq(
        folders.clone(),
        &mut device2.owner,
        &mut bridge,
    )
    .await?;
    */

    device1.owner.sign_out().await?;
    device2.owner.sign_out().await?;

    teardown(TEST_ID).await;

    Ok(())
}
