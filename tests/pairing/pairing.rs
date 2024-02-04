use crate::test_utils::{
    assert_local_remote_events_eq, mock, simulate_device, spawn, teardown,
};
use anyhow::Result;
use futures::{select, FutureExt};
use rand::{rngs::OsRng, Rng};
use sos_net::{
    client::{
        pairing::{listen, Accept, Offer},
        NetworkAccount, RemoteSync,
    },
    relay::RelayPacket,
    sdk::prelude::*,
};
use tokio::sync::mpsc;

/// Tests the protocol for pairing devices.
#[tokio::test]
async fn pairing_protocol() -> Result<()> {
    const TEST_ID: &str = "pairing_protocol";
    //crate::test_utils::init_tracing();

    // Spawn a backend server and wait for it to be listening
    let server = spawn(TEST_ID, None, None).await?;

    // Prepare mock devices
    let mut primary_device =
        simulate_device(TEST_ID, 2, Some(&server)).await?;

    let origin = primary_device.origin.clone();

    let (mut offer, offer_stream) =
        Offer::new(&mut primary_device.owner, origin.url().clone()).await?;

    // URL shared via QR code or other means.
    let share_url = offer.share_url().clone();

    let mut rng = OsRng {};
    let mock_key: [u8; 32] = rng.gen();
    let mock_device = TrustedDevice::new(mock_key.into(), None, None);

    let (mut accept, accept_stream) =
        Accept::new(share_url, &mock_device).await?;

    let (offer_tx, mut offer_rx) = mpsc::channel::<RelayPacket>(32);
    tokio::task::spawn(listen(offer_stream, offer_tx));

    let (accept_tx, mut accept_rx) = mpsc::channel::<RelayPacket>(32);
    tokio::task::spawn(listen(accept_stream, accept_tx));

    // Start the pairing
    accept.pair().await?;

    loop {
        select! {
            event = offer_rx.recv().fuse() => {
                if let Some(packet) = event {
                    offer.incoming(packet).await?;
                }
            }
            event = accept_rx.recv().fuse() => {
                if let Some(packet) = event {
                    accept.incoming(packet).await?;
                }
            }
            /*
            _ = futures::future::ready(()).fuse() => {
                if offer.is_finished() && accept.is_finished() {
                    break;
                }
            }
            */
        }
    }

    /*
    // Create a secret in the primary owner which won't exist
    // in the second device
    let (meta, secret) = mock::note(TEST_ID, TEST_ID);
    let result = primary_device
        .owner
        .create_secret(meta, secret, Default::default())
        .await?;
    assert!(result.sync_error.is_none());

    let password = primary_device.password.clone();
    let key: AccessKey = password.into();
    let origin = primary_device.origin.clone();
    let signing_key = primary_device.owner.account_signer().await?;
    let data_dir = primary_device.dirs.clients.get(1).cloned().unwrap();
    let folders = primary_device.folders.clone();

    // Need to clear the data directory for the second client
    // as simulate_device() copies all the account data and
    // the identity folder must not exist to enroll a new device
    std::fs::remove_dir_all(&data_dir)?;
    std::fs::create_dir(&data_dir)?;

    // Start enrollment by fetching the account data
    // from the remote server
    let enrollment = NetworkAccount::enroll_device(
        origin.clone(),
        signing_key,
        Some(data_dir),
    )
    .await?;

    // Complete device enrollment by authenticating
    // to the new account
    let mut enrolled_account = enrollment.finish(&key).await?;

    // Sync on the original device to fetch the updated device logs
    assert!(primary_device.owner.sync().await.is_none());

    // Read the secret on the newly enrolled account
    let (secret_data, _) =
        enrolled_account.read_secret(&result.id, None).await?;
    assert_eq!(TEST_ID, secret_data.meta().label());

    // Primary device has two trusted devices
    let devices = primary_device.owner.trusted_devices().await?;
    assert_eq!(2, devices.len());

    // Enrolled device has two trusted devices
    let devices = enrolled_account.trusted_devices().await?;
    assert_eq!(2, devices.len());

    // Check primary device is in sync with remote
    let mut bridge =
        primary_device.owner.remove_server(&origin).await?.unwrap();
    assert_local_remote_events_eq(
        folders.clone(),
        &mut primary_device.owner,
        &mut bridge,
    )
    .await?;

    // Check the enrolled device is in sync with remote
    let mut bridge = enrolled_account.remove_server(&origin).await?.unwrap();
    assert_local_remote_events_eq(
        folders,
        &mut enrolled_account,
        &mut bridge,
    )
    .await?;

    primary_device.owner.sign_out().await?;
    enrolled_account.sign_out().await?;
    */

    teardown(TEST_ID).await;

    Ok(())
}
