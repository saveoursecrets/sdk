use crate::test_utils::{simulate_device, spawn, teardown};
use anyhow::Result;
use futures::{stream::FuturesUnordered, Future, StreamExt};
use sos_net::{
    client::pairing::{self, Accept, Offer},
    sdk::prelude::*,
};
use std::pin::Pin;

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
    let password = primary_device.password.clone();
    let key: AccessKey = password.into();

    // Get the data dir for the second client
    let data_dir = primary_device.dirs.clients.get(1).cloned().unwrap();

    // Need to clear the data directory for the second client
    // as simulate_device() copies all the account data and
    // the identity folder must not exist to enroll a new device
    std::fs::remove_dir_all(&data_dir)?;
    std::fs::create_dir(&data_dir)?;

    let mock_device_signer = DeviceSigner::new_random();
    let enrollment = {
        // Create the offer of device pairing
        let (mut offer, offer_stream) =
            Offer::new(&mut primary_device.owner, origin.url().clone())
                .await?;

        // URL shared via QR code or other means.
        let share_url = offer.share_url().clone();

        // Generate a mock device
        let mock_device = TrustedDevice::new(
            mock_device_signer.public_key().clone(),
            None,
            None,
        );

        // Create the device that will accept the pairing
        let (mut accept, accept_stream) = Accept::new(
            share_url,
            &mock_device,
            mock_device_signer.clone(),
            Some(data_dir),
        )
        .await?;

        // Run both sides of the protocol to completion
        let mut tasks = FuturesUnordered::<
            Pin<Box<dyn Future<Output = pairing::Result<()>>>>,
        >::new();

        tasks.push(Box::pin(offer.run(offer_stream)));
        tasks.push(Box::pin(accept.run(accept_stream)));

        while let Some(result) = tasks.next().await {
            result?;
        }

        drop(tasks);

        accept.take_enrollment()?
    };

    let mut enrolled_account = enrollment.finish(&key).await?;

    primary_device.owner.sign_out().await?;
    enrolled_account.sign_out().await?;

    teardown(TEST_ID).await;

    Ok(())
}
