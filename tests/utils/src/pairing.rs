use crate::SimulatedDevice;
use anyhow::Result;
use futures::{stream::FuturesUnordered, Future, StreamExt};
use sos_account::Account;
use sos_net::{
    pairing::{self, AcceptPairing, OfferPairing},
    NetworkAccount,
};
use sos_sdk::prelude::*;
use std::pin::Pin;
use tokio::sync::mpsc;

/// Run the pairing protocol to completion.
pub async fn run_pairing_protocol(
    primary_device: &mut SimulatedDevice,
    _test_id: &str,
    finish_enrollment: bool,
) -> Result<Option<NetworkAccount>> {
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

    let mut enrollment = {
        // Create the offer of device pairing
        let (mut offer, offer_stream) = OfferPairing::new(
            &mut primary_device.owner,
            origin.url().clone(),
        )
        .await?;

        // URL shared via QR code or other means.
        let share_url = offer.share_url().clone();

        // Generate a mock device
        let device_meta: DeviceMetaData = Default::default();

        // Create the device that will accept the pairing
        let (mut accept, accept_stream) =
            AcceptPairing::new(share_url, &device_meta, Some(data_dir))
                .await?;

        let (_otx, offer_shutdown_rx) = mpsc::channel::<()>(1);
        let (_atx, accept_shutdown_rx) = mpsc::channel::<()>(1);

        // Run both sides of the protocol to completion
        let mut tasks = FuturesUnordered::<
            Pin<Box<dyn Future<Output = pairing::Result<()>>>>,
        >::new();

        tasks.push(Box::pin(offer.run(offer_stream, offer_shutdown_rx)));
        tasks.push(Box::pin(accept.run(accept_stream, accept_shutdown_rx)));

        while let Some(result) = tasks.next().await {
            result?;
        }

        drop(tasks);

        accept.take_enrollment()?
    };

    enrollment.fetch_account().await?;

    if finish_enrollment {
        Ok(Some(enrollment.finish(&key).await?))
    } else {
        Ok(None)
    }
}

/// Run the inverted pairing protocol to completion.
pub async fn run_inverted_pairing_protocol(
    primary_device: &mut SimulatedDevice,
    _test_id: &str,
) -> Result<NetworkAccount> {
    let origin = primary_device.origin.clone();
    let password = primary_device.password.clone();
    let account_id = primary_device.owner.account_id().clone();
    let key: AccessKey = password.into();

    // Get the data dir for the second client
    let data_dir = primary_device.dirs.clients.get(1).cloned().unwrap();

    // Need to clear the data directory for the second client
    // as simulate_device() copies all the account data and
    // the identity folder must not exist to enroll a new device
    std::fs::remove_dir_all(&data_dir)?;
    std::fs::create_dir(&data_dir)?;

    let device_meta: DeviceMetaData = Default::default();

    let mut enrollment = {
        // Accepting side creates the pairing URL passing
        // in the server URL
        let (share_url, mut accept, accept_stream) =
            AcceptPairing::new_inverted(
                account_id,
                origin.url().clone(),
                &device_meta,
                Some(data_dir),
            )
            .await?;

        // Offering side receives the URL shared
        // via QR code or other means.

        // Create the offer of device pairing
        let (mut offer, offer_stream) =
            OfferPairing::new_inverted(&mut primary_device.owner, share_url)
                .await?;

        let (_otx, offer_shutdown_rx) = mpsc::channel::<()>(1);
        let (_atx, accept_shutdown_rx) = mpsc::channel::<()>(1);

        // Run both sides of the protocol to completion
        let mut tasks = FuturesUnordered::<
            Pin<Box<dyn Future<Output = pairing::Result<()>>>>,
        >::new();

        tasks.push(Box::pin(offer.run(offer_stream, offer_shutdown_rx)));
        tasks.push(Box::pin(accept.run(accept_stream, accept_shutdown_rx)));

        while let Some(result) = tasks.next().await {
            result?;
        }

        drop(tasks);

        accept.take_enrollment()?
    };

    enrollment.fetch_account().await?;

    Ok(enrollment.finish(&key).await?)
}
