use crate::test_utils::{simulate_device, spawn, teardown};
use anyhow::Result;
use futures::{stream::FuturesUnordered, Future, StreamExt};
use sos_net::{
    client::pairing::{self, OfferPairing},
    sdk::prelude::*,
};
use std::pin::Pin;
use tokio::sync::mpsc;

/// Tests shutting down the websocket for an
/// offer side of the pairing protocol.
#[tokio::test]
async fn pairing_websocket_shutdown() -> Result<()> {
    const TEST_ID: &str = "pairing_websocket_shutdown";
    //crate::test_utils::init_tracing();

    // Spawn a backend server and wait for it to be listening
    let server = spawn(TEST_ID, None, None).await?;

    // Prepare mock devices
    let mut primary_device =
        simulate_device(TEST_ID, 2, Some(&server)).await?;
    let origin = primary_device.origin.clone();

    {
        // Create the offer of device pairing
        let (mut offer, offer_stream) =
            OfferPairing::new(&mut primary_device.owner, origin.url().clone())
                .await?;

        let (offer_shutdown_tx, offer_shutdown_rx) = mpsc::channel::<()>(1);

        // Run both sides of the protocol to completion
        let mut tasks = FuturesUnordered::<
            Pin<Box<dyn Future<Output = pairing::Result<()>>>>,
        >::new();

        tasks.push(Box::pin(offer.run(offer_stream, offer_shutdown_rx)));
        tasks.push(Box::pin(async move {
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            offer_shutdown_tx.send(()).await.unwrap();
            Ok(())
        }));

        while let Some(result) = tasks.next().await {
            result?;
        }
    }

    primary_device.owner.sign_out().await?;

    teardown(TEST_ID).await;

    Ok(())
}
