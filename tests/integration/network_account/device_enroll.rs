use anyhow::Result;

use sos_net::{client::{RemoteBridge, RemoteSync, NetworkAccount, Origin}, sdk::prelude::*};
use crate::test_utils::{mock, spawn, teardown};
use super::{assert_local_remote_events_eq, num_events, simulate_device};

const TEST_ID: &str = "sync_device_enroll";

/// Tests enrolling a new device and syncing the device event log 
/// for the enrolled device.
#[tokio::test]
async fn integration_sync_device_enroll() -> Result<()> {
    //crate::test_utils::init_tracing();

    // Spawn a backend server and wait for it to be listening
    let server = spawn(TEST_ID, None, None).await?;

    // Prepare mock devices
    let mut device1 = simulate_device(TEST_ID, &server, 2).await?;

    // Create a secret in the primary owner which won't exist
    // in the second device
    let (meta, secret) = mock::note("note_first_owner", TEST_ID);
    device1
        .owner
        .create_secret(meta, secret, Default::default())
        .await?;
    
    let password = device1.password.clone();
    let key: AccessKey = password.into();
    let origin = Origin::Hosted(device1.origin.clone());
    let signing_key = device1.owner.account_signer().await?;
    let data_dir = device1.dirs.clients.get(1).cloned().unwrap();
    
    // Need to clear the data directory for the second client
    // as simulate_device() copies all the account data and 
    // the identity folder must not exist to enroll a new device
    std::fs::remove_dir_all(&data_dir)?;
    std::fs::create_dir(&data_dir)?;
    
    // Start enrollment by fetching the account data 
    // from the remote server
    let enrollment = NetworkAccount::enroll(
        origin, signing_key, Some(data_dir)).await?;

    // Complete device enrollment by authenticating 
    // to the new account
    let enrolled_account = enrollment.finish(&key).await?;

    //teardown(TEST_ID).await;

    Ok(())
}
