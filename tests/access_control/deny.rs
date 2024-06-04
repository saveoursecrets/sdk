use anyhow::Result;
use std::collections::HashSet;

use crate::test_utils::{
    default_server_config, simulate_device, spawn_with_config, teardown,
};
use http::StatusCode;
use sos_net::{
    client::{Error as ClientError, NetworkAccount, RemoteSync},
    sdk::prelude::*,
    server::AccessControlConfig,
};

/// Tests server deny access control.
#[tokio::test]
async fn access_control_deny() -> Result<()> {
    const TEST_ID: &str = "access_control_deny";
    //crate::test_utils::init_tracing();

    let mut config = default_server_config().await?;
    let mut allowed = simulate_device(TEST_ID, 2, None).await?;
    let allowed_address = allowed.owner.address().clone();

    // Create an account with a different address
    let data_dir = allowed.dirs.clients.get(1).unwrap().clone();
    let (password, _) = generate_passphrase()?;
    let mut denied = NetworkAccount::new_account(
        TEST_ID.to_owned(),
        password.clone(),
        Some(data_dir.clone()),
        Default::default(),
    )
    .await?;
    let denied_address = denied.address().clone();
    let key: AccessKey = password.into();
    denied.sign_in(&key).await?;

    assert_ne!(allowed_address, denied_address);

    let mut addresses = HashSet::new();
    addresses.insert(denied_address);
    config.access = Some(AccessControlConfig {
        allow: None,
        deny: Some(addresses),
    });

    // Spawn a backend server and wait for it to be listening
    let server = spawn_with_config(TEST_ID, None, None, Some(config)).await?;
    let origin = server.origin.clone();

    allowed.owner.add_server(origin.clone()).await?;
    denied.add_server(origin.clone()).await?;

    assert!(allowed.owner.sync().await.is_none());
    let sync_error = denied.sync().await;
    if let Some(SyncError { mut errors }) = sync_error {
        let (_, err) = errors.remove(0);
        assert!(matches!(
            err,
            ClientError::ResponseJson(StatusCode::FORBIDDEN, _)
        ));
    } else {
        panic!("expecting multiple sync error (forbidden)");
    }

    allowed.owner.sign_out().await?;
    denied.sign_out().await?;

    teardown(TEST_ID).await;

    Ok(())
}
