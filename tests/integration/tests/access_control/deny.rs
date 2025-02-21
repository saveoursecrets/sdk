use crate::test_utils::{
    default_server_config, simulate_device, spawn_with_config, teardown,
};
use anyhow::Result;
use http::StatusCode;
use sos_account::Account;
use sos_net::{Error as ClientError, NetworkAccount};
use sos_protocol::{AccountSync, Error as ProtocolError, NetworkError};
use sos_sdk::prelude::*;
use sos_server::AccessControlConfig;
use sos_test_utils::make_client_backend;
use std::collections::HashSet;

/// Tests server deny access control.
#[tokio::test]
async fn access_control_deny() -> Result<()> {
    const TEST_ID: &str = "access_control_deny";
    //crate::test_utils::init_tracing();

    let mut config = default_server_config().await?;
    let mut allowed = simulate_device(TEST_ID, 2, None).await?;
    let allowed_account_id = allowed.owner.account_id().clone();

    // Create an account with a different account_id
    let data_dir = allowed.dirs.clients.get(1).unwrap().clone();
    let paths = Paths::new_global(&data_dir);
    let (password, _) = generate_passphrase()?;
    let mut denied = NetworkAccount::new_account(
        TEST_ID.to_owned(),
        password.clone(),
        make_client_backend(&paths).await?,
        Default::default(),
    )
    .await?;
    let denied_account_id = denied.account_id().clone();
    let key: AccessKey = password.into();
    denied.sign_in(&key).await?;

    assert_ne!(allowed_account_id, denied_account_id);

    let mut account_ides = HashSet::new();
    account_ides.insert(denied_account_id);
    config.access = Some(AccessControlConfig {
        allow: None,
        deny: Some(account_ides),
    });

    // Spawn a backend server and wait for it to be listening
    let server = spawn_with_config(TEST_ID, None, None, Some(config)).await?;
    let origin = server.origin.clone();

    allowed.owner.add_server(origin.clone()).await?;
    denied.add_server(origin.clone()).await?;
    assert!(allowed.owner.sync().await.first_error().is_none());
    let sync_error = denied.sync().await;
    if let Some(err) = sync_error.first_error() {
        assert!(matches!(
            err,
            ClientError::Protocol(ProtocolError::Network(
                NetworkError::ResponseCode(StatusCode::FORBIDDEN)
            ))
        ));
    } else {
        panic!("expecting multiple sync error (forbidden)");
    }

    allowed.owner.sign_out().await?;
    denied.sign_out().await?;

    teardown(TEST_ID).await;

    Ok(())
}
