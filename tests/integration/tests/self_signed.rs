use anyhow::Result;
use sos_account::Account;
use sos_core::Paths;
use sos_protocol::{
    network_client::{HttpClient, NetworkConfig},
    reqwest::Url,
    SyncClient,
};
use sos_server::{SslConfig, TlsConfig};
use sos_test_utils::{
    default_server_config, setup, simulate_device, spawn_with_config,
};
use std::path::PathBuf;

/// Tests creating an identity vault and logging in
/// with the new vault and managing delegated passwords.
#[tokio::test]
async fn self_signed_server() -> Result<()> {
    const TEST_ID: &str = "self_signed_server";
    //sos_test_utils::init_tracing();

    // Prepare the server with self-signed certificate for 127.0.0.1
    let mut config = default_server_config().await?;
    let cert = PathBuf::from("../fixtures/self_signed_cert/server.crt");
    let key = PathBuf::from("../fixtures/self_signed_cert/server.key");
    config.net.ssl = Some(SslConfig::Tls(TlsConfig {
        cert: cert.clone(),
        key,
    }));
    let mut server =
        spawn_with_config(TEST_ID, None, Some(TEST_ID), Some(config)).await?;

    // Prepare mock client data storage directory
    // and move the root certificate into place
    let mut dirs = setup(TEST_ID, 1).await?;
    let data_dir = dirs.clients.remove(0);
    let paths = Paths::new_client(data_dir);
    let certs = paths.certificates_dir();

    std::fs::create_dir_all(certs)?;
    let root_cert = PathBuf::from("../fixtures/self_signed_cert/root.crt");
    let dest = certs.join("root.crt");
    std::fs::copy(&root_cert, dest)?;

    // Load root certificates into memory, usually the app would do this
    // when it boots
    NetworkConfig::load_root_certificates(certs)?;

    let certificates = NetworkConfig::get_root_certificates();
    assert!(!certificates.is_empty());

    // Most tests use HTTP but we need to use HTTPS fpr this so
    // we update the server origin which will be used when simulating
    // a connected device.
    let server_url =
        format!("https://{}:{}", server.addr.ip(), server.addr.port());
    let server_url = Url::parse(&server_url)
        .expect("failed to parse server URL from socket addr");
    server.origin = server_url.into();

    let device = simulate_device(TEST_ID, 1, Some(&server)).await?;
    let account_id = *device.owner.account_id();
    let origin = device.origin.clone();
    let device_signer = device.owner.device_signer().await?;

    let client = HttpClient::new(
        account_id,
        origin,
        device_signer.into(),
        String::new(),
    )?;

    let exists = client.account_exists().await?;
    // Account should exist as we did an initial
    // sync when creating the simulated device
    assert!(exists);

    Ok(())
}
