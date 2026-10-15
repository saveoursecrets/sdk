use anyhow::Result;
use sos_protocol::{network_client::NetworkConfig, reqwest::Url};
use sos_server::{SslConfig, TlsConfig};
use sos_test_utils::{
    default_server_config, simulate_device_with_network_config,
    spawn_with_config, teardown,
};
use std::{collections::HashMap, path::PathBuf};

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

    let root_cert = std::fs::read_to_string(PathBuf::from(
        "../fixtures/self_signed_cert/root.crt",
    ))?;
    let mut certificates = HashMap::new();
    certificates.insert("root.crt".to_string(), root_cert);
    let network_config = NetworkConfig {
        certificates,
        ..Default::default()
    };

    // Most tests use HTTP but we need to use HTTPS fpr this so
    // we update the server origin which will be used when simulating
    // a connected device.
    let server_url =
        format!("https://{}:{}", server.addr.ip(), server.addr.port());
    let server_url = Url::parse(&server_url)
        .expect("failed to parse server URL from socket addr");
    server.origin = server_url.into();

    // We sync by passing the server so this inherently
    // checks the TLS connecion is working.
    let device = simulate_device_with_network_config(
        TEST_ID,
        1,
        Some(&server),
        network_config.clone(),
    )
    .await?;

    // Establish a websocket connection
    device.listen_with_config(network_config).await?;

    tokio::time::sleep(std::time::Duration::from_secs(1)).await;

    teardown(TEST_ID).await;

    Ok(())
}
