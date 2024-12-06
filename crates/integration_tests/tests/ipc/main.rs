mod app_info;
mod list_accounts;
mod local_sync;
mod native_bridge_list_accounts;
mod native_bridge_probe;

use async_trait::async_trait;
use sos_ipc::client::LocalSocketClient;
use sos_ipc::local_transport::{LocalRequest, LocalResponse, LocalTransport};
pub use sos_test_utils as test_utils;

pub fn native_bridge_cmd(
    socket_name: &'static str,
) -> (&'static str, Vec<&'static str>) {
    let command = "cargo";
    let arguments = vec![
        "run",
        "-q",
        "--bin",
        "test-native-bridge",
        "--",
        "sos-test-native-bridge", // mock extension name
        socket_name,
    ];
    (command, arguments)
}

/// Local transport for the test specs.
pub struct TestLocalTransport {
    /// Socket name.
    pub socket_name: String,
    /// Socket client.
    pub client: LocalSocketClient,
}

impl TestLocalTransport {
    /// Create a test transport.
    pub async fn new(socket_name: String) -> anyhow::Result<Self> {
        let client = LocalSocketClient::connect(&socket_name).await?;
        Ok(Self {
            socket_name,
            client,
        })
    }
}

#[async_trait]
impl LocalTransport for TestLocalTransport {
    async fn call(&mut self, request: LocalRequest) -> LocalResponse {
        let Ok(response) = self.client.send_request(request).await else {
            panic!("unable to send request");
        };
        response
    }
}
