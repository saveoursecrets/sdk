mod app_info;
mod list_accounts;
mod local_sync;
mod memory_server;
mod native_bridge_chunks;
mod native_bridge_list_accounts;
mod native_bridge_probe;

use async_trait::async_trait;
use sos_ipc::client::LocalSocketClient;
use sos_ipc::local_transport::{LocalRequest, LocalResponse, LocalTransport};
pub use sos_test_utils as test_utils;

pub fn native_bridge_cmd() -> (&'static str, Vec<&'static str>) {
    let command = "cargo";
    let arguments = vec![
        "run",
        "-q",
        "--bin",
        "test-native-bridge",
        "--",
        "sos-test-native-bridge", // mock extension name
    ];
    (command, arguments)
}

/// Local transport for the test specs.
pub struct TestLocalTransport {
    /// Socket name.
    pub socket_name: String,
}

impl TestLocalTransport {
    /// Create a test transport.
    pub fn new(socket_name: String) -> Self {
        Self { socket_name }
    }
}

#[async_trait]
impl LocalTransport for TestLocalTransport {
    async fn call(&mut self, request: LocalRequest) -> LocalResponse {
        let mut client =
            LocalSocketClient::connect(&self.socket_name).await.unwrap();
        let Ok(response) = client.send_request(request).await else {
            panic!("unable to send request");
        };
        response
    }
}
