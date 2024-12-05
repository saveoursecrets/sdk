mod app_info;
mod list_accounts;
mod local_sync;
pub use sos_test_utils as test_utils;

use async_trait::async_trait;
use sos_net::protocol::local_transport::{
    LocalRequest, LocalResponse, LocalTransport,
};

use sos_ipc::SocketClient;

/// Local transport for the test specs.
pub struct TestLocalTransport {
    /// Socket name.
    pub socket_name: String,
    /// Socket client.
    pub client: SocketClient,
}

impl TestLocalTransport {
    /// Create a test transport.
    pub async fn new(socket_name: String) -> anyhow::Result<Self> {
        let client = SocketClient::connect(&socket_name).await?;
        Ok(Self {
            socket_name,
            client,
        })
    }
}

#[async_trait]
impl LocalTransport for TestLocalTransport {
    async fn call(
        &mut self,
        request: LocalRequest,
    ) -> sos_net::protocol::Result<LocalResponse> {
        Ok(self.client.send_request(request).await.unwrap())
    }
}
