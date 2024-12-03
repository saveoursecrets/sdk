mod app_info;
mod authenticate_success;
mod authenticate_timeout;
mod list_accounts;
mod local_sync;
mod lock_account;
mod ping_pong;
mod search;
pub use sos_test_utils as test_utils;

use async_trait::async_trait;
use sos_net::protocol::integration::{
    LocalTransport, TransportRequest, TransportResponse,
};

use sos_ipc::{AppIntegration, SocketClient};

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
        request: TransportRequest,
    ) -> sos_net::protocol::Result<TransportResponse> {
        Ok(self.client.request(request).await.unwrap())
    }
}
