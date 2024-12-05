use async_trait::async_trait;

use crate::{Error, Result, ServiceAppInfo};

use sos_net::sdk::prelude::PublicIdentity;

use sos_protocol::{
    constants::routes::v1::ACCOUNTS_LIST,
    local_transport::{LocalRequest, LocalResponse},
    NetworkError,
};

mod local_socket;

pub use local_socket::*;

/// Contract for types that expose an API to
/// app integrations such as browser extensions.
#[async_trait]
pub trait AppIntegration {
    /// App info.
    async fn info(&mut self) -> Result<ServiceAppInfo>;

    /// List the accounts on disc and include authentication state.
    async fn list_accounts(&mut self) -> Result<Vec<PublicIdentity>>;
}

#[async_trait]
impl AppIntegration for SocketClient {
    async fn info(&mut self) -> Result<ServiceAppInfo> {
        let response = self.send_request(Default::default()).await?;
        let status = response.status()?;
        if status.is_success() {
            let app_info: ServiceAppInfo =
                serde_json::from_slice(&response.body)?;
            Ok(app_info)
        } else {
            Err(NetworkError::ResponseCode(status).into())
        }
    }

    async fn list_accounts(&mut self) -> Result<Vec<PublicIdentity>> {
        let request = LocalRequest {
            uri: ACCOUNTS_LIST.parse()?,
            ..Default::default()
        };

        let response = self.send_request(request).await?;
        let status = response.status()?;
        if status.is_success() {
            let accounts: Vec<PublicIdentity> =
                serde_json::from_slice(&response.body)?;
            Ok(accounts)
        } else {
            Err(NetworkError::ResponseCode(status).into())
        }
    }
}
