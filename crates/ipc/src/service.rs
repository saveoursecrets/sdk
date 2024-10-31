use crate::{
    wire_ipc_request_body, Error, IpcResponse, Result, WireIpcRequest,
    WireIpcResponse,
};
use async_trait::async_trait;
use sos_net::{
    sdk::account::{Account, AccountSwitcher, AppIntegration, LocalAccount},
    NetworkAccount,
};

/// IPC service for local accounts.
pub type LocalAccountIpcService = IpcServiceHandler<
    <LocalAccount as Account>::Error,
    <LocalAccount as Account>::NetworkResult,
    LocalAccount,
>;

/// IPC service for network accounts.
pub type NetworkAccountIpcService = IpcServiceHandler<
    <NetworkAccount as Account>::Error,
    <NetworkAccount as Account>::NetworkResult,
    NetworkAccount,
>;

/// Service handler for IPC requests
#[async_trait]
pub trait IpcService {
    /// Handle a request and reply with a response.
    async fn handle(
        &mut self,
        request: WireIpcRequest,
    ) -> Result<WireIpcResponse>;
}

pub struct IpcServiceHandler<E, R, A>
where
    A: Account<Error = E, NetworkResult = R> + Sync + Send + 'static,
    E: From<sos_net::sdk::Error>,
{
    accounts: AccountSwitcher<E, R, A>,
}

impl<E, R, A> IpcServiceHandler<E, R, A>
where
    A: Account<Error = E, NetworkResult = R> + Sync + Send + 'static,
    E: From<sos_net::sdk::Error>,
{
    pub fn new(accounts: AccountSwitcher<E, R, A>) -> Self {
        Self { accounts }
    }
}

#[async_trait]
impl<E, R, A: Account<Error = E, NetworkResult = R> + Send + Sync> IpcService
    for IpcServiceHandler<E, R, A>
where
    E: std::fmt::Debug + From<sos_net::sdk::Error>,
{
    /// Handle an incoming request.
    async fn handle(
        &mut self,
        request: WireIpcRequest,
    ) -> Result<WireIpcResponse> {
        let body = request.body.ok_or(Error::DecodeRequest)?;
        match body.inner {
            Some(wire_ipc_request_body::Inner::ListAccounts(_)) => {
                // FIXME: the unwrap!
                let data = self.accounts.list_accounts().await.unwrap();
                Ok((request.message_id, IpcResponse::ListAccounts(data))
                    .into())
            }
            _ => Err(Error::DecodeRequest),
        }
    }
}
