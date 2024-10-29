use crate::{ipc_request_body, Error, IpcRequest, IpcResponse, Result};
use async_trait::async_trait;
use sos_net::{
    sdk::account::{Account, AccountSwitcher, LocalAccount},
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

#[async_trait]
pub trait IpcService {
    async fn handle(&mut self, request: IpcRequest) -> Result<IpcResponse>;
}

pub struct IpcServiceHandler<E, R, A: Account<Error = E, NetworkResult = R>> {
    accounts: AccountSwitcher<E, R, A>,
}

impl<E, R, A: Account<Error = E, NetworkResult = R>>
    IpcServiceHandler<E, R, A>
{
    pub fn new(accounts: AccountSwitcher<E, R, A>) -> Self {
        Self { accounts }
    }
}

#[async_trait]
impl<E, R, A: Account<Error = E, NetworkResult = R> + Send + Sync> IpcService
    for IpcServiceHandler<E, R, A>
where
    E: std::fmt::Debug,
{
    /// Handle an incoming request.
    async fn handle(&mut self, request: IpcRequest) -> Result<IpcResponse> {
        let body = request.body.ok_or(Error::DecodeRequest)?;
        match body.inner {
            Some(ipc_request_body::Inner::Authenticated(_)) => {
                // FIXME: the unwrap!
                let data = self.accounts.authenticated().await.unwrap();
                Ok(IpcResponse::new_authenticated(request.message_id, data))
            }
            _ => Err(Error::DecodeRequest),
        }
    }
}
