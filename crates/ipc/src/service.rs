use crate::{
    wire_ipc_request_body, AuthenticateOutcome, Error, IpcResponse, Result,
    WireIpcRequest, WireIpcResponse,
};
use async_trait::async_trait;
use sos_net::{
    sdk::{
        account::{Account, AccountSwitcher, AppIntegration, LocalAccount},
        prelude::Address,
    },
    NetworkAccount,
};
use std::sync::Arc;
use tokio::sync::RwLock;

/// IPC service for local accounts.
pub type LocalAccountIpcService = IpcServiceHandler<
    <LocalAccount as Account>::Error,
    <LocalAccount as Account>::NetworkResult,
    LocalAccount,
>;

/// IPC service for network-enabled accounts.
pub type NetworkAccountIpcService = IpcServiceHandler<
    <NetworkAccount as Account>::Error,
    <NetworkAccount as Account>::NetworkResult,
    NetworkAccount,
>;

/// Handler for authenticate requests.
pub type AuthenticateHandler<E, R, A> = Box<
    dyn Fn(
            Arc<RwLock<AccountSwitcher<E, R, A>>>,
            Address,
        ) -> std::pin::Pin<
            Box<
                dyn std::future::Future<
                        Output = std::result::Result<AuthenticateOutcome, E>,
                    > + Send
                    + Sync
                    + 'static,
            >,
        > + Send
        + Sync
        + 'static,
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
    accounts: Arc<RwLock<AccountSwitcher<E, R, A>>>,
    authenticate_handler: Option<AuthenticateHandler<E, R, A>>,
}

impl<E, R, A> IpcServiceHandler<E, R, A>
where
    A: Account<Error = E, NetworkResult = R> + Sync + Send + 'static,
    E: From<sos_net::sdk::Error>,
{
    pub fn new(accounts: Arc<RwLock<AccountSwitcher<E, R, A>>>) -> Self {
        Self {
            accounts,
            authenticate_handler: None,
        }
    }

    pub fn new_with_authenticator(
        accounts: Arc<RwLock<AccountSwitcher<E, R, A>>>,
        authenticate_handler: AuthenticateHandler<E, R, A>,
    ) -> Self {
        Self {
            accounts,
            authenticate_handler: Some(authenticate_handler),
        }
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
        let message_id = request.message_id;

        let body = request.body.ok_or(Error::DecodeRequest)?;
        match body.inner {
            Some(wire_ipc_request_body::Inner::ListAccounts(_)) => {
                // FIXME: the unwrap!
                let mut accounts = self.accounts.write().await;
                let data = accounts.list_accounts().await.unwrap();
                Ok((message_id, IpcResponse::ListAccounts(data)).into())
            }
            Some(wire_ipc_request_body::Inner::Authenticate(body)) => {
                let address: Address = body.address.parse()?;
                if let Some(handler) = self.authenticate_handler.as_mut() {
                    // FIXME: the unwrap!
                    let accounts = self.accounts.clone();
                    let outcome = handler(accounts, address).await.unwrap();
                    Ok((message_id, IpcResponse::Authenticate(outcome))
                        .into())
                } else {
                    todo!();
                }
            }
            _ => Err(Error::DecodeRequest),
        }
    }
}
