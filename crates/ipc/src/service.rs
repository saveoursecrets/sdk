use crate::{
    wire_ipc_request_body, AccountsList, AuthenticateOutcome, Error,
    IpcResponse, Result, WireIpcRequest, WireIpcResponse,
};
use async_trait::async_trait;
use sos_net::{
    sdk::{
        account::{Account, AccountSwitcher, LocalAccount},
        prelude::{Address, Identity},
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

/// Authenticate command for local accounts.
pub type LocalAccountAuthenticateCommand = AuthenticateCommand<
    <LocalAccount as Account>::Error,
    <LocalAccount as Account>::NetworkResult,
    LocalAccount,
>;

/// Authenticate command for network-enabled accounts.
pub type NetworkAccountAuthenticateCommand = AuthenticateCommand<
    <NetworkAccount as Account>::Error,
    <NetworkAccount as Account>::NetworkResult,
    NetworkAccount,
>;

/// Command to authenticate an account.
pub struct AuthenticateCommand<E, R, A>
where
    A: Account<Error = E, NetworkResult = R> + Sync + Send + 'static,
    E: From<sos_net::sdk::Error>,
{
    /// Account address.
    pub address: Address,
    /// Collection of accounts.
    pub accounts: Arc<RwLock<AccountSwitcher<E, R, A>>>,
    /// Result channel for the outcome.
    pub result: tokio::sync::oneshot::Sender<AuthenticateOutcome>,
}

/// Handler for authenticate requests.
pub type AuthenticateHandler<E, R, A> =
    tokio::sync::mpsc::Sender<AuthenticateCommand<E, R, A>>;

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

    async fn list_accounts(&self) -> std::result::Result<AccountsList, E> {
        let accounts = self.accounts.read().await;
        let mut out = Vec::new();
        let disc_accounts =
            Identity::list_accounts(accounts.data_dir()).await?;
        for account in disc_accounts {
            let authenticated = if let Some(memory_account) =
                accounts.iter().find(|a| a.address() == account.address())
            {
                memory_account.is_authenticated().await
            } else {
                false
            };

            out.push((account, authenticated));
        }
        Ok(out)
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
                let data = self.list_accounts().await.unwrap();
                Ok((message_id, IpcResponse::ListAccounts(data)).into())
            }
            Some(wire_ipc_request_body::Inner::Authenticate(body)) => {
                let address: Address = body.address.parse()?;
                if let Some(handler) = self.authenticate_handler.as_mut() {
                    let (result_tx, result_rx) =
                        tokio::sync::oneshot::channel();
                    let command = AuthenticateCommand {
                        address,
                        accounts: self.accounts.clone(),
                        result: result_tx,
                    };

                    handler.send(command).await.unwrap();

                    // FIXME: the unwrap!
                    let outcome = result_rx.await.unwrap();

                    // let outcome = handler(accounts, address).await.unwrap();
                    Ok((message_id, IpcResponse::Authenticate(outcome))
                        .into())
                } else {
                    let outcome = AuthenticateOutcome::Unsupported;
                    Ok((message_id, IpcResponse::Authenticate(outcome))
                        .into())
                }
            }
            _ => Err(Error::DecodeRequest),
        }
    }
}
