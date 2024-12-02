use http::{Request, Response};
use sos_net::sdk::prelude::{Account, AccountSwitcher};
use std::sync::Arc;
use tokio::sync::RwLock;

use super::{Body, Incoming};

pub async fn account_exists<E, R, A>(
    _req: Request<Incoming>,
    _accounts: Arc<RwLock<AccountSwitcher<E, R, A>>>,
) -> hyper::Result<Response<Body>>
where
    E: std::fmt::Debug
        + From<sos_net::sdk::Error>
        + From<std::io::Error>
        + 'static,
    R: 'static,
    A: Account<Error = E, NetworkResult = R> + Sync + Send + 'static,
{
    todo!();
}

pub async fn create_account<E, R, A>(
    _req: Request<Incoming>,
    _accounts: Arc<RwLock<AccountSwitcher<E, R, A>>>,
) -> hyper::Result<Response<Body>>
where
    E: std::fmt::Debug
        + From<sos_net::sdk::Error>
        + From<std::io::Error>
        + 'static,
    R: 'static,
    A: Account<Error = E, NetworkResult = R> + Sync + Send + 'static,
{
    todo!();
}

pub async fn update_account<E, R, A>(
    _req: Request<Incoming>,
    _accounts: Arc<RwLock<AccountSwitcher<E, R, A>>>,
) -> hyper::Result<Response<Body>>
where
    E: std::fmt::Debug
        + From<sos_net::sdk::Error>
        + From<std::io::Error>
        + 'static,
    R: 'static,
    A: Account<Error = E, NetworkResult = R> + Sync + Send + 'static,
{
    todo!();
}

pub async fn fetch_account<E, R, A>(
    _req: Request<Incoming>,
    _accounts: Arc<RwLock<AccountSwitcher<E, R, A>>>,
) -> hyper::Result<Response<Body>>
where
    E: std::fmt::Debug
        + From<sos_net::sdk::Error>
        + From<std::io::Error>
        + 'static,
    R: 'static,
    A: Account<Error = E, NetworkResult = R> + Sync + Send + 'static,
{
    todo!();
}

pub async fn account_status<E, R, A>(
    _req: Request<Incoming>,
    _accounts: Arc<RwLock<AccountSwitcher<E, R, A>>>,
) -> hyper::Result<Response<Body>>
where
    E: std::fmt::Debug
        + From<sos_net::sdk::Error>
        + From<std::io::Error>
        + 'static,
    R: 'static,
    A: Account<Error = E, NetworkResult = R> + Sync + Send + 'static,
{
    todo!();
}

pub async fn sync_account<E, R, A>(
    _req: Request<Incoming>,
    _accounts: Arc<RwLock<AccountSwitcher<E, R, A>>>,
) -> hyper::Result<Response<Body>>
where
    E: std::fmt::Debug
        + From<sos_net::sdk::Error>
        + From<std::io::Error>
        + 'static,
    R: 'static,
    A: Account<Error = E, NetworkResult = R> + Sync + Send + 'static,
{
    todo!();
}
