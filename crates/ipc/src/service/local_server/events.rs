use http::{Request, Response};
use sos_net::sdk::prelude::{Account, AccountSwitcher};
use std::sync::Arc;
use tokio::sync::RwLock;

use super::{Body, Incoming};

pub async fn events_scan<E, R, A>(
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

pub async fn events_diff<E, R, A>(
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

pub async fn events_patch<E, R, A>(
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
