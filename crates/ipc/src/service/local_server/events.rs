use http::{Request, Response};
use sos_net::sdk::prelude::{Account, AccountSwitcher};
use std::sync::Arc;
use tokio::sync::RwLock;

use super::{Body, Incoming};

pub async fn events_scan<A, R, E>(
    _req: Request<Incoming>,
    _accounts: Arc<RwLock<AccountSwitcher<A, R, E>>>,
) -> hyper::Result<Response<Body>>
where
    A: Account<Error = E, NetworkResult = R> + Sync + Send + 'static,
    R: 'static,
    E: std::fmt::Debug
        + From<sos_net::sdk::Error>
        + From<std::io::Error>
        + 'static,
{
    todo!();
}

pub async fn events_diff<A, R, E>(
    _req: Request<Incoming>,
    _accounts: Arc<RwLock<AccountSwitcher<A, R, E>>>,
) -> hyper::Result<Response<Body>>
where
    A: Account<Error = E, NetworkResult = R> + Sync + Send + 'static,
    R: 'static,
    E: std::fmt::Debug
        + From<sos_net::sdk::Error>
        + From<std::io::Error>
        + 'static,
{
    todo!();
}

pub async fn events_patch<A, R, E>(
    _req: Request<Incoming>,
    _accounts: Arc<RwLock<AccountSwitcher<A, R, E>>>,
) -> hyper::Result<Response<Body>>
where
    A: Account<Error = E, NetworkResult = R> + Sync + Send + 'static,
    R: 'static,
    E: std::fmt::Debug
        + From<sos_net::sdk::Error>
        + From<std::io::Error>
        + 'static,
{
    todo!();
}
