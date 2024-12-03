use http::{Request, Response};
use sos_net::{
    protocol::{SyncStorage, WireEncodeDecode},
    sdk::prelude::{Account, AccountSwitcher, Address, X_SOS_ACCOUNT_ID},
};
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::service::local_server::internal_server_error;

use super::{bad_request, forbidden, not_found, ok, Body, Incoming};

fn parse_account_id(req: &Request<Incoming>) -> Option<Address> {
    let Some(Ok(account_id)) =
        req.headers().get(X_SOS_ACCOUNT_ID).map(|v| v.to_str())
    else {
        return None;
    };
    let Ok(account_id) = account_id.parse::<Address>() else {
        return None;
    };
    Some(account_id)
}

pub async fn account_exists<A, R, E>(
    req: Request<Incoming>,
    accounts: Arc<RwLock<AccountSwitcher<A, R, E>>>,
) -> hyper::Result<Response<Body>>
where
    A: Account<Error = E, NetworkResult = R>
        + SyncStorage
        + Sync
        + Send
        + 'static,
    R: 'static,
    E: std::fmt::Debug
        + From<sos_net::sdk::Error>
        + From<std::io::Error>
        + 'static,
{
    let Some(account_id) = parse_account_id(&req) else {
        return bad_request(req).await;
    };

    let accounts = accounts.read().await;
    if accounts
        .iter()
        .find(|a| a.address() == &account_id)
        .is_some()
    {
        ok(req, Body::default()).await
    } else {
        not_found(req).await
    }
}

pub async fn create_account<A, R, E>(
    req: Request<Incoming>,
    _accounts: Arc<RwLock<AccountSwitcher<A, R, E>>>,
) -> hyper::Result<Response<Body>>
where
    A: Account<Error = E, NetworkResult = R>
        + SyncStorage
        + Sync
        + Send
        + 'static,
    R: 'static,
    E: std::fmt::Debug
        + From<sos_net::sdk::Error>
        + From<std::io::Error>
        + 'static,
{
    forbidden(req).await
}

pub async fn update_account<A, R, E>(
    req: Request<Incoming>,
    _accounts: Arc<RwLock<AccountSwitcher<A, R, E>>>,
) -> hyper::Result<Response<Body>>
where
    A: Account<Error = E, NetworkResult = R>
        + SyncStorage
        + Sync
        + Send
        + 'static,
    R: 'static,
    E: std::fmt::Debug
        + From<sos_net::sdk::Error>
        + From<std::io::Error>
        + 'static,
{
    forbidden(req).await
}

pub async fn fetch_account<A, R, E>(
    req: Request<Incoming>,
    accounts: Arc<RwLock<AccountSwitcher<A, R, E>>>,
) -> hyper::Result<Response<Body>>
where
    A: Account<Error = E, NetworkResult = R>
        + SyncStorage
        + Sync
        + Send
        + 'static,
    R: 'static,
    E: std::fmt::Debug
        + From<sos_net::sdk::Error>
        + From<std::io::Error>
        + 'static,
{
    let Some(account_id) = parse_account_id(&req) else {
        return bad_request(req).await;
    };

    let accounts = accounts.read().await;
    if let Some(account) =
        accounts.iter().find(|a| a.address() == &account_id)
    {
        let Ok(change_set) = account.change_set().await else {
            return internal_server_error(req).await;
        };
        let Ok(buffer) = change_set.encode().await else {
            return internal_server_error(req).await;
        };

        ok(req, buffer).await
    } else {
        not_found(req).await
    }
}

pub async fn delete_account<A, R, E>(
    req: Request<Incoming>,
    _accounts: Arc<RwLock<AccountSwitcher<A, R, E>>>,
) -> hyper::Result<Response<Body>>
where
    A: Account<Error = E, NetworkResult = R>
        + SyncStorage
        + Sync
        + Send
        + 'static,
    R: 'static,
    E: std::fmt::Debug
        + From<sos_net::sdk::Error>
        + From<std::io::Error>
        + 'static,
{
    forbidden(req).await
}

pub async fn account_status<A, R, E>(
    req: Request<Incoming>,
    accounts: Arc<RwLock<AccountSwitcher<A, R, E>>>,
) -> hyper::Result<Response<Body>>
where
    A: Account<Error = E, NetworkResult = R>
        + SyncStorage
        + Sync
        + Send
        + 'static,
    R: 'static,
    E: std::fmt::Debug
        + From<sos_net::sdk::Error>
        + From<std::io::Error>
        + 'static,
{
    let Some(account_id) = parse_account_id(&req) else {
        return bad_request(req).await;
    };

    let accounts = accounts.read().await;
    if let Some(account) =
        accounts.iter().find(|a| a.address() == &account_id)
    {
        let Ok(status) = account.sync_status().await else {
            return internal_server_error(req).await;
        };
        let Ok(buffer) = status.encode().await else {
            return internal_server_error(req).await;
        };
        ok(req, buffer).await
    } else {
        not_found(req).await
    }
}

pub async fn sync_account<A, R, E>(
    _req: Request<Incoming>,
    _accounts: Arc<RwLock<AccountSwitcher<A, R, E>>>,
) -> hyper::Result<Response<Body>>
where
    A: Account<Error = E, NetworkResult = R>
        + SyncStorage
        + Sync
        + Send
        + 'static,
    R: 'static,
    E: std::fmt::Debug
        + From<sos_net::sdk::Error>
        + From<std::io::Error>
        + 'static,
{
    todo!();
}
