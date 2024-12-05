use http::{Request, Response};
use hyper::body::Bytes;
use sos_net::{
    protocol::{
        server_helpers, Merge, SyncPacket, SyncStorage, WireEncodeDecode,
    },
    sdk::prelude::{Account, AccountSwitcher},
};
use std::sync::Arc;
use tokio::sync::RwLock;

use super::{
    bad_request, forbidden, internal_server_error, not_found, ok,
    parse_account_id, protobuf, protobuf_compress, Body, Incoming,
};

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
        return bad_request();
    };

    let accounts = accounts.read().await;
    if accounts
        .iter()
        .find(|a| a.address() == &account_id)
        .is_some()
    {
        ok(Body::default())
    } else {
        not_found()
    }
}

pub async fn create_account<A, R, E>(
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
    forbidden()
}

pub async fn update_account<A, R, E>(
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
    forbidden()
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
        return bad_request();
    };

    let accounts = accounts.read().await;
    if let Some(account) =
        accounts.iter().find(|a| a.address() == &account_id)
    {
        match account.change_set().await {
            Ok(change_set) => {
                let Ok(buffer) = change_set.encode().await else {
                    return internal_server_error("fetch_account::encode");
                };

                protobuf_compress(buffer)
            }
            Err(e) => internal_server_error(e),
        }
    } else {
        not_found()
    }
}

pub async fn delete_account<A, R, E>(
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
    forbidden()
}

pub async fn sync_status<A, R, E>(
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
        return bad_request();
    };

    let accounts = accounts.read().await;
    if let Some(account) =
        accounts.iter().find(|a| a.address() == &account_id)
    {
        match account.sync_status().await {
            Ok(status) => {
                let Ok(buffer) = status.encode().await else {
                    return internal_server_error("sync_status::encode");
                };
                protobuf(buffer)
            }
            Err(e) => internal_server_error(e),
        }
    } else {
        not_found()
    }
}

pub async fn sync_account<A, R, E>(
    req: Request<Incoming>,
    accounts: Arc<RwLock<AccountSwitcher<A, R, E>>>,
) -> hyper::Result<Response<Body>>
where
    A: Account<Error = E, NetworkResult = R>
        + SyncStorage
        + Merge
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
        return bad_request();
    };

    let mut accounts = accounts.write().await;
    if let Some(account) =
        accounts.iter_mut().find(|a| a.address() == &account_id)
    {
        let buf: Bytes = req.into_body().into();
        let Ok(packet) = SyncPacket::decode(buf).await else {
            return bad_request();
        };

        match server_helpers::sync_account(packet, account).await {
            Ok((packet, _)) => {
                let Ok(response) = packet.encode().await else {
                    return internal_server_error("sync_account::encode");
                };

                protobuf(response)
            }
            Err(e) => internal_server_error(e),
        }
    } else {
        not_found()
    }
}
