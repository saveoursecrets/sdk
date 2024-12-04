use http::{Request, Response};
use hyper::body::Bytes;
use sos_net::{
    protocol::{
        server_helpers, DiffRequest, Merge, PatchRequest, ScanRequest,
        SyncStorage, WireEncodeDecode,
    },
    sdk::prelude::{Account, AccountSwitcher, StorageEventLogs},
};
use std::sync::Arc;
use tokio::sync::RwLock;

use super::{
    bad_request, internal_server_error, not_found, parse_account_id,
    protobuf, Body, Incoming,
};

pub async fn event_scan<A, R, E>(
    req: Request<Incoming>,
    accounts: Arc<RwLock<AccountSwitcher<A, R, E>>>,
) -> hyper::Result<Response<Body>>
where
    A: Account<Error = E, NetworkResult = R>
        + StorageEventLogs
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
        let buf: Bytes = req.into_body().into();
        let Ok(packet) = ScanRequest::decode(buf).await else {
            return bad_request();
        };

        // Maximum number of proofs to return in a single request
        if packet.limit > 256 {
            return bad_request();
        }

        let Ok(response) = server_helpers::event_scan(&packet, account).await
        else {
            return internal_server_error();
        };

        let Ok(buffer) = response.encode().await else {
            return internal_server_error();
        };

        protobuf(buffer)
    } else {
        not_found()
    }
}

pub async fn event_diff<A, R, E>(
    req: Request<Incoming>,
    accounts: Arc<RwLock<AccountSwitcher<A, R, E>>>,
) -> hyper::Result<Response<Body>>
where
    A: Account<Error = E, NetworkResult = R>
        + StorageEventLogs
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
        let buf: Bytes = req.into_body().into();
        let Ok(packet) = DiffRequest::decode(buf).await else {
            return bad_request();
        };

        let Ok(response) = server_helpers::event_diff(&packet, account).await
        else {
            return internal_server_error();
        };

        let Ok(buffer) = response.encode().await else {
            return internal_server_error();
        };

        protobuf(buffer)
    } else {
        not_found()
    }
}

pub async fn event_patch<A, R, E>(
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
        let Ok(packet) = PatchRequest::decode(buf).await else {
            return bad_request();
        };

        let Ok((response, _)) =
            server_helpers::event_patch(packet, account).await
        else {
            return internal_server_error();
        };

        let Ok(buffer) = response.encode().await else {
            return internal_server_error();
        };

        protobuf(buffer)
    } else {
        not_found()
    }
}
