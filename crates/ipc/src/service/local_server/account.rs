use http::{Request, Response};
use hyper::body::Bytes;
use sos_net::{
    protocol::{
        Merge, MergeOutcome, SyncPacket, SyncStorage, WireEncodeDecode,
    },
    sdk::prelude::{Account, AccountSwitcher},
};
use std::sync::Arc;
use tokio::sync::RwLock;

use super::{
    bad_request, conflict, forbidden, internal_server_error, not_found, ok,
    parse_account_id, protobuf, Body, Incoming,
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
        let Ok(change_set) = account.change_set().await else {
            return internal_server_error();
        };
        let Ok(buffer) = change_set.encode().await else {
            return internal_server_error();
        };

        protobuf(buffer)
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
        let Ok(status) = account.sync_status().await else {
            return internal_server_error();
        };
        let Ok(buffer) = status.encode().await else {
            return internal_server_error();
        };
        protobuf(buffer)
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
        let (remote_status, mut diff) = (packet.status, packet.diff);

        // Apply the diff to the storage
        let mut outcome = MergeOutcome::default();
        let compare = {
            tracing::debug!("merge_local_server");
            if account.storage().await.is_none() {
                return conflict();
            };

            // Only try to merge folders that exist in storage
            // otherwise after folder deletion sync will fail
            {
                let Ok(folders) = account.folder_identifiers().await else {
                    return internal_server_error();
                };
                diff.folders.retain(|k, _| folders.contains(k));
            }

            let Ok(compare) = account.merge(diff, &mut outcome).await else {
                return internal_server_error();
            };

            compare
        };

        // Generate a new diff so the client can apply changes
        // that exist in remote but not in the local
        let Ok((_, local_status, diff)) =
            sos_net::protocol::diff(account, remote_status).await
        else {
            return internal_server_error();
        };

        let packet = SyncPacket {
            status: local_status,
            diff,
            compare: Some(compare),
        };

        let Ok(buffer) = packet.encode().await else {
            return internal_server_error();
        };
        protobuf(buffer)
    } else {
        not_found()
    }
}
