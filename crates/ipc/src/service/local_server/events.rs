use binary_stream::futures::{Decodable, Encodable};
use http::{Request, Response};
use hyper::body::Bytes;
use sos_net::{
    protocol::{DiffRequest, DiffResponse, EventLogType, WireEncodeDecode},
    sdk::{
        events::DiscEventLog,
        prelude::{Account, AccountSwitcher, EventLogExt, StorageEventLogs},
    },
};
use std::sync::Arc;
use tokio::sync::RwLock;

use super::{
    bad_request, internal_server_error, not_found, parse_account_id,
    protobuf, Body, Incoming,
};

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

        let response = match &packet.log_type {
            EventLogType::Identity => {
                let Ok(log) = account.identity_log().await else {
                    return internal_server_error();
                };
                let event_log = log.read().await;
                let Ok(response) = diff_log(&packet, &*event_log).await
                else {
                    return internal_server_error();
                };
                response
            }
            EventLogType::Account => {
                let Ok(log) = account.account_log().await else {
                    return internal_server_error();
                };
                let event_log = log.read().await;
                let Ok(response) = diff_log(&packet, &*event_log).await
                else {
                    return internal_server_error();
                };
                response
            }
            EventLogType::Device => {
                let Ok(log) = account.device_log().await else {
                    return internal_server_error();
                };
                let event_log = log.read().await;
                let Ok(response) = diff_log(&packet, &*event_log).await
                else {
                    return internal_server_error();
                };
                response
            }
            EventLogType::Files => {
                let Ok(log) = account.file_log().await else {
                    return internal_server_error();
                };
                let event_log = log.read().await;
                let Ok(response) = diff_log(&packet, &*event_log).await
                else {
                    return internal_server_error();
                };
                response
            }
            EventLogType::Folder(id) => {
                let Ok(log) = account.folder_log(id).await else {
                    return internal_server_error();
                };
                let event_log = log.read().await;
                let Ok(response) = diff_log(&packet, &*event_log).await
                else {
                    return internal_server_error();
                };
                response
            }
        };
        protobuf(response)
    } else {
        not_found()
    }
}

/*
        let account = {
            let reader = backend.read().await;
            let accounts = reader.accounts();
            let reader = accounts.read().await;
            let account = reader
                .get(caller.address())
                .ok_or_else(|| Error::NoAccount(*caller.address()))?;
            Arc::clone(account)
        };

        let req = DiffRequest::decode(bytes).await?;

        let response = match &req.log_type {
            EventLogType::Identity => {
                let reader = account.read().await;
                let log = reader.storage.identity_log();
                let event_log = log.read().await;
                diff_log(&req, &*event_log).await?
            }
            EventLogType::Account => {
                let reader = account.read().await;
                let log = reader.storage.account_log();
                let event_log = log.read().await;
                diff_log(&req, &*event_log).await?
            }
            EventLogType::Device => {
                let reader = account.read().await;
                let log = reader.storage.device_log().await?;
                let event_log = log.read().await;
                diff_log(&req, &*event_log).await?
            }
            EventLogType::Files => {
                let reader = account.read().await;
                let log = reader.storage.file_log().await?;
                let event_log = log.read().await;
                diff_log(&req, &*event_log).await?
            }
            EventLogType::Folder(id) => {
                let reader = account.read().await;
                let log = reader.storage.folder_log(id).await?;
                let event_log = log.read().await;
                diff_log(&req, &*event_log).await?
            }
        };

        let mut headers = HeaderMap::new();
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static(MIME_TYPE_PROTOBUF),
        );

        Ok((headers, response))
*/

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

async fn diff_log<T>(
    req: &DiffRequest,
    event_log: &DiscEventLog<T>,
) -> crate::Result<Vec<u8>>
where
    T: Default + Encodable + Decodable + Send + Sync + 'static,
{
    let response = DiffResponse {
        patch: event_log.diff_records(req.from_hash.as_ref()).await?,
        checkpoint: event_log.tree().head()?,
    };
    Ok(response.encode().await?)
}
