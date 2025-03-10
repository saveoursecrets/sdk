//! Search index query routes.

use http::{Request, Response, StatusCode};
use serde::Deserialize;
use sos_account::Account;
use sos_core::ErrorExt;
use sos_search::{ArchiveFilter, DocumentView, QueryFilter};
use sos_sync::SyncStorage;
use std::collections::HashMap;

use crate::web_service::{
    internal_server_error, json, parse_json_body, status, Body, Incoming,
    WebAccounts,
};

#[derive(Deserialize)]
struct SearchRequest {
    needle: String,
    filter: QueryFilter,
}

#[derive(Deserialize)]
struct QueryViewRequest {
    views: Vec<DocumentView>,
    archive_filter: Option<ArchiveFilter>,
}

/// Search authenticated accounts.
pub async fn search<A, R, E>(
    req: Request<Incoming>,
    accounts: WebAccounts<A, R, E>,
) -> hyper::Result<Response<Body>>
where
    A: Account<Error = E, NetworkResult = R> + SyncStorage,
    R: 'static,
    E: std::fmt::Debug
        + ErrorExt
        + std::error::Error
        + From<sos_core::Error>
        + From<sos_database::Error>
        + From<sos_account::Error>
        + From<sos_backend::Error>
        + From<sos_vault::Error>
        + From<sos_search::Error>
        + From<std::io::Error>
        + Send
        + Sync
        + 'static,
{
    let Ok(request) = parse_json_body::<SearchRequest>(req).await else {
        return status(StatusCode::BAD_REQUEST);
    };

    let accounts = accounts.as_ref().read().await;
    match accounts.search(request.needle, request.filter).await {
        Ok(results) => {
            let list = results
                .into_iter()
                .map(|(k, v)| (k.to_string(), v))
                .collect::<HashMap<_, _>>();
            json(StatusCode::OK, &list)
        }
        Err(e) => internal_server_error(e),
    }
}

/// Query a search index view for authenticated accounts.
pub async fn query_view<A, R, E>(
    req: Request<Incoming>,
    accounts: WebAccounts<A, R, E>,
) -> hyper::Result<Response<Body>>
where
    A: Account<Error = E, NetworkResult = R> + SyncStorage,
    R: 'static,
    E: std::fmt::Debug
        + ErrorExt
        + std::error::Error
        + From<sos_core::Error>
        + From<sos_database::Error>
        + From<sos_account::Error>
        + From<sos_backend::Error>
        + From<sos_vault::Error>
        + From<sos_search::Error>
        + From<std::io::Error>
        + Send
        + Sync
        + 'static,
{
    let Ok(request) = parse_json_body::<QueryViewRequest>(req).await else {
        return status(StatusCode::BAD_REQUEST);
    };

    let accounts = accounts.as_ref().read().await;
    match accounts
        .query_view(request.views.as_slice(), request.archive_filter.as_ref())
        .await
    {
        Ok(results) => {
            let list = results
                .into_iter()
                .map(|(k, v)| (k.to_string(), v))
                .collect::<HashMap<_, _>>();

            json(StatusCode::OK, &list)
        }
        Err(e) => internal_server_error(e),
    }
}
