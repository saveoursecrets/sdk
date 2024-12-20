//! Search index query routes.

use http::{Request, Response, StatusCode};
use serde::Deserialize;
use sos_sdk::prelude::{Account, ArchiveFilter, DocumentView, QueryFilter};
use std::collections::HashMap;

use crate::web_service::{
    internal_server_error, json, parse_json_body, status, Accounts, Body,
    Incoming,
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
    accounts: Accounts<A, R, E>,
) -> hyper::Result<Response<Body>>
where
    A: Account<Error = E, NetworkResult = R> + Sync + Send + 'static,
    R: 'static,
    E: std::fmt::Debug
        + std::error::Error
        + From<sos_sdk::Error>
        + From<std::io::Error>
        + 'static,
{
    let Ok(request) = parse_json_body::<SearchRequest>(req).await else {
        return status(StatusCode::BAD_REQUEST);
    };

    let accounts = accounts.read().await;
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
    accounts: Accounts<A, R, E>,
) -> hyper::Result<Response<Body>>
where
    A: Account<Error = E, NetworkResult = R> + Sync + Send + 'static,
    R: 'static,
    E: std::fmt::Debug
        + std::error::Error
        + From<sos_sdk::Error>
        + From<std::io::Error>
        + 'static,
{
    let Ok(request) = parse_json_body::<QueryViewRequest>(req).await else {
        return status(StatusCode::BAD_REQUEST);
    };

    let accounts = accounts.read().await;
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
